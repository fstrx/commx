// Drives daemons over unix sockets and uses SIGKILL/SIGSTOP.
#![cfg(unix)]

//! End-to-end: real commxd processes on localhost, driven over their control
//! sockets. "Killing a node" is a real SIGKILL / SIGSTOP.

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

struct Node {
    child: Child,
    dir: PathBuf,
    w: UnixStream,
    rx: mpsc::Receiver<Value>,
}

impl Node {
    fn spawn(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("cx-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        Self::spawn_in(dir)
    }

    fn spawn_in(dir: PathBuf) -> Self {
        Self::spawn_with(dir, &[])
    }

    fn spawn_with(dir: PathBuf, extra: &[&str]) -> Self {
        let child = Command::new(env!("CARGO_BIN_EXE_commxd"))
            .args(["--data-dir", dir.to_str().unwrap(), "--listen", "127.0.0.1:0", "--no-keep-awake"])
            .args(extra)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let sock = dir.join("commxd.sock");
        let deadline = Instant::now() + Duration::from_secs(10);
        let stream = loop {
            if let Ok(s) = UnixStream::connect(&sock) {
                break s;
            }
            assert!(Instant::now() < deadline, "daemon didn't start");
            std::thread::sleep(Duration::from_millis(50));
        };
        let (tx, rx) = mpsc::channel();
        let r = stream.try_clone().unwrap();
        std::thread::spawn(move || {
            for line in BufReader::new(r).lines() {
                let Ok(line) = line else { break };
                if tx.send(serde_json::from_str(&line).unwrap()).is_err() {
                    break;
                }
            }
        });
        Node { child, dir, w: stream, rx }
    }

    fn req(&mut self, v: Value) {
        let mut s = v.to_string();
        s.push('\n');
        self.w.write_all(s.as_bytes()).unwrap();
    }

    fn expect(&self, what: &str, secs: u64, pred: impl Fn(&Value) -> bool) -> Value {
        let deadline = Instant::now() + Duration::from_secs(secs);
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.rx.recv_timeout(left) {
                Ok(v) if pred(&v) => return v,
                Ok(v) if v["ev"] == "error" => panic!("{what}: daemon error {v}"),
                Ok(_) => {}
                Err(_) => panic!("timed out waiting for {what}"),
            }
        }
    }

    fn alias(&mut self, name: &str) {
        self.req(json!({"op": "alias_new", "name": name, "ephemeral": true, "passphrase": null}));
        self.expect("alias", 5, |v| v["ev"] == "ok");
    }

    fn room(&mut self, name: &str, mode: &str, grace: u64, dm: bool) -> (String, String) {
        self.req(json!({"op": "room_new", "name": name, "kill_mode": mode, "grace_secs": grace, "dm": dm}));
        let v = self.expect("invite", 5, |v| v["ev"] == "invite_code");
        (v["room_id"].as_str().unwrap().into(), v["code"].as_str().unwrap().into())
    }

    fn invite(&mut self, room: &str) -> String {
        self.req(json!({"op": "invite", "room_id": room}));
        self.expect("invite", 5, |v| v["ev"] == "invite_code")["code"].as_str().unwrap().into()
    }

    fn join(&mut self, code: &str) {
        self.req(json!({"op": "join", "code": code}));
        self.expect("join", 10, |v| v["ev"] == "ok" && v["msg"].as_str().unwrap().starts_with("joined"));
    }

    fn send(&mut self, room: &str, text: &str) {
        self.req(json!({"op": "send", "room_id": room, "text": text}));
    }

    fn expect_msg(&self, from: &str, text: &str) {
        self.expect(&format!("message '{text}' from {from}"), 5, |v| {
            v["ev"] == "line" && v["line"]["from"] == from && v["line"]["text"] == text
        });
    }

    fn expect_system(&self, contains: &str) {
        self.expect(&format!("system line '{contains}'"), 10, |v| {
            v["ev"] == "line" && v["line"]["system"] == true && v["line"]["text"].as_str().unwrap().contains(contains)
        });
    }

    fn expect_nuked(&self, room: &str, secs: u64) -> String {
        let v = self.expect(&format!("nuke of {room}"), secs, |v| v["ev"] == "nuked" && v["room_id"] == room);
        v["reason"].as_str().unwrap().to_string()
    }

    fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        unsafe { libc::kill(self.child.id() as i32, libc::SIGCONT) };
        self.kill();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn host_only_room_survives_member_drop_and_dies_with_host() {
    let (mut a, mut b, mut c) = (Node::spawn("ho-a"), Node::spawn("ho-b"), Node::spawn("ho-c"));
    a.alias("alice");
    b.alias("bob");
    c.alias("carol");

    let (room, code) = a.room("lounge", "HostOnly", 15, false);
    b.join(&code);
    let code2 = a.invite(&room);
    c.join(&code2);

    a.send(&room, "hi from host");
    b.expect_msg("alice", "hi from host");
    c.expect_msg("alice", "hi from host");

    b.send(&room, "hi from bob");
    a.expect_msg("bob", "hi from bob");
    c.expect_msg("bob", "hi from bob");

    // member drop: room survives, key rotates, chat continues
    c.kill();
    a.expect_system("carol dropped");
    b.expect_system("room key rotated (epoch 1)");
    b.send(&room, "still here");
    a.expect_msg("bob", "still here");

    // host drop: room is gone for everyone
    a.kill();
    let reason = b.expect_nuked(&room, 10);
    assert!(reason.contains("host dropped"), "{reason}");
}

#[test]
fn any_member_room_nukes_when_any_member_drops() {
    let (mut a, mut b, mut c) = (Node::spawn("am-a"), Node::spawn("am-b"), Node::spawn("am-c"));
    a.alias("alice");
    b.alias("bob");
    c.alias("carol");
    let (room, code) = a.room("vault", "AnyMember", 15, false);
    b.join(&code);
    let code = a.invite(&room);
    c.join(&code);

    c.kill();
    assert!(a.expect_nuked(&room, 10).contains("carol dropped"));
    assert!(b.expect_nuked(&room, 10).contains("host nuked"));
}

#[test]
fn silent_member_trips_grace_timeout() {
    let (mut a, mut b) = (Node::spawn("to-a"), Node::spawn("to-b"));
    a.alias("alice");
    b.alias("bob");
    let (room, code) = a.room("quiet", "AnyMember", 3, false);
    b.join(&code);

    // frozen, not dead: TCP stays open, only heartbeats stop
    unsafe { libc::kill(b.child.id() as i32, libc::SIGSTOP) };
    let started = Instant::now();
    assert!(a.expect_nuked(&room, 10).contains("timed out"));
    assert!(started.elapsed() >= Duration::from_secs(2));
}

#[test]
fn dm_is_two_party_and_nukes_on_either_side() {
    let (mut a, mut b, mut c) = (Node::spawn("dm-a"), Node::spawn("dm-b"), Node::spawn("dm-c"));
    a.alias("alice");
    b.alias("bob");
    c.alias("carol");
    let (room, code) = a.room("bob", "HostOnly", 15, true);
    b.join(&code);
    a.req(json!({"op": "invite", "room_id": room}));
    a.expect("dm full error", 5, |v| v["ev"] == "error" && v["msg"] == "DM is full");

    // invites are single use
    c.req(json!({"op": "join", "code": code}));
    c.expect("reused invite rejected", 10, |v| v["ev"] == "error" && v["msg"].as_str().unwrap().contains("denied"));

    b.send(&room, "psst");
    a.expect_msg("bob", "psst");

    b.kill();
    assert!(a.expect_nuked(&room, 10).contains("bob dropped"));
}

#[test]
fn host_manual_nuke_reaches_members() {
    let (mut a, mut b) = (Node::spawn("mn-a"), Node::spawn("mn-b"));
    a.alias("alice");
    b.alias("bob");
    let (room, code) = a.room("tmp", "HostOnly", 15, false);
    b.join(&code);
    a.req(json!({"op": "nuke", "room_id": room}));
    assert!(b.expect_nuked(&room, 5).contains("host nuked"));
    a.expect_nuked(&room, 5);
}

#[test]
fn persistent_alias_survives_restart_behind_passphrase() {
    let dir = std::env::temp_dir().join(format!("cx-{}-persist", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let fp = {
        let mut n = Node::spawn_in(dir.clone());
        n.req(json!({"op": "alias_new", "name": "ghost", "ephemeral": false, "passphrase": "hunter2hunter2"}));
        let v = n.expect("status", 30, |v| v["ev"] == "status");
        let fp = v["fingerprint"].as_str().unwrap().to_string();
        n.kill();
        n.dir = PathBuf::new(); // keep the data dir for the restart
        fp
    };
    let mut n = Node::spawn_in(dir.clone());
    n.req(json!({"op": "status"}));
    assert!(n.expect("status", 5, |v| v["ev"] == "status")["alias"].is_null(), "starts locked");

    n.req(json!({"op": "unlock", "passphrase": "wrong-password"}));
    n.expect("unlock error", 30, |v| v["ev"] == "error");

    n.req(json!({"op": "unlock", "passphrase": "hunter2hunter2"}));
    let v = n.expect("status", 30, |v| v["ev"] == "status");
    assert_eq!(v["alias"], "ghost");
    assert_eq!(v["fingerprint"].as_str().unwrap(), fp);
}

#[test]
fn duplicate_alias_name_is_refused() {
    let (mut a, mut b, mut c) = (Node::spawn("dup-a"), Node::spawn("dup-b"), Node::spawn("dup-c"));
    a.alias("alice");
    b.alias("bob");
    c.alias("Bob");
    let (room, code) = a.room("r", "HostOnly", 15, false);
    b.join(&code);
    let code = a.invite(&room);
    c.req(json!({"op": "join", "code": code}));
    c.expect("name clash", 10, |v| v["ev"] == "error" && v["msg"].as_str().unwrap().contains("taken"));
}

#[test]
fn member_flood_is_rate_limited() {
    let (mut a, mut b) = (Node::spawn("fl-a"), Node::spawn("fl-b"));
    a.alias("alice");
    b.alias("bob");
    let (room, code) = a.room("r", "HostOnly", 15, false);
    b.join(&code);
    for i in 0..100 {
        b.send(&room, &format!("spam {i}"));
    }
    std::thread::sleep(Duration::from_secs(2));
    let got = a.rx.try_iter().filter(|v| v["ev"] == "line" && v["line"]["from"] == "bob").count();
    // burst of 20 plus ~5/s refill over the send window
    assert!((20..=35).contains(&got), "host accepted {got} of 100");
}

/// Needs a `tor` binary and internet access: `cargo test -- --ignored tor`.
#[test]
#[ignore]
fn tor_room_over_onion_services() {
    let tor_node = |tag: &str| {
        let dir = std::env::temp_dir().join(format!("cx-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        Node::spawn_with(dir, &["--tor"])
    };
    let (mut a, mut b) = (tor_node("tor-a"), tor_node("tor-b"));
    for n in [&mut a, &mut b] {
        let started = Instant::now();
        loop {
            n.req(json!({"op": "status"}));
            let v = n.expect("status", 10, |v| v["ev"] == "status");
            let label = v["listen"].as_str().unwrap().to_string();
            assert!(!label.contains("failed"), "{label}");
            if label == "tor ready" {
                eprintln!("tor ready after {:?}", started.elapsed());
                break;
            }
            assert!(started.elapsed() < Duration::from_secs(180), "tor never bootstrapped: {label}");
            std::thread::sleep(Duration::from_secs(1));
        }
    }
    a.alias("alice");
    b.alias("bob");
    let (room, code) = a.room("hidden", "HostOnly", 60, false);
    let addr = commx_core::invite::Invite::decode(&code).unwrap().addr;
    assert!(addr.ends_with(".onion:4700"), "{addr}");

    let started = Instant::now();
    b.req(json!({"op": "join", "code": code}));
    b.expect("join over tor", 200, |v| v["ev"] == "ok" && v["msg"].as_str().unwrap().starts_with("joined"));
    eprintln!("joined over tor after {:?}", started.elapsed());

    b.send(&room, "hello through three hops");
    a.expect("message over tor", 60, |v| v["ev"] == "line" && v["line"]["text"] == "hello through three hops");
    a.send(&room, "and back");
    b.expect("reply over tor", 60, |v| v["ev"] == "line" && v["line"]["text"] == "and back");

    a.kill();
    let reason = b.expect_nuked(&room, 90);
    eprintln!("member nuked: {reason}");
}

#[test]
fn file_shared_through_host_then_nuked_off_disk() {
    let (mut a, mut b, mut c) = (Node::spawn("f-a"), Node::spawn("f-b"), Node::spawn("f-c"));
    a.alias("alice");
    b.alias("bob");
    c.alias("carol");
    let (room, code) = a.room("files", "HostOnly", 15, false);
    b.join(&code);
    let code = a.invite(&room);
    c.join(&code);

    // 5 MiB + change of non-repeating bytes, so a plaintext scan is meaningful.
    let mut data = Vec::with_capacity(5 * 1024 * 1024 + 777);
    let mut x: u64 = 0x9e3779b97f4a7c15;
    while data.len() < 5 * 1024 * 1024 + 777 {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        data.extend_from_slice(&x.to_le_bytes());
    }
    let src = b.dir.join("report.bin");
    std::fs::write(&src, &data).unwrap();

    b.req(json!({"op": "send_file", "room_id": room, "path": src.to_str().unwrap()}));
    a.expect_system("is sharing #1 'report.bin'");
    c.expect_system("#1 'report.bin' ready");
    a.expect_system("#1 'report.bin' ready");
    b.expect_system("📎 #1 sent");

    // At rest: only random-named, padded ciphertext blobs.
    let blobs: Vec<_> = std::fs::read_dir(c.dir.join("blobs")).unwrap().flatten().map(|e| e.path()).collect();
    assert_eq!(blobs.len(), 1);
    let on_disk = std::fs::read(&blobs[0]).unwrap();
    assert!(on_disk.len() > data.len(), "padded");
    assert!(!on_disk.windows(32).step_by(7).any(|w| w == &data[4096..4128]), "plaintext on disk");

    let out = c.dir.join("export");
    std::fs::create_dir_all(&out).unwrap();
    c.req(json!({"op": "save_file", "room_id": room, "no": 1, "dest": out.to_str().unwrap()}));
    c.expect("save ok", 20, |v| v["ev"] == "ok" && v["msg"].as_str().unwrap().starts_with("saved #1"));
    assert_eq!(std::fs::read(out.join("report.bin")).unwrap(), data);

    a.req(json!({"op": "nuke", "room_id": room}));
    c.expect_nuked(&room, 10);
    std::thread::sleep(Duration::from_millis(300));
    for n in [&a, &c] {
        let left = std::fs::read_dir(n.dir.join("blobs")).map(|d| d.count()).unwrap_or(0);
        assert_eq!(left, 0, "blobs survived the nuke");
    }
}

#[test]
fn call_routes_voice_only_to_participants() {
    let (mut a, mut b, mut c) = (Node::spawn("c-a"), Node::spawn("c-b"), Node::spawn("c-c"));
    a.alias("alice");
    b.alias("bob");
    c.alias("carol");
    let (room, code) = a.room("vc", "HostOnly", 15, false);
    b.join(&code);
    let code = a.invite(&room);
    c.join(&code);

    // A member starts the call (goes through the host's chain).
    b.req(json!({"op": "call", "room_id": room}));
    a.expect_system("bob started a call");
    a.req(json!({"op": "call", "room_id": room}));
    b.expect_system("alice joined the call");
    c.expect("roster", 5, |v| {
        v["ev"] == "call" && v["call"]["participants"].as_array().is_some_and(|p| p.len() == 2) && v["call"]["joined"] == false
    });

    let frame = |i: u8| hex::encode([i; 60]);
    for i in 0..5u8 {
        a.req(json!({"op": "voice_out", "room_id": room, "opus": frame(i)}));
        b.req(json!({"op": "voice_out", "room_id": room, "opus": frame(100 + i)}));
    }
    for i in 0..5u8 {
        b.expect("voice from alice", 5, |v| v["ev"] == "voice_in" && v["from"] == "alice" && v["opus"] == frame(i));
        a.expect("voice from bob", 5, |v| v["ev"] == "voice_in" && v["from"] == "bob" && v["opus"] == frame(100 + i));
    }
    std::thread::sleep(Duration::from_millis(300));
    assert!(c.rx.try_iter().all(|v| v["ev"] != "voice_in"), "non-participant got audio");

    b.req(json!({"op": "hangup", "room_id": room}));
    a.expect_system("bob left the call");
    a.req(json!({"op": "hangup", "room_id": room}));
    c.expect_system("call ended");
}
