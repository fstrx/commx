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

fn wait_link(n: &mut Node, room: &str, want: &str) {
    let started = Instant::now();
    loop {
        n.req(json!({"op": "status"}));
        let v = n.expect("status", 5, |v| v["ev"] == "status");
        let link = v["rooms"].as_array().unwrap().iter().find(|r| r["room_id"] == room).unwrap()["link"].clone();
        if link == want {
            return;
        }
        assert!(started.elapsed() < Duration::from_secs(10), "link stuck at {link}, wanted {want}");
        std::thread::sleep(Duration::from_millis(300));
    }
}

fn voice_both_ways(a: &mut Node, b: &mut Node, room: &str) {
    a.req(json!({"op": "call", "room_id": room}));
    b.expect_system("alice started a call");
    b.req(json!({"op": "call", "room_id": room}));
    a.expect_system("bob joined the call");
    for i in 0..20u8 {
        a.req(json!({"op": "voice_out", "room_id": room, "opus": hex::encode([i; 60])}));
        b.req(json!({"op": "voice_out", "room_id": room, "opus": hex::encode([i ^ 0xff; 60])}));
        // Real clients emit one frame per 20 ms; the media lane drops bursts by design.
        std::thread::sleep(Duration::from_millis(20));
    }
    for i in 0..20u8 {
        b.expect("voice a→b", 5, |v| v["ev"] == "voice_in" && v["opus"] == hex::encode([i; 60]));
        a.expect("voice b→a", 5, |v| v["ev"] == "voice_in" && v["opus"] == hex::encode([i ^ 0xff; 60]));
    }
}

#[test]
fn voice_uses_udp_fast_path_when_available() {
    let (mut a, mut b) = (Node::spawn("u-a"), Node::spawn("u-b"));
    a.alias("alice");
    b.alias("bob");
    let (room, code) = a.room("udp", "HostOnly", 15, false);
    b.join(&code);
    wait_link(&mut b, &room, "udp");
    wait_link(&mut a, &room, "udp 1/1");
    voice_both_ways(&mut a, &mut b, &room);
}

#[test]
fn voice_falls_back_to_tcp_without_udp() {
    let dir = std::env::temp_dir().join(format!("cx-{}-nu-a", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let mut a = Node::spawn_with(dir, &["--no-udp"]);
    let mut b = Node::spawn("nu-b");
    a.alias("alice");
    b.alias("bob");
    let (room, code) = a.room("tcp", "HostOnly", 15, false);
    b.join(&code);
    std::thread::sleep(Duration::from_secs(2));
    wait_link(&mut b, &room, "tcp");
    voice_both_ways(&mut a, &mut b, &room);
}

// ---- Fault containment: no single peer, room, transfer, or UI operation may
// terminate the daemon. Faults are injected via a debug-only IPC request.

fn fault(n: &mut Node, scope: &str, room: Option<&str>) {
    n.req(json!({"op": "debug_fault", "scope": scope, "room_id": room}));
}

fn assert_alive(n: &mut Node) {
    n.req(json!({"op": "status"}));
    n.expect("daemon still alive", 5, |v| v["ev"] == "status");
    assert!(n.child.try_wait().unwrap().is_none(), "daemon process exited");
}

#[test]
fn panicking_ui_request_is_an_error_not_a_crash() {
    let mut a = Node::spawn("ff-ipc");
    a.alias("alice");
    fault(&mut a, "ipc", None);
    let v = a.expect("contained error", 5, |v| v["ev"] == "error");
    assert!(v["msg"].as_str().unwrap().contains("contained"), "{v}");
    assert_alive(&mut a);
    // The same client keeps working.
    a.room("after", "HostOnly", 15, false);
}

#[test]
fn room_fault_destroys_only_that_room() {
    let (mut a, mut b, mut c) = (Node::spawn("ff-a"), Node::spawn("ff-b"), Node::spawn("ff-c"));
    a.alias("alice");
    b.alias("bob");
    c.alias("carol");
    let (bad, code) = a.room("bad", "HostOnly", 15, false);
    b.join(&code);
    let (good, code) = a.room("good", "HostOnly", 15, false);
    c.join(&code);

    // Next message from bob panics alice's handler for room "bad".
    fault(&mut a, "wire", Some(&bad));
    a.expect("armed", 5, |v| v["ev"] == "ok");
    b.send(&bad, "trigger");
    assert!(a.expect_nuked(&bad, 5).contains("internal fault"));
    assert!(b.expect_nuked(&bad, 5).contains("host nuked"), "peers told, not left hanging");

    // Everything else on the same daemon is untouched.
    assert_alive(&mut a);
    c.send(&good, "still fine?");
    a.expect_msg("carol", "still fine?");
    a.send(&good, "yes");
    c.expect_msg("alice", "yes");
}

#[test]
fn room_tick_fault_destroys_only_that_room() {
    let (mut a, mut b, mut c) = (Node::spawn("ft-a"), Node::spawn("ft-b"), Node::spawn("ft-c"));
    a.alias("alice");
    b.alias("bob");
    c.alias("carol");
    let (bad, code) = a.room("bad", "HostOnly", 3, false);
    b.join(&code);
    let (good, code) = a.room("good", "HostOnly", 3, false);
    c.join(&code);
    fault(&mut a, "tick", Some(&bad));
    assert!(a.expect_nuked(&bad, 5).contains("internal fault"));
    // "good" keeps its heartbeats: well past its 3 s grace, carol is still in.
    std::thread::sleep(Duration::from_secs(5));
    c.send(&good, "alive");
    a.expect_msg("carol", "alive");
}

#[test]
fn crashed_kill_switch_ticker_is_restarted() {
    let (mut a, mut b) = (Node::spawn("fk-a"), Node::spawn("fk-b"));
    a.alias("alice");
    b.alias("bob");
    let (room, code) = a.room("r", "AnyMember", 3, false);
    b.join(&code);
    fault(&mut a, "tick-task", None);
    a.expect("armed", 5, |v| v["ev"] == "ok");
    std::thread::sleep(Duration::from_secs(2));
    assert_alive(&mut a);
    // If the ticker hadn't come back, liveness checks would be dead and a
    // frozen member would never be noticed.
    unsafe { libc::kill(b.child.id() as i32, libc::SIGSTOP) };
    assert!(a.expect_nuked(&room, 10).contains("timed out"));
}

#[test]
fn hostile_network_input_cannot_kill_the_daemon() {
    use std::io::Write as _;
    let (mut a, mut b) = (Node::spawn("fh-a"), Node::spawn("fh-b"));
    a.alias("alice");
    b.alias("bob");
    let (room, code) = a.room("r", "HostOnly", 15, false);
    let addr = commx_core::invite::Invite::decode(&code).unwrap().addr;
    b.join(&code);

    let mut x: u64 = 0x1234_5678;
    let mut junk = |n: usize| {
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect::<Vec<u8>>()
    };
    // Garbage, oversized length prefixes, and half-open handshakes on TCP.
    let mut held = Vec::new();
    for i in 0..60 {
        if let Ok(mut s) = std::net::TcpStream::connect(&addr) {
            let _ = match i % 3 {
                0 => s.write_all(&junk(4096)),
                1 => s.write_all(&[0xff, 0xff, 0xff, 0xff]),
                _ => Ok(()),
            };
            held.push(s);
        }
    }
    // Garbage and truncated datagrams on UDP.
    let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    for n in [0usize, 1, 8, 40, 48, 300, 1200, 1500] {
        for _ in 0..20 {
            let _ = udp.send_to(&junk(n), &addr);
        }
    }
    drop(held);
    std::thread::sleep(Duration::from_millis(500));

    assert_alive(&mut a);
    b.send(&room, "unbothered");
    a.expect_msg("bob", "unbothered");
}

#[test]
fn malicious_file_name_cannot_escape_the_save_directory() {
    let (mut a, mut b) = (Node::spawn("pt-a"), Node::spawn("pt-b"));
    a.alias("alice");
    b.alias("mallory");
    let (room, code) = a.room("r", "HostOnly", 15, false);
    b.join(&code);

    // Victim's layout: <dir>/home/Downloads is where /save goes by default.
    let home = a.dir.join("home");
    let downloads = home.join("Downloads");
    std::fs::create_dir_all(home.join(".ssh")).unwrap();
    std::fs::create_dir_all(&downloads).unwrap();
    let payload = b.dir.join("payload");
    std::fs::write(&payload, b"ssh-ed25519 AAAA attacker").unwrap();

    b.req(json!({"op": "debug_send_file_as", "room_id": room, "path": payload.to_str().unwrap(),
                 "name": "../.ssh/authorized_keys"}));
    a.expect_system("ready — /save 1");
    a.req(json!({"op": "save_file", "room_id": room, "no": 1, "dest": downloads.to_str().unwrap()}));
    a.expect("saved", 10, |v| v["ev"] == "ok" && v["msg"].as_str().unwrap().starts_with("saved #1"));

    assert!(!home.join(".ssh/authorized_keys").exists(), "wrote outside Downloads");
    assert_eq!(std::fs::read(downloads.join("authorized_keys")).unwrap(), b"ssh-ed25519 AAAA attacker");
}

fn pw_invite(n: &mut Node, room: &str, password: &str) -> String {
    n.req(json!({"op": "invite_password", "room_id": room, "password": password}));
    let v = n.expect("password invite", 10, |v| v["ev"] == "invite_code");
    assert_eq!(v["reusable"], true);
    v["code"].as_str().unwrap().into()
}

/// Join request that must fail; returns the error text.
fn join_err(n: &mut Node, code: &str, password: Option<&str>) -> String {
    n.req(json!({"op": "join", "code": code, "password": password}));
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match n.rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(v) if v["ev"] == "error" => return v["msg"].as_str().unwrap().to_string(),
            Ok(v) if v["ev"] == "ok" && v["msg"].as_str().unwrap().starts_with("joined") => panic!("join should fail"),
            Ok(_) => {}
            Err(_) => panic!("timed out waiting for join error"),
        }
    }
}

#[test]
fn password_invite_is_reusable_and_needs_the_password() {
    let (mut a, mut b, mut c) = (Node::spawn("pw-a"), Node::spawn("pw-b"), Node::spawn("pw-c"));
    a.alias("alice");
    b.alias("bob");
    c.alias("carol");
    let (room, _) = a.room("club", "HostOnly", 15, false);
    let code = pw_invite(&mut a, &room, "open sesame 42");
    assert!(code.starts_with("cx2:"));

    assert!(join_err(&mut b, &code, None).contains("needs a password"));
    assert!(join_err(&mut b, &code, Some("open sesame 41")).contains("wrong password"));
    a.expect_system("wrong password");
    // Same code, twice more: it's reusable.
    b.req(json!({"op": "join", "code": code, "password": "open sesame 42"}));
    b.expect("bob joins", 10, |v| v["ev"] == "ok" && v["msg"].as_str().unwrap().starts_with("joined"));
    c.req(json!({"op": "join", "code": code, "password": "open sesame 42"}));
    c.expect("carol joins", 10, |v| v["ev"] == "ok" && v["msg"].as_str().unwrap().starts_with("joined"));
    a.send(&room, "welcome both");
    b.expect_msg("alice", "welcome both");
    c.expect_msg("alice", "welcome both");

    // Revoked: the same code is dead, even with the right password.
    a.req(json!({"op": "invite_revoke", "room_id": room}));
    a.expect("revoked", 5, |v| v["ev"] == "ok");
    let mut d = Node::spawn("pw-d");
    d.alias("dave");
    assert!(join_err(&mut d, &code, Some("open sesame 42")).contains("invalid or revoked"));
}

#[test]
fn password_invite_locks_after_repeated_wrong_passwords() {
    let (mut a, mut b) = (Node::spawn("pwl-a"), Node::spawn("pwl-b"));
    a.alias("alice");
    b.alias("bob");
    let (room, _) = a.room("club", "HostOnly", 15, false);
    let code = pw_invite(&mut a, &room, "open sesame 42");
    for i in 0..5 {
        assert!(join_err(&mut b, &code, Some(&format!("guess number {i}"))).contains("wrong password"));
    }
    a.expect_system("password invite paused");
    // Now even the right password is refused, before any proof is checked.
    assert!(join_err(&mut b, &code, Some("open sesame 42")).contains("too many wrong passwords"));
    // A fresh invite (new token) works again.
    let code2 = pw_invite(&mut a, &room, "new password 99");
    b.req(json!({"op": "join", "code": code2, "password": "new password 99"}));
    b.expect("bob joins", 10, |v| v["ev"] == "ok" && v["msg"].as_str().unwrap().starts_with("joined"));
}

#[test]
fn password_proof_is_never_sent_to_an_unproven_host() {
    // An attacker who intercepts the connection can't pass the host proof,
    // so the joiner must give up before sending anything password-derived.
    // Simulate by pointing the invite at the right address but a different
    // host key: the real host then looks like an impostor to the joiner.
    let (mut a, mut b) = (Node::spawn("pwm-a"), Node::spawn("pwm-b"));
    a.alias("alice");
    b.alias("bob");
    let (room, _) = a.room("club", "HostOnly", 15, false);
    let code = pw_invite(&mut a, &room, "open sesame 42");
    let mut inv = commx_core::invite::Invite::decode(&code).unwrap();
    inv.host = commx_core::identity::Identity::generate("mallory").public();
    let err = join_err(&mut b, &inv.encode(), Some("open sesame 42"));
    assert!(err.contains("host failed identity proof"), "{err}");
    // The host never saw a password attempt at all.
    a.req(json!({"op": "history", "room_id": room}));
    let h = a.expect("history", 5, |v| v["ev"] == "history");
    assert!(!h.to_string().contains("wrong password"), "{h}");
}

#[test]
fn web_tls_port_still_takes_native_peers_and_redirects_http() {
    let dir = std::env::temp_dir().join(format!("cx-{}-tls-a", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let web = std::env::temp_dir().join(format!("cx-{}-tls-web", std::process::id()));
    std::fs::create_dir_all(&web).unwrap();
    let mut a = Node::spawn_with(dir, &["--web", web.to_str().unwrap(), "--web-tls"]);
    let mut b = Node::spawn("tls-b");
    a.alias("alice");
    b.alias("bob");
    a.req(json!({"op": "room_new", "name": "lounge", "kill_mode": "HostOnly", "grace_secs": 15, "dm": false}));
    let inv = a.expect("invite", 5, |v| v["ev"] == "invite_code");
    let (room, code) = (inv["room_id"].as_str().unwrap().to_string(), inv["code"].as_str().unwrap().to_string());
    assert!(inv["web_link"].as_str().unwrap().starts_with("https://"), "{inv}");
    assert_eq!(inv["web_cert"].as_str().unwrap().len(), 32 * 3 - 1, "{inv}");

    // Native peers share the port with HTTPS.
    b.join(&code);
    a.send(&room, "over noise");
    b.expect_msg("alice", "over noise");

    // Plain http only redirects; it never serves the client.
    let addr = commx_core::invite::Invite::decode(&code).unwrap().addr;
    let mut s = std::net::TcpStream::connect(&addr).unwrap();
    write!(s, "GET /app.js HTTP/1.1\r\nHost: {addr}\r\n\r\n").unwrap();
    let mut resp = String::new();
    std::io::Read::read_to_string(&mut s, &mut resp).unwrap();
    assert!(resp.starts_with("HTTP/1.1 308"), "{resp}");
    assert!(resp.contains(&format!("Location: https://{addr}/app.js")), "{resp}");
    let _ = std::fs::remove_dir_all(&web);
}
