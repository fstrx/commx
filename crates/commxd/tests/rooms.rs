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
        let child = Command::new(env!("CARGO_BIN_EXE_commxd"))
            .args(["--data-dir", dir.to_str().unwrap(), "--listen", "127.0.0.1:0", "--no-keep-awake"])
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
