//! The browser member client, run natively against a real in-process commxd
//! host over TCP (the same bytes the browser carries over its WebSocket).

use commx_core::secmem::ZLines;
use commx_web::Member;
use serde_json::{json, Value};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

struct Host {
    tx: mpsc::UnboundedSender<String>,
    rx: mpsc::UnboundedReceiver<Value>,
    _stop: tokio::sync::oneshot::Sender<()>,
}

impl Host {
    async fn start(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("cx-web-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (clients_tx, clients_rx) = mpsc::unbounded_channel();
        let (ui, daemon) = tokio::io::duplex(1 << 20);
        let (dr, dw) = tokio::io::split(daemon);
        clients_tx.send((Box::new(dr) as commxd::Reader, Box::new(dw) as commxd::Writer)).unwrap();
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let cfg = commxd::Config {
            data_dir: dir,
            listen: "127.0.0.1:0".into(),
            advertise: None,
            keep_awake: false,
            tor: false,
            tor_bin: String::new(),
            no_udp: true,
            web_dir: None,
        };
        tokio::spawn(async move {
            let _keep = clients_tx;
            let _ = commxd::run(cfg, commxd::Control::InProcess(clients_rx), async {
                let _ = stop_rx.await;
            })
            .await;
        });
        let (ur, mut uw) = tokio::io::split(ui);
        let (tx, mut req_rx) = mpsc::unbounded_channel::<String>();
        tokio::spawn(async move {
            while let Some(mut l) = req_rx.recv().await {
                l.push('\n');
                if uw.write_all(l.as_bytes()).await.is_err() {
                    break;
                }
            }
        });
        let (ev_tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            let mut lines = ZLines::new(ur, 1 << 22);
            while let Ok(Some(l)) = lines.next_line().await {
                if ev_tx.send(serde_json::from_slice(&l).unwrap()).is_err() {
                    break;
                }
            }
        });
        Host { tx, rx, _stop: stop_tx }
    }

    fn req(&self, v: Value) {
        self.tx.send(v.to_string()).unwrap();
    }

    async fn expect(&mut self, what: &str, pred: impl Fn(&Value) -> bool) -> Value {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let v = self.rx.recv().await.expect("host gone");
                if pred(&v) {
                    return v;
                }
            }
        })
        .await
        .unwrap_or_else(|_| panic!("host: timed out waiting for {what}"))
    }
}

/// Move bytes between member and host until an event matches `pred`.
async fn pump(m: &mut Member, sock: &mut TcpStream, what: &str, pred: impl Fn(&Value) -> bool) -> Value {
    let mut buf = vec![0u8; 65536];
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let out = m.take_outgoing();
            if !out.is_empty() {
                sock.write_all(&out).await.unwrap();
            }
            for e in m.take_events() {
                if pred(&e) {
                    return e;
                }
            }
            match tokio::time::timeout(Duration::from_millis(100), sock.read(&mut buf)).await {
                Ok(Ok(0)) => m.on_close(),
                Ok(Ok(n)) => m.on_bytes(&buf[..n]),
                _ => {}
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("member: timed out waiting for {what}"))
}

async fn host_with_room(tag: &str, grace: u64) -> (Host, String, String) {
    let mut host = Host::start(tag).await;
    host.req(json!({"op": "alias_new", "name": "alice", "ephemeral": true, "passphrase": null}));
    host.expect("alias", |v| v["ev"] == "status").await;
    host.req(json!({"op": "room_new", "name": "lounge", "kill_mode": "HostOnly", "grace_secs": grace, "dm": false}));
    let inv = host.expect("invite", |v| v["ev"] == "invite_code").await;
    (host, inv["code"].as_str().unwrap().to_string(), inv["room_id"].as_str().unwrap().to_string())
}

#[tokio::test(flavor = "multi_thread")]
async fn web_member_joins_and_chats_both_ways() {
    let (mut host, code, room) = host_with_room("chat", 15).await;
    let addr = commx_core::invite::Invite::decode(&code).unwrap().addr;
    let mut m = Member::new(&code, "webby", None).unwrap();
    let mut sock = TcpStream::connect(&addr).await.unwrap();

    let joined = pump(&mut m, &mut sock, "joined", |e| e["ev"] == "joined").await;
    assert_eq!(joined["name"], "lounge");
    assert_eq!(joined["host"], "alice");
    host.expect("webby joined", |v| v["ev"] == "line" && v["line"]["text"].as_str().unwrap().contains("webby joined"))
        .await;

    host.req(json!({"op": "send", "room_id": room, "text": "hi from the host"}));
    pump(&mut m, &mut sock, "host message", |e| e["ev"] == "line" && e["text"] == "hi from the host").await;

    m.send_text("hi from the browser").unwrap();
    pump(&mut m, &mut sock, "own message echoed", |e| e["ev"] == "line" && e["mine"] == true).await;
    host.expect("browser message", |v| v["ev"] == "line" && v["line"]["text"] == "hi from the browser").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn web_member_stays_alive_by_answering_heartbeats() {
    let (host, code, room) = host_with_room("hb", 3).await;
    let addr = commx_core::invite::Invite::decode(&code).unwrap().addr;
    let mut m = Member::new(&code, "webby", None).unwrap();
    let mut sock = TcpStream::connect(&addr).await.unwrap();
    pump(&mut m, &mut sock, "joined", |e| e["ev"] == "joined").await;

    // The member sends nothing on its own; only replies. Well past the 3 s grace:
    let quiet = pump(&mut m, &mut sock, "6 s of quiet", |e| e["ev"] == "nuked");
    assert!(tokio::time::timeout(Duration::from_secs(6), quiet).await.is_err(), "member was dropped");
    host.req(json!({"op": "send", "room_id": room, "text": "still here?"}));
    pump(&mut m, &mut sock, "message after quiet", |e| e["ev"] == "line" && e["text"] == "still here?").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn web_member_honours_host_nuke() {
    let (host, code, room) = host_with_room("nuke", 15).await;
    let addr = commx_core::invite::Invite::decode(&code).unwrap().addr;
    let mut m = Member::new(&code, "webby", None).unwrap();
    let mut sock = TcpStream::connect(&addr).await.unwrap();
    pump(&mut m, &mut sock, "joined", |e| e["ev"] == "joined").await;
    host.req(json!({"op": "nuke", "room_id": room}));
    let e = pump(&mut m, &mut sock, "nuked", |e| e["ev"] == "nuked").await;
    assert_eq!(e["reason"], "host nuked the room");
    assert!(m.is_dead());
    assert!(m.send_text("too late").is_err());
}

#[test]
fn garbage_from_the_network_ends_the_room_without_panicking() {
    let code = {
        let inv = commx_core::invite::Invite {
            addr: "127.0.0.1:1".into(),
            host: commx_core::identity::Identity::generate("h").public(),
            room_id: [1; 16],
            token: [2; 16],
            password: false,
        };
        inv.encode()
    };
    for junk in [vec![0u8; 3], vec![0xff; 8], vec![0, 0, 0, 5, 1, 2, 3, 4, 5], vec![0, 0, 0, 0]] {
        let mut m = Member::new(&code, "webby", None).unwrap();
        m.on_bytes(&junk);
        m.on_bytes(&[0, 0, 0, 2, 9, 9]);
        let _ = m.take_events();
    }
    assert!(Member::new("not an invite", "webby", None).is_err());
    assert!(Member::new(&code, "two words", None).is_err());
}

async fn pw_room(host: &mut Host, room: &str, pw: &str) -> String {
    host.req(json!({"op": "invite_password", "room_id": room, "password": pw}));
    host.expect("pw invite", |v| v["ev"] == "invite_code" && v["reusable"] == true).await["code"].as_str().unwrap().to_string()
}

#[tokio::test(flavor = "multi_thread")]
async fn web_member_joins_with_password_invite() {
    let (mut host, _, room) = host_with_room("pw", 15).await;
    let code = pw_room(&mut host, &room, "open sesame 42").await;
    let addr = commx_core::invite::Invite::decode(&code).unwrap().addr;
    assert!(Member::new(&code, "webby", None).is_err(), "cx2 needs a password");

    let mut bad = Member::new(&code, "webby", Some("open sesame 41")).unwrap();
    let mut sock = TcpStream::connect(&addr).await.unwrap();
    let e = pump(&mut bad, &mut sock, "denied", |e| e["ev"] == "error").await;
    assert!(e["msg"].as_str().unwrap().contains("wrong password"), "{e}");

    for name in ["webby", "webster"] {
        let mut m = Member::new(&code, name, Some("open sesame 42")).unwrap();
        let mut sock = TcpStream::connect(&addr).await.unwrap();
        pump(&mut m, &mut sock, "joined", |e| e["ev"] == "joined").await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn web_member_never_sends_password_proof_to_unproven_host() {
    let (mut host, _, room) = host_with_room("pwm", 15).await;
    let code = pw_room(&mut host, &room, "open sesame 42").await;
    let mut inv = commx_core::invite::Invite::decode(&code).unwrap();
    inv.host = commx_core::identity::Identity::generate("mallory").public();
    let mut m = Member::new(&inv.encode(), "webby", Some("open sesame 42")).unwrap();
    let mut sock = TcpStream::connect(&inv.addr).await.unwrap();
    let e = pump(&mut m, &mut sock, "nuked", |e| e["ev"] == "nuked").await;
    assert!(e["reason"].as_str().unwrap().contains("host failed identity proof"), "{e}");
}
