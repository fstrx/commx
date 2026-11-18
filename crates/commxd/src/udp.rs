//! UDP fast path for voice in direct-TCP mode.
//!
//! TCP's in-order delivery turns one lost packet into a stall for every frame
//! behind it, which is bad for live audio. Each room connection therefore also
//! gets a UDP path keyed from its channel secret (`Conn::secret`: both ends
//! know it, nobody else does), so no extra handshake is needed:
//!
//! `datagram = path_id(8) | key_idx(BE32) | nonce(24) | XChaCha20-Poly1305(K[key_idx], postcard(UdpMsg), aad = path_id | key_idx)`
//!
//! Each direction has its own key chain, `K[i+1] = KDF(K[i])`. The sender
//! steps forward every 512 datagrams or 30 s and forgets the old key; the
//! receiver keeps the current and previous key and follows the sender
//! forward (at most 64 steps at once, committed only once a datagram under
//! the new key authenticates). A key taken from a running node opens at most
//! the last minute or so of recorded datagrams.
//!
//! The member pings the host every second; the host learns the member's
//! (possibly NAT-mapped) address only from authenticated pings and answers with
//! a same-size pong, so the socket can't be used for amplification or to aim
//! traffic at third parties. Voice uses the path while it's fresh and falls
//! back to the TCP media lane otherwise. Voice frames inside are still sealed
//! end-to-end with the call key; this layer only authenticates the hop.
//!
//! Never used in Tor mode: there is no UDP socket at all, so no IP can leak.

use commx_core::crypto::{aead_decrypt, aead_encrypt};
use commx_core::secmem::Locked;
use commx_core::wire::WireMsg;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use zeroize::Zeroizing;

use crate::state::{lock, PeerKind, Role, Shared};
use crate::supervise::{contain, io_backoff, supervise};

/// A path is used for voice only if we heard from the other end this recently.
pub const FRESH: Duration = Duration::from_secs(3);
pub const PING_EVERY: Duration = Duration::from_secs(1);
const MAX_DATAGRAM: usize = 1200;
const HEADER: usize = 8 + 4 + 24;
/// Outgoing datagrams queued before we start dropping (they'd be late anyway).
const OUT_QUEUE: usize = 256;
/// The sender moves to the next key after this many datagrams...
const ROTATE_AFTER: u32 = 512;
/// ...or this long, whichever comes first.
const ROTATE_EVERY: Duration = Duration::from_secs(30);
/// Furthest a receiver follows the sender's key chain in one go.
const MAX_SKIP: u32 = 64;

pub type Outbox = mpsc::Sender<(SocketAddr, Vec<u8>)>;

#[derive(Serialize, Deserialize)]
enum UdpMsg {
    Ping,
    Pong,
    Voice(Box<WireMsg>),
}

fn step(k: &[u8; 32]) -> Locked<32> {
    Locked::from_bytes(&Zeroizing::new(blake3::derive_key("commx udp ratchet v2", k)))
}

struct SendChain {
    idx: u32,
    key: Locked<32>,
    used: u32,
    since: Instant,
}

impl SendChain {
    /// The key for the next datagram, stepping (and forgetting) first if due.
    fn next(&mut self) -> (u32, &[u8; 32]) {
        if self.used >= ROTATE_AFTER || self.since.elapsed() >= ROTATE_EVERY {
            self.key = step(self.key.bytes());
            self.idx = self.idx.wrapping_add(1);
            self.used = 0;
            self.since = Instant::now();
        }
        self.used += 1;
        (self.idx, self.key.bytes())
    }
}

struct RecvChain {
    idx: u32,
    key: Locked<32>,
    prev: Option<Locked<32>>,
}

pub struct UdpPath {
    pub id: [u8; 8],
    /// Behind a mutex so voice can go out through `&self`.
    send: Mutex<SendChain>,
    recv: RecvChain,
    /// Where the other end is. Member side: the host's address from the invite.
    /// Host side: learned from the member's authenticated pings.
    pub remote: Option<SocketAddr>,
    pub last_rx: Option<Instant>,
    last_ping: Option<Instant>,
    out: Outbox,
}

impl UdpPath {
    /// `secret` is the connection's channel secret; `initiator` says which
    /// end dialled (the member).
    pub fn new(secret: &[u8; 32], initiator: bool, remote: Option<SocketAddr>, out: Outbox) -> Self {
        let id_full = blake3::derive_key("commx udp id v2", secret);
        let i2r = Locked::from_bytes(&Zeroizing::new(blake3::derive_key("commx udp i2r v2", secret)));
        let r2i = Locked::from_bytes(&Zeroizing::new(blake3::derive_key("commx udp r2i v2", secret)));
        let (send, recv) = if initiator { (i2r, r2i) } else { (r2i, i2r) };
        Self {
            id: id_full[..8].try_into().unwrap(),
            send: Mutex::new(SendChain { idx: 0, key: send, used: 0, since: Instant::now() }),
            recv: RecvChain { idx: 0, key: recv, prev: None },
            remote,
            last_rx: None,
            last_ping: None,
            out,
        }
    }

    pub fn fresh(&self) -> bool {
        self.remote.is_some() && self.last_rx.is_some_and(|t| t.elapsed() < FRESH)
    }

    fn aad(&self, idx: u32) -> [u8; 12] {
        let mut a = [0u8; 12];
        a[..8].copy_from_slice(&self.id);
        a[8..].copy_from_slice(&idx.to_be_bytes());
        a
    }

    fn seal(&self, msg: &UdpMsg) -> Option<Vec<u8>> {
        let plain = Zeroizing::new(postcard::to_allocvec(msg).ok()?);
        let mut chain = self.send.lock().unwrap_or_else(|e| e.into_inner());
        let (idx, key) = chain.next();
        let (nonce, ct) = aead_encrypt(key, &plain, &self.aad(idx)).ok()?;
        let mut d = Vec::with_capacity(HEADER + ct.len());
        d.extend_from_slice(&self.id);
        d.extend_from_slice(&idx.to_be_bytes());
        d.extend_from_slice(&nonce);
        d.extend_from_slice(&ct);
        (d.len() <= MAX_DATAGRAM).then_some(d)
    }

    fn send_to(&self, to: SocketAddr, msg: &UdpMsg) {
        if let Some(d) = self.seal(msg) {
            let _ = self.out.try_send((to, d));
        }
    }

    /// Send a voice frame over UDP if the path is up. Returns false to make
    /// the caller fall back to TCP.
    pub fn send_voice(&self, msg: &WireMsg) -> bool {
        match self.remote {
            Some(to) if self.fresh() => {
                self.send_to(to, &UdpMsg::Voice(Box::new(msg.clone())));
                true
            }
            _ => false,
        }
    }

    /// Member side: keep the path (and any NAT mapping) alive.
    pub fn maybe_ping(&mut self) {
        let due = self.last_ping.is_none_or(|t| t.elapsed() >= PING_EVERY);
        if let (true, Some(to)) = (due, self.remote) {
            self.last_ping = Some(Instant::now());
            self.send_to(to, &UdpMsg::Ping);
        }
    }

    fn open(&mut self, datagram: &[u8]) -> Option<UdpMsg> {
        let idx = u32::from_be_bytes(datagram.get(8..12)?.try_into().ok()?);
        let nonce: [u8; 24] = datagram.get(12..HEADER)?.try_into().ok()?;
        let ct = &datagram[HEADER..];
        let aad = self.aad(idx);
        let r = &self.recv;
        let plain = if idx == r.idx {
            aead_decrypt(r.key.bytes(), &nonce, ct, &aad).ok()?
        } else if idx.wrapping_add(1) == r.idx {
            aead_decrypt(r.prev.as_ref()?.bytes(), &nonce, ct, &aad).ok()?
        } else if idx > r.idx && idx - r.idx <= MAX_SKIP {
            // The sender moved on. Follow it, but only keep the new keys
            // if this datagram really is under them.
            let mut prev = Locked::from_bytes(r.key.bytes());
            let mut k = step(r.key.bytes());
            for _ in r.idx + 1..idx {
                prev = k;
                k = step(prev.bytes());
            }
            let plain = aead_decrypt(k.bytes(), &nonce, ct, &aad).ok()?;
            self.recv = RecvChain { idx, key: k, prev: Some(prev) };
            plain
        } else {
            return None;
        };
        postcard::from_bytes(&plain).ok()
    }
}

/// Bind the UDP socket and start the send/receive tasks. Returns the outbox
/// connections use to send.
pub fn start(shared: Shared, socket: UdpSocket) -> Outbox {
    let socket = Arc::new(socket);
    let (out, rx) = mpsc::channel::<(SocketAddr, Vec<u8>)>(OUT_QUEUE);
    // Shared so a restarted sender loop picks up the same queue.
    let rx = Arc::new(tokio::sync::Mutex::new(rx));
    let tx_sock = socket.clone();
    supervise("udp sender", move || {
        let (rx, sock) = (rx.clone(), tx_sock.clone());
        async move {
            let mut rx = rx.lock().await;
            while let Some((to, d)) = rx.recv().await {
                let _ = sock.send_to(&d, to).await;
            }
        }
    });
    supervise("udp receiver", move || {
        let (shared, socket) = (shared.clone(), socket.clone());
        async move {
            let mut buf = vec![0u8; 2048];
            loop {
                let (n, from) = match socket.recv_from(&mut buf).await {
                    Ok(x) => x,
                    Err(_) => {
                        io_backoff().await;
                        continue;
                    }
                };
                if !(HEADER + 16..=MAX_DATAGRAM).contains(&n) {
                    continue;
                }
                on_datagram(&shared, &buf[..n], from);
            }
        }
    });
    out
}

fn on_datagram(shared: &Shared, d: &[u8], from: SocketAddr) {
    let id: [u8; 8] = d[..8].try_into().unwrap();
    let mut daemon = lock(shared);
    let Some((room_id, kind)) = daemon.udp_index.get(&id).copied() else { return };
    // Fault boundary: a datagram can cost at most its room.
    if contain(|| handle_datagram(&mut daemon, room_id, kind, id, d, from)).is_err() {
        daemon.contained_fault(&room_id);
    }
}

fn handle_datagram(
    daemon: &mut crate::state::Daemon,
    room_id: commx_core::RoomId,
    kind: PeerKind,
    id: [u8; 8],
    d: &[u8],
    from: SocketAddr,
) {
    let ev = daemon.events.clone();
    let Some(room) = daemon.rooms.get_mut(&room_id) else {
        daemon.udp_index.remove(&id);
        return;
    };
    let path = match (&mut room.role, kind) {
        (Role::Host { peers }, PeerKind::Member(pk)) => peers.get_mut(&pk).and_then(|p| p.udp.as_mut()),
        (Role::Member { host }, PeerKind::Host) => host.udp.as_mut(),
        _ => None,
    };
    let Some(path) = path else {
        daemon.udp_index.remove(&id);
        return;
    };
    // Unauthenticated datagrams are dropped without any reply.
    let Some(msg) = path.open(d) else { return };
    path.last_rx = Some(Instant::now());
    match msg {
        UdpMsg::Ping => {
            // Host side: this is how we learn (and track NAT changes of) the member's address.
            path.remote = Some(from);
            path.send_to(from, &UdpMsg::Pong);
        }
        UdpMsg::Pong => {}
        UdpMsg::Voice(v) => {
            if matches!(*v, WireMsg::Voice { room_id: r, .. } if r == room_id) {
                room.touch(kind);
                room.on_voice(&ev, kind, *v);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (UdpPath, UdpPath) {
        let (out, _rx) = mpsc::channel(4);
        (UdpPath::new(&[7; 32], true, None, out.clone()), UdpPath::new(&[7; 32], false, None, out))
    }

    #[test]
    fn paths_from_the_same_channel_interoperate() {
        let (a, mut b) = pair();
        let (out, _rx) = mpsc::channel(4);
        let mut other = UdpPath::new(&[8; 32], false, None, out);
        assert_eq!(a.id, b.id);
        assert_ne!(a.id, other.id);
        let d = a.seal(&UdpMsg::Ping).unwrap();
        assert!(other.open(&d).is_none(), "foreign path can't open");
        let mut bad = d.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(b.open(&bad).is_none(), "tampered");
        assert!(matches!(b.open(&d), Some(UdpMsg::Ping)));
        // Each direction has its own keys: a datagram doesn't open on its sender's side.
        let mut a = a;
        assert!(a.open(&d).is_none());
        // ping and pong are the same size: no amplification
        assert_eq!(a.seal(&UdpMsg::Ping).unwrap().len(), a.seal(&UdpMsg::Pong).unwrap().len());
    }

    #[test]
    fn keys_ratchet_and_old_ones_are_gone() {
        let (a, mut b) = pair();
        let first = a.seal(&UdpMsg::Ping).unwrap();
        // Push the sender three keys on.
        for _ in 0..3 * ROTATE_AFTER {
            a.seal(&UdpMsg::Ping).unwrap();
        }
        let later = a.seal(&UdpMsg::Ping).unwrap();
        assert_eq!(u32::from_be_bytes(later[8..12].try_into().unwrap()), 3);
        assert!(matches!(b.open(&later), Some(UdpMsg::Ping)), "receiver follows forward");
        assert!(b.open(&first).is_none(), "and can't go back");
        // A forged index far ahead doesn't move the receiver.
        let mut forged = later.clone();
        forged[8..12].copy_from_slice(&40u32.to_be_bytes());
        assert!(b.open(&forged).is_none());
        assert_eq!(b.recv.idx, 3);
    }
}
