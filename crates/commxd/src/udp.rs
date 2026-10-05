//! UDP fast path for voice in direct-TCP mode.
//!
//! TCP's in-order delivery turns one lost packet into a stall for every frame
//! behind it, which is bad for live audio. Each room connection therefore also
//! gets a UDP path keyed from its Noise handshake hash (both ends know it,
//! nobody else does), so no extra handshake is needed:
//!
//! `datagram = path_id(8) | nonce(24) | XChaCha20-Poly1305(udp_key, postcard(UdpMsg))`
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
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::state::{lock, PeerKind, Role, Shared};

/// A path is used for voice only if we heard from the other end this recently.
pub const FRESH: Duration = Duration::from_secs(3);
pub const PING_EVERY: Duration = Duration::from_secs(1);
const MAX_DATAGRAM: usize = 1200;
/// Outgoing datagrams queued before we start dropping (they'd be late anyway).
const OUT_QUEUE: usize = 256;

pub type Outbox = mpsc::Sender<(SocketAddr, Vec<u8>)>;

#[derive(Serialize, Deserialize)]
enum UdpMsg {
    Ping,
    Pong,
    Voice(Box<WireMsg>),
}

pub struct UdpPath {
    pub id: [u8; 8],
    key: Locked<32>,
    /// Where the other end is. Member side: the host's address from the invite.
    /// Host side: learned from the member's authenticated pings.
    pub remote: Option<SocketAddr>,
    pub last_rx: Option<Instant>,
    last_ping: Option<Instant>,
    out: Outbox,
}

impl UdpPath {
    pub fn new(handshake_hash: &[u8], remote: Option<SocketAddr>, out: Outbox) -> Self {
        let key = Locked::from_bytes(&blake3::derive_key("commx udp key v1", handshake_hash));
        let id_full = blake3::derive_key("commx udp id v1", handshake_hash);
        Self {
            id: id_full[..8].try_into().unwrap(),
            key,
            remote,
            last_rx: None,
            last_ping: None,
            out,
        }
    }

    pub fn fresh(&self) -> bool {
        self.remote.is_some() && self.last_rx.is_some_and(|t| t.elapsed() < FRESH)
    }

    fn seal(&self, msg: &UdpMsg) -> Option<Vec<u8>> {
        let plain = zeroize::Zeroizing::new(postcard::to_allocvec(msg).ok()?);
        let (nonce, ct) = aead_encrypt(self.key.bytes(), &plain, &self.id).ok()?;
        let mut d = Vec::with_capacity(8 + 24 + ct.len());
        d.extend_from_slice(&self.id);
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

    fn open(&self, datagram: &[u8]) -> Option<UdpMsg> {
        let nonce: [u8; 24] = datagram.get(8..32)?.try_into().ok()?;
        let plain = aead_decrypt(self.key.bytes(), &nonce, &datagram[32..], &self.id).ok()?;
        postcard::from_bytes(&plain).ok()
    }
}

/// Bind the UDP socket and start the send/receive tasks. Returns the outbox
/// connections use to send.
pub fn start(shared: Shared, socket: UdpSocket) -> Outbox {
    let socket = Arc::new(socket);
    let (out, mut rx) = mpsc::channel::<(SocketAddr, Vec<u8>)>(OUT_QUEUE);
    let tx_sock = socket.clone();
    tokio::spawn(async move {
        while let Some((to, d)) = rx.recv().await {
            let _ = tx_sock.send_to(&d, to).await;
        }
    });
    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        loop {
            let Ok((n, from)) = socket.recv_from(&mut buf).await else { continue };
            if !(8 + 24 + 16..=MAX_DATAGRAM).contains(&n) {
                continue;
            }
            on_datagram(&shared, &buf[..n], from);
        }
    });
    out
}

fn on_datagram(shared: &Shared, d: &[u8], from: SocketAddr) {
    let id: [u8; 8] = d[..8].try_into().unwrap();
    let mut daemon = lock(shared);
    let Some((room_id, kind)) = daemon.udp_index.get(&id).copied() else { return };
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

    #[test]
    fn paths_derived_from_same_handshake_interoperate() {
        let (out, _rx) = mpsc::channel(4);
        let a = UdpPath::new(b"handshake-hash-1", None, out.clone());
        let b = UdpPath::new(b"handshake-hash-1", None, out.clone());
        let other = UdpPath::new(b"handshake-hash-2", None, out);
        assert_eq!(a.id, b.id);
        assert_ne!(a.id, other.id);
        let d = a.seal(&UdpMsg::Ping).unwrap();
        assert!(matches!(b.open(&d), Some(UdpMsg::Ping)));
        assert!(other.open(&d).is_none(), "foreign path can't open");
        let mut bad = d.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(b.open(&bad).is_none(), "tampered");
        // ping and pong are the same size: no amplification
        assert_eq!(a.seal(&UdpMsg::Ping).unwrap().len(), a.seal(&UdpMsg::Pong).unwrap().len());
    }
}
