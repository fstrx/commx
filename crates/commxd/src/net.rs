//! Connection tasks: inbound joins (host side) and outbound joins (member side).

use anyhow::{anyhow, bail, Context, Result};
use commx_core::chain::{chunk_aad, Chain, FileMeta, FILE_CHUNK, MAX_FILE_SIZE};
use commx_core::crypto::aead_encrypt;
use commx_core::secmem::Locked;
use rand::{rngs::OsRng, RngCore};
use tokio::io::AsyncReadExt;
use zeroize::Zeroizing;
use crate::files::FileState;
use crate::state::human_size;
use commx_core::crypto::{open_sealed, RoomKey};
use commx_core::identity::verify;
use commx_core::invite::Invite;
use commx_core::ipc::IpcEvent;
use commx_core::room::MemberInfo;
use commx_core::wire::{channel_binding, WireMsg};
use commx_core::text::{clean, safe_file_name};
use commx_core::RoomId;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, OwnedSemaphorePermit};

use crate::files::hash_file;
use crate::supervise::contain;
use crate::udp::UdpPath;
use crate::state::{
    lock, Followup, Lanes, Peer, PeerKind, Role, Room, Shared, BULK_QUEUE, MAX_LINES, MEDIA_QUEUE, PEER_QUEUE,
};
use commx_core::secmem::SealedLog;
use crate::transport::{Net, SecureReader, SecureWriter};

const JOIN_TIMEOUT: Duration = Duration::from_secs(10);

/// Receiving halves for the writer: (control, media, bulk).
type LaneRx = (mpsc::Receiver<WireMsg>, mpsc::Receiver<WireMsg>, mpsc::Receiver<WireMsg>);

/// The three lanes of one connection: senders for the Peer, receivers for the writer.
fn lanes() -> (Lanes, LaneRx) {
    let (ctl, ctl_rx) = mpsc::channel(PEER_QUEUE);
    let (bulk, bulk_rx) = mpsc::channel(BULK_QUEUE);
    let (media, media_rx) = mpsc::channel(MEDIA_QUEUE);
    (Lanes { ctl, bulk, media }, (ctl_rx, media_rx, bulk_rx))
}

/// Control frames first, then voice, then file chunks.
async fn writer_task(
    (mut ctl, mut media, mut bulk): LaneRx,
    mut w: SecureWriter,
) {
    loop {
        let msg = tokio::select! {
            biased;
            m = ctl.recv() => match m {
                Some(m) => m,
                None => break,
            },
            Some(m) = media.recv() => m,
            Some(m) = bulk.recv() => m,
        };
        if w.send(&msg).await.is_err() {
            break;
        }
    }
}

/// Longest a relay waits on one slow receiver before skipping that chunk for
/// them, so the sender isn't starved into a heartbeat timeout.
const RELAY_WAIT: Duration = Duration::from_secs(5);

async fn run_followup(shared: &Shared, room_id: RoomId, kind: PeerKind, fu: Followup) {
    if !fu.forward.is_empty() {
        for (tx, msg) in fu.forward {
            let _ = tokio::time::timeout(RELAY_WAIT, tx.send(msg)).await;
        }
        // We were the slow part, not them.
        if let Some(room) = lock(shared).rooms.get_mut(&room_id) {
            room.touch(kind);
        }
    }
    if let Some((rid, fid, reader)) = fu.verify {
        let shared = shared.clone();
        tokio::spawn(async move {
            let res = tokio::task::spawn_blocking(move || reader.verify()).await;
            let res = res.map_err(anyhow::Error::from).and_then(|r| r);
            lock(&shared).file_verified(rid, fid, res);
        });
    }
}

async fn reader_loop(
    shared: Shared,
    mut r: SecureReader,
    mut cancel: oneshot::Receiver<()>,
    room_id: RoomId,
    kind: PeerKind,
) {
    loop {
        tokio::select! {
            // Fires when the Peer is dropped (room nuked / member removed).
            _ = &mut cancel => return,
            res = r.recv() => match res {
                Ok(msg) => {
                    // Fault boundary: whatever a peer sends, a panic while
                    // handling it costs at most this room, never the daemon.
                    let fu = {
                        let mut d = lock(&shared);
                        match contain(|| d.on_wire(room_id, kind, msg)) {
                            Ok(fu) => fu,
                            Err(()) => {
                                d.contained_fault(&room_id);
                                return;
                            }
                        }
                    };
                    run_followup(&shared, room_id, kind, fu).await;
                }
                Err(_) => {
                    let mut d = lock(&shared);
                    if contain(|| d.peer_gone(room_id, kind, "connection lost")).is_err() {
                        d.contained_fault(&room_id);
                    }
                    return;
                }
            },
        }
    }
}

/// Host side: someone dialed us with an invite.
///
/// `permit` bounds how many unauthenticated connections exist at once; it's
/// released as soon as the join is decided.
pub async fn handle_inbound(
    shared: Shared,
    transport: Arc<Net>,
    stream: TcpStream,
    permit: OwnedSemaphorePermit,
) {
    let Ok(conn) = transport.respond(stream).await else { return };
    let mut reader = conn.reader;
    let Ok(Ok(WireMsg::JoinReq { room_id, token, member, sig })) =
        tokio::time::timeout(JOIN_TIMEOUT, reader.recv()).await
    else {
        return;
    };
    let (lanes, rxs) = lanes();
    let tx = lanes.ctl.clone();
    let (cancel_tx, cancel_rx) = oneshot::channel();
    let sign_pk = member.id.sign_pk;
    let res = {
        let mut d = lock(&shared);
        let udp = d.udp_out.clone().map(|out| UdpPath::new(&conn.handshake_hash, None, out));
        let udp_id = udp.as_ref().map(|u| u.id);
        let peer = Peer::new(lanes, cancel_tx, udp);
        let res = match contain(|| d.admit(room_id, token, member, &sig, &conn.handshake_hash, peer)) {
            Ok(r) => r,
            Err(()) => {
                d.contained_fault(&room_id);
                Err("internal error".to_string())
            }
        };
        if let (Ok(()), Some(id)) = (&res, udp_id) {
            d.udp_index.insert(id, (room_id, PeerKind::Member(sign_pk)));
        }
        res
    };
    if let Err(reason) = &res {
        let _ = tx.try_send(WireMsg::JoinDenied { reason: reason.clone() });
    }
    drop(tx);
    drop(permit);
    tokio::spawn(writer_task(rxs, conn.writer));
    if res.is_ok() {
        reader_loop(shared, reader, cancel_rx, room_id, PeerKind::Member(sign_pk)).await;
    }
}

/// Member side: dial a host from an invite code and join its room.
pub async fn join(shared: Shared, transport: Arc<Net>, code: &str) -> Result<RoomId> {
    let invite = Invite::decode(code)?;
    let me = {
        let d = lock(&shared);
        if d.rooms.contains_key(&invite.room_id) {
            bail!("already in that room");
        }
        d.active_identity()?
    };
    if invite.host == me.public() {
        bail!("that's your own invite");
    }

    let conn = transport.dial(&invite.addr).await?;
    let (mut reader, mut writer) = (conn.reader, conn.writer);
    let member = MemberInfo { name: me.name.clone(), id: me.public() };
    writer
        .send(&WireMsg::JoinReq {
            room_id: invite.room_id,
            token: invite.token,
            member,
            sig: me.sign(&channel_binding(&conn.handshake_hash, "member")),
        })
        .await?;

    let reply = tokio::time::timeout(JOIN_TIMEOUT, reader.recv()).await.context("host didn't answer")??;
    let (cfg, host, host_sig, epoch, sealed_key, members, next_seq, head) = match reply {
        WireMsg::JoinOk { cfg, host, host_sig, epoch, sealed_key, members, next_seq, head } => {
            (cfg, host, host_sig, epoch, sealed_key, members, next_seq, head)
        }
        WireMsg::JoinDenied { reason } => bail!("join denied: {reason}"),
        _ => bail!("unexpected reply from host"),
    };
    // The invite pins the host's keys; the signature pins them to this channel.
    if host.id != invite.host {
        bail!("host identity doesn't match the invite");
    }
    if !verify(&host.id.sign_pk, &channel_binding(&conn.handshake_hash, "host"), &host_sig) {
        bail!("host failed identity proof");
    }
    let key = RoomKey::from_bytes(&open_sealed(&me, &sealed_key).map_err(|_| anyhow!("can't open room key"))?)?;

    // The host's UDP port is its TCP port (same advertised address). Resolve
    // only when the UDP fast path is actually on: in Tor mode the system
    // resolver must never see the address (a cleartext DNS query for a room's
    // onion would link its members' IPs to the room).
    let udp_enabled = {
        let d = lock(&shared);
        d.udp_out.is_some() && !d.net.is_tor()
    };
    let host_udp = if should_resolve_for_udp(&invite.addr, udp_enabled) {
        tokio::net::lookup_host(&invite.addr).await.ok().and_then(|mut a| a.next())
    } else {
        None
    };
    let (lanes, rxs) = lanes();
    let (cancel_tx, cancel_rx) = oneshot::channel();
    // Everything the host told us about the room is displayed; scrub it.
    let mut cfg = cfg;
    cfg.name = clean(&cfg.name);
    let members: Vec<MemberInfo> =
        members.into_iter().map(|m| MemberInfo { name: clean(&m.name), id: m.id }).collect();
    let host = MemberInfo { name: clean(&host.name), id: host.id };
    {
        let mut d = lock(&shared);
        let ev = d.events.clone();
        let mut room = Room {
            id: invite.room_id,
            chain: Chain::resume(invite.room_id, host.id.sign_pk, next_seq, head),
            cfg,
            me,
            host,
            members,
            keys: HashMap::from([(epoch, key)]),
            epoch,
            lines: SealedLog::new(MAX_LINES),
            role: Role::Member {
                host: Peer::new(
                    lanes,
                    cancel_tx,
                    d.udp_out.clone().map(|out| UdpPath::new(&conn.handshake_hash, host_udp, out)),
                ),
            },
            last_hb: Instant::now(),
            addr: String::new(),
            onion: None,
            files: HashMap::new(),
            next_file_no: 0,
            call: None,
            data_dir: d.data_dir.clone(),
            over_tor: d.net.is_tor(),
            fault_armed: None,
        };
        room.system(
            &ev,
            format!(
                "joined · host {} [{}] · kill switch: {} · grace {}s",
                room.host.name,
                room.host.id.fingerprint(),
                room.cfg.kill_mode.label(),
                room.cfg.grace_secs
            ),
        );
        d.emit(IpcEvent::Room { room: room.summary() });
        if let Role::Member { host: Peer { udp: Some(u), .. } } = &room.role {
            d.udp_index.insert(u.id, (invite.room_id, PeerKind::Host));
        }
        d.rooms.insert(invite.room_id, room);
        d.refresh_power();
    }
    tokio::spawn(writer_task(rxs, writer));
    tokio::spawn(reader_loop(shared, reader, cancel_rx, invite.room_id, PeerKind::Host));
    Ok(invite.room_id)
}

/// Share a file: hash it, announce it through the chain, then stream
/// encrypted chunks on the bulk lane.
///
/// `raw_name` (debug builds only, for tests) announces the file under an
/// unsanitized name, impersonating a malicious sender.
pub async fn send_file(
    shared: Shared,
    room_id: RoomId,
    path: std::path::PathBuf,
    raw_name: Option<String>,
) -> Result<()> {
    let p = path.clone();
    let (size, hash) = tokio::task::spawn_blocking(move || hash_file(&p)).await??;
    if size > MAX_FILE_SIZE {
        bail!("file too large (max {})", human_size(MAX_FILE_SIZE));
    }
    let mut name = safe_file_name(&path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default());
    if let (true, Some(raw)) = (cfg!(debug_assertions), raw_name) {
        name = raw;
    }
    let key = Locked::<32>::random();
    let meta = FileMeta { name, size, chunks: FileMeta::expected_chunks(size), hash, key: *key.bytes() };
    let mut file_id = [0u8; 16];
    OsRng.fill_bytes(&mut file_id);

    let targets = {
        let mut d = lock(&shared);
        let ev = d.events.clone();
        let room = d.rooms.get_mut(&room_id).ok_or_else(|| anyhow!("no such room"))?;
        room.announce_file(&ev, file_id, &meta)?
    };

    let mut f = tokio::fs::File::open(&path).await?;
    let mut buf = Zeroizing::new(vec![0u8; FILE_CHUNK]);
    let mut sent = 0u64;
    for idx in 0..meta.chunks {
        let mut n = 0;
        while n < FILE_CHUNK {
            let r = f.read(&mut buf[n..]).await?;
            if r == 0 {
                break;
            }
            n += r;
        }
        sent += n as u64;
        let (nonce, ct) = aead_encrypt(key.bytes(), &buf[..n], &chunk_aad(&file_id, idx))?;
        let msg = WireMsg::FileChunk { room_id, file_id, idx, nonce, ct };
        for t in &targets {
            let _ = t.send(msg.clone()).await;
        }
    }

    let mut d = lock(&shared);
    let ev = d.events.clone();
    if let Some(room) = d.rooms.get_mut(&room_id) {
        let changed = sent != size;
        if let Some(e) = room.files.get_mut(&file_id) {
            e.state = if changed { FileState::Failed("file changed while sending".into()) } else { FileState::Sent };
        }
        let no = room.files.get(&file_id).map(|e| e.no).unwrap_or(0);
        room.system(&ev, if changed { format!("📎 #{no} failed: file changed while sending") } else { format!("📎 #{no} sent") });
    }
    Ok(())
}

/// May `addr` be handed to the OS resolver for the UDP fast path? Never in
/// Tor mode, and never for an onion name, whatever the mode.
fn should_resolve_for_udp(addr: &str, udp_enabled: bool) -> bool {
    let host = addr.rsplit_once(':').map_or(addr, |(h, _)| h).trim_end_matches('.');
    udp_enabled && !host.to_ascii_lowercase().ends_with(".onion")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn onion_addresses_never_reach_the_system_resolver() {
        let onion = "vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion:4700";
        assert!(!should_resolve_for_udp(onion, false), "tor mode");
        assert!(!should_resolve_for_udp(onion, true), "onion name, even if udp somehow on");
        assert!(!should_resolve_for_udp("ABC.ONION.:4700", true), "case / trailing dot");
        assert!(should_resolve_for_udp("192.168.1.5:4700", true));
        assert!(!should_resolve_for_udp("192.168.1.5:4700", false), "--no-udp");
    }
}
