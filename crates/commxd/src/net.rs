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
use commx_core::text::clean;
use commx_core::RoomId;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, OwnedSemaphorePermit};

use crate::files::hash_file;
use crate::state::{lock, Followup, Peer, PeerKind, Role, Room, Shared, BULK_QUEUE, MAX_LINES, PEER_QUEUE};
use commx_core::secmem::SealedLog;
use crate::transport::{Net, SecureReader, SecureWriter};

const JOIN_TIMEOUT: Duration = Duration::from_secs(10);

/// Control frames always go first; file chunks fill the gaps.
async fn writer_task(mut ctl: mpsc::Receiver<WireMsg>, mut bulk: mpsc::Receiver<WireMsg>, mut w: SecureWriter) {
    loop {
        let msg = tokio::select! {
            biased;
            m = ctl.recv() => match m {
                Some(m) => m,
                None => break,
            },
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
                    let fu = lock(&shared).on_wire(room_id, kind, msg);
                    run_followup(&shared, room_id, kind, fu).await;
                }
                Err(_) => {
                    lock(&shared).peer_gone(room_id, kind, "connection lost");
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
    let (tx, rx) = mpsc::channel(PEER_QUEUE);
    let (bulk_tx, bulk_rx) = mpsc::channel(BULK_QUEUE);
    let (cancel_tx, cancel_rx) = oneshot::channel();
    let sign_pk = member.id.sign_pk;
    let peer = Peer::new(tx.clone(), bulk_tx, cancel_tx);
    let res = lock(&shared).admit(room_id, token, member, &sig, &conn.handshake_hash, peer);
    if let Err(reason) = &res {
        let _ = tx.try_send(WireMsg::JoinDenied { reason: reason.clone() });
    }
    drop(tx);
    drop(permit);
    tokio::spawn(writer_task(rx, bulk_rx, conn.writer));
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

    let (tx, rx) = mpsc::channel(PEER_QUEUE);
    let (bulk_tx, bulk_rx) = mpsc::channel(BULK_QUEUE);
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
            role: Role::Member { host: Peer::new(tx, bulk_tx, cancel_tx) },
            last_hb: Instant::now(),
            addr: String::new(),
            onion: None,
            files: HashMap::new(),
            next_file_no: 0,
            data_dir: d.data_dir.clone(),
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
        d.rooms.insert(invite.room_id, room);
        d.refresh_power();
    }
    tokio::spawn(writer_task(rx, bulk_rx, writer));
    tokio::spawn(reader_loop(shared, reader, cancel_rx, invite.room_id, PeerKind::Host));
    Ok(invite.room_id)
}

/// Share a file: hash it, announce it through the chain, then stream
/// encrypted chunks on the bulk lane.
pub async fn send_file(shared: Shared, room_id: RoomId, path: std::path::PathBuf) -> Result<()> {
    let p = path.clone();
    let (size, hash) = tokio::task::spawn_blocking(move || hash_file(&p)).await??;
    if size > MAX_FILE_SIZE {
        bail!("file too large (max {})", human_size(MAX_FILE_SIZE));
    }
    let name: String = clean(&path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "file".into()))
        .chars()
        .take(128)
        .collect();
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
