//! Connection tasks: inbound joins (host side) and outbound joins (member side).

use anyhow::{anyhow, bail, Context, Result};
use commx_core::chain::Chain;
use commx_core::crypto::{open_sealed, RoomKey};
use commx_core::identity::verify;
use commx_core::invite::Invite;
use commx_core::ipc::IpcEvent;
use commx_core::room::MemberInfo;
use commx_core::wire::{channel_binding, WireMsg};
use commx_core::RoomId;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};

use crate::state::{lock, Peer, PeerKind, Role, Room, Shared};
use crate::transport::tcp::TcpTransport;
use crate::transport::{SecureReader, SecureWriter, Transport};

const JOIN_TIMEOUT: Duration = Duration::from_secs(10);

async fn writer_task(mut rx: mpsc::UnboundedReceiver<WireMsg>, mut w: SecureWriter) {
    while let Some(msg) = rx.recv().await {
        if w.send(&msg).await.is_err() {
            break;
        }
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
                Ok(msg) => lock(&shared).on_wire(room_id, kind, msg),
                Err(_) => {
                    lock(&shared).peer_gone(room_id, kind, "connection lost");
                    return;
                }
            },
        }
    }
}

/// Host side: someone dialed us with an invite.
pub async fn handle_inbound(shared: Shared, transport: Arc<TcpTransport>, stream: TcpStream) {
    let Ok(conn) = transport.respond(stream).await else { return };
    let mut reader = conn.reader;
    let Ok(Ok(WireMsg::JoinReq { room_id, token, member, sig })) =
        tokio::time::timeout(JOIN_TIMEOUT, reader.recv()).await
    else {
        return;
    };
    let (tx, rx) = mpsc::unbounded_channel();
    let (cancel_tx, cancel_rx) = oneshot::channel();
    let sign_pk = member.id.sign_pk;
    let peer = Peer::new(tx.clone(), cancel_tx);
    let res = lock(&shared).admit(room_id, token, member, &sig, &conn.handshake_hash, peer);
    if let Err(reason) = &res {
        let _ = tx.send(WireMsg::JoinDenied { reason: reason.clone() });
    }
    drop(tx);
    tokio::spawn(writer_task(rx, conn.writer));
    if res.is_ok() {
        reader_loop(shared, reader, cancel_rx, room_id, PeerKind::Member(sign_pk)).await;
    }
}

/// Member side: dial a host from an invite code and join its room.
pub async fn join(shared: Shared, transport: Arc<TcpTransport>, code: &str) -> Result<RoomId> {
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

    let (tx, rx) = mpsc::unbounded_channel();
    let (cancel_tx, cancel_rx) = oneshot::channel();
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
            lines: Vec::new(),
            role: Role::Member { host: Peer::new(tx, cancel_tx) },
            last_hb: Instant::now(),
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
    tokio::spawn(writer_task(rx, writer));
    tokio::spawn(reader_loop(shared, reader, cancel_rx, invite.room_id, PeerKind::Host));
    Ok(invite.room_id)
}
