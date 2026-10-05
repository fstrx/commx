//! Local control socket for the TUI. Only the same unix user may connect.

use anyhow::{anyhow, Result};
use commx_core::identity::Identity;
use commx_core::ipc::{IpcEvent, IpcRequest};
use commx_core::{keystore, parse_room_id, room_id_hex, RoomId};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{broadcast, mpsc};

use crate::net;
use crate::state::{lock, Shared};
use crate::transport::tcp::TcpTransport;

const MAX_LINE: usize = 64 * 1024;

pub async fn serve(shared: Shared, transport: Arc<TcpTransport>, listener: UnixListener) {
    let uid = unsafe { libc::getuid() };
    loop {
        let Ok((stream, _)) = listener.accept().await else { continue };
        match stream.peer_cred() {
            Ok(c) if c.uid() == uid => {}
            _ => continue,
        }
        tokio::spawn(client(shared.clone(), transport.clone(), stream));
    }
}

async fn client(shared: Shared, transport: Arc<TcpTransport>, stream: UnixStream) {
    let (r, mut w) = stream.into_split();
    let (tx, mut rx) = mpsc::unbounded_channel::<IpcEvent>();
    let mut sub = lock(&shared).events.subscribe();

    let writer = tokio::spawn(async move {
        loop {
            let ev = tokio::select! {
                Some(ev) = rx.recv() => ev,
                res = sub.recv() => match res {
                    Ok(ev) => ev,
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                },
                else => break,
            };
            let mut line = serde_json::to_vec(&ev).expect("serialize event");
            line.push(b'\n');
            if w.write_all(&line).await.is_err() {
                break;
            }
        }
    });

    let mut lines = BufReader::new(r);
    let mut buf = String::new();
    loop {
        buf.clear();
        match (&mut lines).take(MAX_LINE as u64).read_line(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        let reply = match serde_json::from_str::<IpcRequest>(buf.trim()) {
            Ok(req) => handle(&shared, &transport, req, &tx).await,
            Err(e) => Err(anyhow!("bad request: {e}")),
        };
        if let Err(e) = reply {
            let _ = tx.send(IpcEvent::Error { msg: e.to_string() });
        }
    }
    writer.abort();
}

fn room_arg(s: &str) -> Result<RoomId> {
    parse_room_id(s).ok_or_else(|| anyhow!("bad room id"))
}

fn ok(tx: &mpsc::UnboundedSender<IpcEvent>, msg: impl Into<String>) {
    let _ = tx.send(IpcEvent::Ok { msg: msg.into() });
}

async fn handle(
    shared: &Shared,
    transport: &Arc<TcpTransport>,
    req: IpcRequest,
    tx: &mpsc::UnboundedSender<IpcEvent>,
) -> Result<()> {
    match req {
        IpcRequest::Status => {
            let _ = tx.send(lock(shared).status());
        }
        IpcRequest::AliasList => {
            let _ = tx.send(lock(shared).alias_list());
        }
        IpcRequest::Unlock { passphrase } => {
            let dir = lock(shared).data_dir.join("aliases");
            // Argon2 is deliberately slow; keep it off the runtime threads.
            let found = tokio::task::spawn_blocking(move || keystore::load_all(&dir, &passphrase)).await?;
            let mut d = lock(shared);
            let n = found.into_iter().map(|id| d.add_alias(id, false)).filter(|added| *added).count();
            if n == 0 {
                return Err(anyhow!("no new aliases opened with that passphrase"));
            }
            ok(tx, format!("unlocked {n} alias(es)"));
            let _ = tx.send(d.alias_list());
            let _ = tx.send(d.status());
        }
        IpcRequest::AliasNew { name, ephemeral, passphrase } => {
            let name = name.trim().to_string();
            if name.is_empty() || name.len() > 32 || name.chars().any(char::is_whitespace) {
                return Err(anyhow!("alias must be 1-32 chars, no spaces"));
            }
            if lock(shared).aliases.iter().any(|a| a.id.name == name) {
                return Err(anyhow!("alias '{name}' already loaded"));
            }
            let id = Identity::generate(&name);
            if !ephemeral {
                let pass = passphrase.filter(|p| p.len() >= 8).ok_or_else(|| anyhow!("passphrase must be 8+ chars"))?;
                let dir = lock(shared).data_dir.join("aliases");
                let secret = id.to_secret();
                tokio::task::spawn_blocking(move || keystore::save(&dir, &Identity::from_secret(&secret), &pass))
                    .await??;
            }
            let mut d = lock(shared);
            d.add_alias(id, ephemeral);
            d.active = Some(d.aliases.len() - 1);
            ok(tx, format!("alias '{name}' ready{}", if ephemeral { " (ephemeral, RAM only)" } else { "" }));
            let _ = tx.send(d.alias_list());
            let _ = tx.send(d.status());
        }
        IpcRequest::AliasUse { name } => {
            let mut d = lock(shared);
            let i = d.aliases.iter().position(|a| a.id.name == name).ok_or_else(|| anyhow!("no alias '{name}'"))?;
            d.active = Some(i);
            ok(tx, format!("now using '{name}'"));
            let _ = tx.send(d.status());
        }
        IpcRequest::RoomNew { name, kill_mode, grace_secs, dm } => {
            let mut d = lock(shared);
            let id = d.create_room(&name, kill_mode, grace_secs, dm)?;
            let code = d.make_invite(&id)?;
            let _ = tx.send(IpcEvent::InviteCode { room_id: room_id_hex(&id), name, code });
        }
        IpcRequest::Invite { room_id } => {
            let id = room_arg(&room_id)?;
            let mut d = lock(shared);
            let code = d.make_invite(&id)?;
            let name = d.rooms[&id].cfg.name.clone();
            let _ = tx.send(IpcEvent::InviteCode { room_id, name, code });
        }
        IpcRequest::Join { code } => {
            let id = net::join(shared.clone(), transport.clone(), &code).await?;
            ok(tx, format!("joined {}", &room_id_hex(&id)[..8]));
        }
        IpcRequest::Send { room_id, text } => {
            let id = room_arg(&room_id)?;
            let mut d = lock(shared);
            let ev = d.events.clone();
            d.rooms.get_mut(&id).ok_or_else(|| anyhow!("no such room"))?.send_text(&ev, &text)?;
        }
        IpcRequest::History { room_id } => {
            let id = room_arg(&room_id)?;
            let d = lock(shared);
            let lines = d.rooms.get(&id).ok_or_else(|| anyhow!("no such room"))?.lines.clone();
            let _ = tx.send(IpcEvent::History { room_id, lines });
        }
        IpcRequest::Nuke { room_id: Some(room_id) } => {
            let id = room_arg(&room_id)?;
            let mut d = lock(shared);
            if !d.rooms.contains_key(&id) {
                return Err(anyhow!("no such room"));
            }
            d.nuke(&id, "nuked by you", true);
        }
        IpcRequest::Nuke { room_id: None } => {
            lock(shared).nuke_all("nuked by you");
            ok(tx, "everything nuked");
        }
    }
    Ok(())
}
