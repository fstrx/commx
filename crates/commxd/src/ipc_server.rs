//! Local control socket for the TUI. Only the same unix user may connect.

use anyhow::{anyhow, Result};
use commx_core::identity::Identity;
use commx_core::ipc::{IpcEvent, IpcRequest};
use commx_core::secmem::ZLines;
use commx_core::text::valid_name;
use commx_core::{keystore, parse_room_id, room_id_hex, RoomId};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use zeroize::Zeroizing;
use commx_core::local_ipc::{Listener, Reader, Writer};
use tokio::sync::mpsc;

use crate::files::FileState;
use crate::net;
use crate::state::{lock, Shared};
use crate::transport::Net;

const MAX_LINE: usize = 64 * 1024;

pub async fn serve(shared: Shared, transport: Arc<Net>, mut listener: Listener) {
    loop {
        // Listener only yields same-user clients.
        let Ok((r, w)) = listener.accept().await else { continue };
        tokio::spawn(client(shared.clone(), transport.clone(), r, w));
    }
}

async fn client(shared: Shared, transport: Arc<Net>, r: Reader, mut w: Writer) {
    let (tx, mut rx) = mpsc::unbounded_channel::<IpcEvent>();
    let mut sub = lock(&shared).events.subscribe();

    let writer = tokio::spawn(async move {
        loop {
            let mut line = tokio::select! {
                Some(ev) = rx.recv() => Zeroizing::new(serde_json::to_vec(&ev).expect("serialize event")),
                Some(json) = sub.recv() => json,
                else => break,
            };
            line.push(b'\n');
            if w.write_all(&line).await.is_err() {
                break;
            }
        }
    });

    let mut lines = ZLines::new(r, MAX_LINE);
    loop {
        let Ok(Some(line)) = lines.next_line().await else { break };
        let reply = match serde_json::from_slice::<IpcRequest>(&line) {
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
    transport: &Arc<Net>,
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
            if !valid_name(&name, 32) || name.contains(char::is_whitespace) {
                return Err(anyhow!("alias must be 1-32 printable chars, no spaces"));
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
            let endpoint = transport.room_endpoint().await?;
            let onion = endpoint.1.clone();
            let mut d = lock(shared);
            let id = match d.create_room(&name, kill_mode, grace_secs, dm, endpoint) {
                Ok(id) => id,
                Err(e) => {
                    if let Some(o) = onion {
                        transport.release(o);
                    }
                    return Err(e);
                }
            };
            if transport.is_tor() {
                ok(tx, "onion address publishing; friends may need ~1 min before /join connects");
            }
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
            let lines = d.rooms.get(&id).ok_or_else(|| anyhow!("no such room"))?.lines.all();
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
        IpcRequest::SendFile { room_id, path } => {
            let id = room_arg(&room_id)?;
            let path = std::path::PathBuf::from(path);
            if !path.is_file() {
                return Err(anyhow!("not a file: {}", path.display()));
            }
            ok(tx, format!("sending {}…", path.display()));
            let (shared, tx) = (shared.clone(), tx.clone());
            // Big files take a while; don't block this client's other requests.
            tokio::spawn(async move {
                if let Err(e) = net::send_file(shared, id, path).await {
                    let _ = tx.send(IpcEvent::Error { msg: format!("send failed: {e}") });
                }
            });
        }
        IpcRequest::Files { room_id } => {
            let id = room_arg(&room_id)?;
            let list = lock(shared).rooms.get(&id).ok_or_else(|| anyhow!("no such room"))?.file_list();
            let _ = tx.send(IpcEvent::Files { room_id, list });
        }
        IpcRequest::SaveFile { room_id, no, dest } => {
            let id = room_arg(&room_id)?;
            let (reader, name) = {
                let d = lock(shared);
                let room = d.rooms.get(&id).ok_or_else(|| anyhow!("no such room"))?;
                let e = room.files.values().find(|e| e.no == no).ok_or_else(|| anyhow!("no file #{no}"))?;
                if !matches!(e.state, FileState::Ready) {
                    return Err(anyhow!("file #{no} isn't ready ({})", e.info().state));
                }
                (e.reader().ok_or_else(|| anyhow!("file #{no} has no local copy"))?, e.name.clone())
            };
            let mut dest = std::path::PathBuf::from(dest);
            if dest.is_dir() {
                dest = dest.join(&name);
            }
            let out = dest.clone();
            tokio::task::spawn_blocking(move || reader.export(&out)).await??;
            ok(tx, format!("saved #{no} to {} (decrypted copy — commx can't nuke it)", dest.display()));
        }
        IpcRequest::Call { room_id } => {
            let id = room_arg(&room_id)?;
            let mut d = lock(shared);
            let ev = d.events.clone();
            let room = d.rooms.get_mut(&id).ok_or_else(|| anyhow!("no such room"))?;
            match room.call_info() {
                Some(c) if c.joined => return Err(anyhow!("you're already in the call")),
                Some(_) => room.set_my_presence(&ev, true)?,
                None => room.start_call(&ev)?,
            }
        }
        IpcRequest::Hangup { room_id } => {
            let id = room_arg(&room_id)?;
            let mut d = lock(shared);
            let ev = d.events.clone();
            let room = d.rooms.get_mut(&id).ok_or_else(|| anyhow!("no such room"))?;
            room.set_my_presence(&ev, false)?;
        }
        IpcRequest::VoiceOut { room_id, opus } => {
            let id = room_arg(&room_id)?;
            let opus = Zeroizing::new(hex::decode(opus).map_err(|_| anyhow!("bad voice frame"))?);
            if let Some(room) = lock(shared).rooms.get_mut(&id) {
                room.send_voice(&opus)?;
            }
        }
        IpcRequest::Nuke { room_id: None } => {
            lock(shared).nuke_all("nuked by you");
            ok(tx, "everything nuked");
        }
    }
    Ok(())
}
