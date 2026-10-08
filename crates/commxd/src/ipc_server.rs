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
use crate::supervise::io_backoff;
use crate::net;
use crate::state::{lock, Shared};
use crate::transport::Net;

const MAX_LINE: usize = 64 * 1024;

/// Where control clients come from. Shared so a supervised restart of the
/// accept loop picks up the same source.
#[derive(Clone)]
pub enum ControlSource {
    Listener(Arc<tokio::sync::Mutex<Listener>>),
    InProcess(Arc<tokio::sync::Mutex<tokio::sync::mpsc::UnboundedReceiver<(Reader, Writer)>>>),
}

/// Accept loop for control clients.
pub async fn serve(shared: Shared, transport: Arc<Net>, source: ControlSource) {
    match source {
        ControlSource::Listener(listener) => {
            let mut listener = listener.lock().await;
            loop {
                // Listener only yields same-user clients.
                let (r, w) = match listener.accept().await {
                    Ok(x) => x,
                    Err(_) => {
                        io_backoff().await;
                        continue;
                    }
                };
                tokio::spawn(client(shared.clone(), transport.clone(), r, w));
            }
        }
        ControlSource::InProcess(rx) => {
            let mut rx = rx.lock().await;
            // Ends when the embedding app drops its sender (it's shutting down).
            while let Some((r, w)) = rx.recv().await {
                tokio::spawn(client(shared.clone(), transport.clone(), r, w));
            }
            std::future::pending::<()>().await
        }
    }
}

/// The room a request operates on, if any: the fault domain to sacrifice if
/// handling it panics.
fn request_room(req: &IpcRequest) -> Option<RoomId> {
    use IpcRequest::*;
    let id = match req {
        Invite { room_id }
        | Send { room_id, .. }
        | History { room_id }
        | Nuke { room_id: Some(room_id) }
        | SendFile { room_id, .. }
        | Files { room_id }
        | SaveFile { room_id, .. }
        | Call { room_id }
        | Hangup { room_id }
        | VoiceOut { room_id, .. } => room_id,
        _ => return None,
    };
    parse_room_id(id)
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
            Ok(req) => {
                // Fault boundary: each request runs in its own task, so a
                // panic is an error reply, not a dead daemon.
                let room = request_room(&req);
                let (s, t, x) = (shared.clone(), transport.clone(), tx.clone());
                match tokio::spawn(async move { handle(&s, &t, req, &x).await }).await {
                    Ok(r) => r,
                    Err(_) => {
                        if let Some(id) = room {
                            lock(&shared).contained_fault(&id);
                        }
                        Err(anyhow!("internal error (contained)"))
                    }
                }
            }
            Err(e) => Err(anyhow!("bad request: {e}")),
        };
        if let Err(e) = reply {
            let _ = tx.send(IpcEvent::Error { msg: e.to_string() });
        }
    }
    writer.abort();
}

/// Where `/save` writes. A directory gets the (already sanitized) peer file
/// name joined on, re-checked here so that, independently of the receive-side
/// sanitizing, nothing can land outside the directory the user chose.
fn save_path(dest: &std::path::Path, name: &str) -> Result<std::path::PathBuf> {
    use std::path::Component;
    if !dest.is_dir() {
        // An explicit file path typed by the local user.
        return Ok(dest.to_path_buf());
    }
    let mut comps = std::path::Path::new(name).components();
    if !matches!((comps.next(), comps.next()), (Some(Component::Normal(_)), None)) {
        return Err(anyhow!("refusing unsafe file name"));
    }
    let out = dest.join(name);
    if out.parent() != Some(dest) {
        return Err(anyhow!("refusing to write outside {}", dest.display()));
    }
    Ok(out)
}

/// `http://<room addr>/#<invite>`: the invite rides in the fragment, which
/// browsers never send to any server.
fn web_link(d: &crate::state::Daemon, id: &RoomId, code: &str) -> Option<String> {
    let room = d.rooms.get(id)?;
    d.web.then(|| format!("http://{}/#{code}", room.addr))
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
            let web_link = web_link(&d, &id, &code);
            let _ = tx.send(IpcEvent::InviteCode { room_id: room_id_hex(&id), name, code, web_link });
        }
        IpcRequest::Invite { room_id } => {
            let id = room_arg(&room_id)?;
            let mut d = lock(shared);
            let code = d.make_invite(&id)?;
            let name = d.rooms[&id].cfg.name.clone();
            let web_link = web_link(&d, &id, &code);
            let _ = tx.send(IpcEvent::InviteCode { room_id, name, code, web_link });
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
                if let Err(e) = net::send_file(shared, id, path, None).await {
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
            let dest = save_path(std::path::Path::new(&dest), &name)?;
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
        #[cfg(debug_assertions)]
        IpcRequest::DebugSendFileAs { room_id, path, name } => {
            let id = room_arg(&room_id)?;
            net::send_file(shared.clone(), id, std::path::PathBuf::from(path), Some(name)).await?;
            ok(tx, "sent");
        }
        #[cfg(debug_assertions)]
        IpcRequest::DebugFault { scope, room_id } => {
            let mut d = lock(shared);
            match (scope.as_str(), room_id.as_deref().and_then(parse_room_id)) {
                ("ipc", _) => panic!("injected fault: ipc handler"),
                ("tick-task", _) => d.fault = Some(scope),
                (s @ ("wire" | "tick"), Some(id)) => {
                    let room = d.rooms.get_mut(&id).ok_or_else(|| anyhow!("no such room"))?;
                    room.fault_armed = Some(if s == "wire" { "wire" } else { "tick" });
                }
                _ => return Err(anyhow!("unknown fault scope")),
            }
            ok(tx, "fault armed");
        }
        IpcRequest::Nuke { room_id: None } => {
            lock(shared).nuke_all("nuked by you");
            ok(tx, "everything nuked");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_path_never_leaves_the_chosen_directory() {
        let dir = std::env::temp_dir();
        assert_eq!(save_path(&dir, "report.pdf").unwrap(), dir.join("report.pdf"));
        for evil in ["../x", "a/b", "/etc/passwd", "..", ".", ""] {
            assert!(save_path(&dir, evil).is_err(), "{evil:?} accepted");
        }
        // An explicit file path is the user's own choice.
        let f = dir.join("definitely-not-a-dir.bin");
        assert_eq!(save_path(&f, "../ignored").unwrap(), f);
    }
}
