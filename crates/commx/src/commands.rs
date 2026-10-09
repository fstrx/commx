//! Slash-command parsing for the input line.

use commx_core::room::{KillMode, DEFAULT_GRACE_SECS};

#[derive(Debug, PartialEq)]
pub enum Command {
    Help,
    AliasNew { name: String, ephemeral: bool },
    AliasUse(String),
    AliasList,
    Unlock,
    RoomNew { name: String, kill_mode: KillMode, grace_secs: u64 },
    Dm(String),
    Invite,
    InvitePassword,
    InviteRevoke,
    Join(String),
    Nuke { all: bool },
    SendFile(String),
    Files,
    Save { no: u32, dest: Option<String> },
    Call,
    Hangup,
    Mute,
    Ptt,
    EchoTest,
    Devices,
    Mic(String),
    Speaker(String),
    Status,
    Quit,
    Say(String),
}

pub const HELP: &[&str] = &[
    "/alias new <name> [--ephemeral]   new alias (persistent ones ask for a passphrase)",
    "/alias use <name>                 switch active alias",
    "/alias list                       list loaded aliases",
    "/unlock                           load saved aliases (asks for passphrase)",
    "/room new <name> [--any-member] [--grace N]",
    "                                  host a room; default kill switch: host-only, 15s",
    "/dm <label>                       host a 2-person DM (any drop nukes it)",
    "/invite                           fresh single-use invite for this room (host only)",
    "/invite pw                        reusable invite that needs a password (asks; lasts the room)",
    "/invite revoke                    kill the reusable invite",
    "/join <cx1:...|cx2:...>           join from an invite code (cx2 asks for its password)",
    "/send <path>                      share a file with this room (max 256 MiB)",
    "/files                            list this room's files",
    "/save <n> [path]                  export file #n decrypted (default: Downloads)",
    "/call                             start or join this room's voice call",
    "/hangup   /mute                   leave the call / toggle your microphone",
    "/ptt                              push-to-talk: hold Space (empty input) to talk",
    "/echotest                         hear yourself through the full codec path (solo test)",
    "/devices  /mic <n>  /speaker <n>  list / pick audio devices (\"default\" resets)",
    "/nuke                             destroy this room (host: for everyone)",
    "/nuke all                         destroy everything, now",
    "/status   /help   /quit",
    "Tab / Shift-Tab switch rooms · PgUp/PgDn scroll · Ctrl-C quit",
];

pub fn parse(input: &str) -> Result<Command, String> {
    let input = input.trim();
    if !input.starts_with('/') {
        return Ok(Command::Say(input.to_string()));
    }
    let mut words = input.split_whitespace();
    let cmd = words.next().unwrap_or_default();
    let rest: Vec<&str> = words.collect();
    let usage = |u: &str| Err(format!("usage: {u}"));
    match (cmd, rest.as_slice()) {
        ("/help" | "/h", _) => Ok(Command::Help),
        ("/quit" | "/q" | "/exit", _) => Ok(Command::Quit),
        ("/status" | "/fp", _) => Ok(Command::Status),
        ("/unlock", _) => Ok(Command::Unlock),
        ("/aliases", _) | ("/alias", ["list"]) => Ok(Command::AliasList),
        ("/alias", ["use", name]) => Ok(Command::AliasUse(name.to_string())),
        ("/alias", ["new", name, flags @ ..]) => {
            let ephemeral = flags.iter().any(|f| *f == "--ephemeral" || *f == "-e");
            Ok(Command::AliasNew { name: name.to_string(), ephemeral })
        }
        ("/alias", _) => usage("/alias new <name> [--ephemeral] | use <name> | list"),
        ("/room", ["new", args @ ..]) => {
            let mut name = Vec::new();
            let mut kill_mode = KillMode::HostOnly;
            let mut grace_secs = DEFAULT_GRACE_SECS;
            let mut it = args.iter();
            while let Some(a) = it.next() {
                match *a {
                    "--any-member" | "--any" => kill_mode = KillMode::AnyMember,
                    "--host-only" => kill_mode = KillMode::HostOnly,
                    "--grace" => {
                        grace_secs = it
                            .next()
                            .and_then(|g| g.parse().ok())
                            .ok_or("--grace needs a number of seconds")?;
                    }
                    w => name.push(w),
                }
            }
            if name.is_empty() {
                return usage("/room new <name> [--any-member] [--grace N]");
            }
            Ok(Command::RoomNew { name: name.join(" "), kill_mode, grace_secs })
        }
        ("/room", _) => usage("/room new <name> [--any-member] [--grace N]"),
        ("/dm", label) if !label.is_empty() => Ok(Command::Dm(label.join(" "))),
        ("/dm", _) => usage("/dm <label>"),
        ("/invite", []) => Ok(Command::Invite),
        ("/invite", ["pw" | "password"]) => Ok(Command::InvitePassword),
        ("/invite", ["revoke"]) => Ok(Command::InviteRevoke),
        ("/invite", _) => usage("/invite [pw|revoke]"),
        ("/join", [code]) => Ok(Command::Join(code.to_string())),
        ("/join", _) => usage("/join <cx1:...|cx2:...>"),
        ("/send", path) if !path.is_empty() => Ok(Command::SendFile(path.join(" "))),
        ("/send", _) => usage("/send <path>"),
        ("/files", _) => Ok(Command::Files),
        ("/save", [no, dest @ ..]) => {
            let no = no.trim_start_matches('#').parse().map_err(|_| "file number expected".to_string())?;
            Ok(Command::Save { no, dest: (!dest.is_empty()).then(|| dest.join(" ")) })
        }
        ("/save", _) => usage("/save <n> [path]"),
        ("/call" | "/vc", _) => Ok(Command::Call),
        ("/hangup" | "/leave", _) => Ok(Command::Hangup),
        ("/mute" | "/unmute", _) => Ok(Command::Mute),
        ("/ptt", _) => Ok(Command::Ptt),
        ("/echotest" | "/echo", _) => Ok(Command::EchoTest),
        ("/devices", _) => Ok(Command::Devices),
        ("/mic", arg) if !arg.is_empty() => Ok(Command::Mic(arg.join(" "))),
        ("/speaker", arg) if !arg.is_empty() => Ok(Command::Speaker(arg.join(" "))),
        ("/mic" | "/speaker", _) => usage("/mic <n|name|default>  (see /devices)"),
        ("/nuke", []) => Ok(Command::Nuke { all: false }),
        ("/nuke", ["all"]) => Ok(Command::Nuke { all: true }),
        ("/nuke", _) => usage("/nuke [all]"),
        _ => Err(format!("unknown command {cmd} (try /help)")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses() {
        assert_eq!(parse("hello").unwrap(), Command::Say("hello".into()));
        assert_eq!(
            parse("/room new war room --any-member --grace 30").unwrap(),
            Command::RoomNew { name: "war room".into(), kill_mode: KillMode::AnyMember, grace_secs: 30 }
        );
        assert_eq!(
            parse("/alias new ghost -e").unwrap(),
            Command::AliasNew { name: "ghost".into(), ephemeral: true }
        );
        assert_eq!(parse("/nuke all").unwrap(), Command::Nuke { all: true });
        assert_eq!(parse("/send ~/My Docs/a.pdf").unwrap(), Command::SendFile("~/My Docs/a.pdf".into()));
        assert_eq!(parse("/save #3").unwrap(), Command::Save { no: 3, dest: None });
        assert_eq!(parse("/mic MacBook Pro Microphone").unwrap(), Command::Mic("MacBook Pro Microphone".into()));
        assert!(parse("/speaker").is_err());
        assert_eq!(parse("/save 2 /tmp/x").unwrap(), Command::Save { no: 2, dest: Some("/tmp/x".into()) });
        assert!(parse("/room new").is_err());
        assert!(parse("/grace --x").is_err());
    }
}
