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
    Join(String),
    Nuke { all: bool },
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
    "/join <cx1:...>                   join from an invite code",
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
        ("/invite", _) => Ok(Command::Invite),
        ("/join", [code]) => Ok(Command::Join(code.to_string())),
        ("/join", _) => usage("/join <cx1:...>"),
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
        assert!(parse("/room new").is_err());
        assert!(parse("/grace --x").is_err());
    }
}
