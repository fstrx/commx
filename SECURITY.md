# Security

commx is unaudited by third parties. This file records the internal review and the limits we know about.

## Threat model

**In scope:**
- **Network observers.** They can't see content. With Tor they can't see who talks to whom.
- **Non-member peers.** They can't join without an invite and can't read or inject anything.
- **A malicious member.** They can't forge others' messages, can't make the host accept undecryptable data, and can't flood the room.
- **A malicious host.** The host can't forge, reorder or drop messages without members detecting it and nuking the room.
- **Someone who later gets your disk.** Saved aliases are passphrase-encrypted. Blobs are ciphertext whose keys only ever lived in RAM.
- **Someone who dumps a running process's memory.** History is sealed in RAM and freed memory is wiped.

**Out of scope:**
- **A friend who decides to leak.** Nukes are cooperative; a modified client or a screenshot keeps anything.
- **Malware running as your user while commx is open.** It can drive the daemon over the local control channel or read the screen.
- **Root or kernel compromise.**
- **The host learning room metadata.** The host sees who is in the room and when people talk. It can read messages too, as a member.
- **Size-bucket leakage.** Blob padding hides exact file sizes, not the size bucket.

## Internal audit (October 2026)

Findings from reviewing the MVP, all fixed in commit `5a48646` unless noted. Regression tests live in `crates/commxd/tests/rooms.rs`.

| id | severity | finding | fix |
|---|---|---|---|
| H1 | high | Peer send queues were unbounded and members weren't rate-limited. One member could flood the host, which fanned every message out to all members, until it ran out of memory. | Bounded queues; a peer that can't keep up is dropped. Token bucket of 5 msg/s with a burst of 20 per member. |
| H2 | high | No cap on unauthenticated connections. Anyone who could reach the port could exhaust tasks and file descriptors. | At most 32 connections in the handshake/join phase; extras are shed. |
| M1 | medium | A custom `--socket` chmodded an existing parent directory and deleted any non-socket file at the socket path. | Only missing parents are created. Only stale *sockets* are removed. |
| M2 | medium | Remote room names, aliases and message text weren't sanitized. That allowed terminal escape injection (in `commx nuke` output) and bidi/zero-width spoofing. | Control and formatting characters are replaced at the daemon's trust boundary. Names are validated. |
| M3 | medium | Duplicate display names were allowed in a room, so one member could impersonate another. | The host rejects duplicate names, case-insensitively. Fingerprints are shown on join. |
| M4 | medium | Argon2 used library defaults (19 MiB, t=2), and the parameters weren't stored in the file, so they could never be raised. | Format `CXK2`: 64 MiB, t=3, with parameters stored in an authenticated header. |
| M5 | medium | Plaintext lingered in memory: history, IPC buffers and freed heap. | Fixed in `6e2c1a8`: sealed history, zero-on-free allocator, locked keys. Checked with a memory dump. |

## Known limits

- **Invites are bearer tokens.** They're single use and last 10 minutes, but anyone who intercepts one first can join. Check the fingerprints shown on join.
- **No reconnect.** A real disconnect is a drop, by design.
- **Windows is compile-checked here and tested in CI,** but hasn't had hands-on testing yet.
- **Tor mode stores tor's consensus/guard cache** in `<data-dir>/tor`. That reveals commx used Tor, but nothing about rooms.
- **Exported files (`/save`) are plaintext** and outside commx's control.
