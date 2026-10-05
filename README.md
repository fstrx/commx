# commx

commx is a peer-to-peer chat for small groups of friends. Messages are end-to-end encrypted and live only in memory. There are no servers, no accounts and no phone numbers, only aliases. Rooms self-destruct when nodes drop.

```
 commx (TUI) ──unix socket── commxd ──TCP + Noise_XX── other commxd nodes
```

- **`commxd`**: the node. It runs in the background, holds keys and rooms in RAM, and talks to peers.
- **`commx`**: the terminal client. It talks only to your local `commxd`.

## Quick start

```sh
cargo install --path crates/commxd
cargo install --path crates/commx

commxd &            # or install the launchd / systemd unit from dist/
commx
```

Inside the TUI:

```
/alias new ghost --ephemeral          # RAM-only identity (or drop --ephemeral to save it, passphrase-encrypted)
/room new lounge --any-member         # host a room; prints a single-use invite code
```

Send the `cx1:...` code to a friend over a channel you trust. They run `/join cx1:...`. Each side shows a fingerprint for the other (`[abcd-efgh-...]`). Compare fingerprints out-of-band once.

Panic button from any shell: `commx nuke`.

### Reaching each other

The MVP uses direct TCP on port 4700. Friends must be able to reach the host's address in one of these ways:

- the same LAN;
- a VPN/mesh like Tailscale or WireGuard (run `commxd --advertise 100.x.y.z:4700`);
- a port forward.

Tor onion services are the next milestone. They solve NAT traversal and hide IPs.

## Kill switch

Each room picks its kill mode at creation. All members enforce the mode the host chose.

| mode | host drops | a member drops |
|---|---|---|
| `host-only` (default) | room nuked everywhere | member removed, room key rotated |
| `any-member` (`--any-member`, all DMs) | room nuked everywhere | room nuked everywhere |

- **Disconnects:** a closed connection counts as a drop immediately.
- **Silence:** a peer that goes quiet (frozen, network gone, laptop asleep) counts as dropped after `--grace N` seconds (default 15). Heartbeats run every ≤5s.
- **Cascade:** a node going down takes out every room it was in, each according to that room's mode.
- **Stopping the daemon:** stopping `commxd` with Ctrl-C or SIGTERM nukes all its rooms and notifies peers.
- **What a nuke does:** it zeroizes the room key and the chain head, wipes message plaintext from memory, drops connections and deletes pending invites. Nothing was ever written to disk, so nothing on disk needs wiping.

### Sleep

A sleeping machine can't keep connections alive.

- **Keeping the machine awake:** while any room is live, `commxd` holds a sleep inhibitor: `caffeinate -i -s` on macOS, `systemd-inhibit` on Linux. Disable this with `--no-keep-awake`.
- **Lid close:** closing a laptop lid still sleeps it. The status bar warns you when you're on battery.
- **Waking up:** on wake, `commxd` detects that it slept past the grace window and wipes the affected rooms itself. Peers will already have nuked them.
- **Long-lived rooms:** host the room on an always-on box like a Pi, VPS or home server.

## Crypto

| piece | what |
|---|---|
| alias | Ed25519 (signing) + X25519 (key agreement). Each alias has its own keys, so aliases are unlinkable. |
| transport | Noise `XX_25519_ChaChaPoly_BLAKE2s`, with a fresh node key every daemon run. Aliases prove identity by signing the Noise handshake hash (channel binding). |
| room messages | XChaCha20-Poly1305 under a random room key. The host seals the key to each member's X25519 key and rotates it when someone is removed. |
| "blockchain" | Per-room hash chain. Every block is signed by its author **and** the host, and links `blake3(prev)`. Members reject gaps, reorders, forgeries and splices, and they nuke the room if verification fails. There's no mining and no global ledger. The chain lives only in RAM. |
| saved aliases | Argon2id(passphrase) → XChaCha20-Poly1305, stored as randomly named files in a 0700 directory. |
| metadata | Timestamps are coarsened to the minute. Core dumps are disabled. The control socket is 0600 and checks the peer UID. |

## Honest limits

- **A nuke is cooperative.** A modified client, a screenshot or a camera can keep anything you send. commx protects against outsiders and careless leftovers. It doesn't protect against a friend who decides to betray you.
- **Peers see your IP** until Tor transport lands.
- **The host sees room metadata:** who's in the room and when they talk. The host can read messages too, because the host is a room member.
- **There's no reconnect.** A real disconnect is a drop by design.
- **Memory isn't locked.** It isn't `mlock`ed yet, so swap could hold key material. Use encrypted swap (default on macOS).
- **No audit.** The code hasn't been audited. It's an MVP.

## Layout

```
crates/commx-core   identities, crypto, hash chain, wire + IPC formats (no IO)
crates/commxd       daemon: transport, rooms, kill switch, power, IPC server
crates/commx        ratatui TUI
dist/               launchd + systemd units
```

## Tests

```sh
cargo test --workspace
```

The integration tests in `crates/commxd/tests/rooms.rs` spawn real daemons on localhost. They kill nodes with SIGKILL, and freeze nodes with SIGSTOP to exercise the silent-timeout path.

## Roadmap

1. Tor onion-service transport (per alias), implementing the existing `Transport` trait.
2. File sharing:
   - files are chunked, encrypted with the room key and stored as randomly named, size-padded blobs;
   - keys are kept only in RAM, so a nuke crypto-shreds the blobs and unlinks them.
3. Reconnect within the grace window, plus catch-up of missed blocks.
4. `mlock` for key material, and memory hygiene for TUI buffers.
