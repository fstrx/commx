//! Rooms handed over from IP to a radio link (SPEC §18, text only).
//!
//! The room is joined over IP as usual. When the host runs `/radio`, it
//! sends a signed `RadioGo` naming its chain head, drops its IP peers and
//! continues on the radio; members check the head, switch over, and from
//! then on ignore their IP connection. One radio room per node at a time,
//! so the node's airtime budget is that room's.

use anyhow::{anyhow, bail, Result};
use commx_core::identity::verify;
use commx_core::ipc::{ChatLine, IpcEvent};
use commx_core::secmem::Locked;
use commx_core::text::clean;
use commx_core::wire::{radio_go_bytes, WireMsg};
use commx_core::{room_id_hex, RoomId};
use commx_radio::link::{self, LinkSpec};
use commx_radio::packet::unix_hour;
use commx_radio::{Event, LoRa, Member, Radio, Setup, MAX_TEXT};
use tokio::sync::mpsc;

use crate::state::{lock, Daemon, Role, Shared};
use crate::supervise::contain;

/// `--radio` settings.
#[derive(Clone, Debug)]
pub struct RadioOpts {
    /// Link spec, e.g. `rnode:/dev/ttyACM0,freq=869525000` or `udp:...`.
    pub link: String,
    /// Share of airtime this node may use, in percent (EU 868 MHz: 1).
    pub budget_pct: f64,
    /// Kill-switch grace window once a room is on radio.
    pub grace_secs: u64,
}

pub struct RadioHw {
    tx: mpsc::Sender<Vec<u8>>,
    lora: LoRa,
    budget: f64,
    grace_secs: u64,
}

/// Shortest grace window a radio room accepts. Real links want minutes;
/// tests use seconds.
pub const MIN_RADIO_GRACE: u64 = 4;

pub fn unix_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// Open the link and start listening. Returns a label for the startup log.
pub async fn start(shared: Shared, opts: &RadioOpts) -> Result<String> {
    let spec = LinkSpec::parse(&opts.link)?;
    if !(opts.budget_pct > 0.0 && opts.budget_pct <= 100.0) {
        bail!("--radio-budget must be in (0, 100] percent");
    }
    let mut l = link::open(&spec).await?;
    let lora = spec.lora();
    lock(&shared).radio = Some(RadioHw {
        tx: l.tx,
        lora,
        budget: opts.budget_pct / 100.0,
        grace_secs: opts.grace_secs.max(MIN_RADIO_GRACE),
    });
    tokio::spawn(async move {
        while let Some(pkt) = l.rx.recv().await {
            lock(&shared).on_radio_packet(&pkt);
        }
        eprintln!("commxd: radio link closed");
    });
    let what = match &spec {
        LinkSpec::Rnode { path, freq_hz, .. } => format!("RNode {path} at {:.3} MHz", *freq_hz as f64 / 1e6),
        LinkSpec::Udp { bind, .. } => format!("simulated radio on udp {bind}"),
    };
    Ok(format!("{what}, SF{} {} kHz, airtime budget {}%", lora.sf, lora.bw_hz / 1000, opts.budget_pct))
}

impl Daemon {
    /// Host: move a room onto the radio. Members follow on `RadioGo`.
    pub fn radio_handover(&mut self, room_id: &RoomId) -> Result<()> {
        let hw = self.radio.as_ref().ok_or_else(|| anyhow!("this node has no radio (start commxd with --radio)"))?;
        let grace = hw.grace_secs;
        if self.rooms.values().any(|r| r.radio.is_some()) {
            bail!("a room is already on the radio (one at a time)");
        }
        let room = self.rooms.get(room_id).ok_or_else(|| anyhow!("no such room"))?;
        if !room.is_host() {
            bail!("only the host can move the room to radio");
        }
        if room.members.len() > 255 {
            bail!("radio rooms hold at most 255 members");
        }
        let head = room.chain.head;
        let hour = unix_hour(unix_ms());
        let sig = room.me.sign(&radio_go_bytes(room_id, &head, grace, hour));
        room.send_all(&WireMsg::RadioGo { room_id: *room_id, head, grace_secs: grace, hour, sig });
        self.enter_radio(room_id, grace, hour)
    }

    /// Member: the host says the room continues on radio.
    pub fn radio_go(&mut self, room_id: &RoomId, head: [u8; 32], grace: u64, hour: u32, sig: &[u8]) {
        let Some(room) = self.rooms.get(room_id) else { return };
        if room.is_host() || room.radio.is_some() {
            return;
        }
        if !verify(&room.chain.host_pk, &radio_go_bytes(room_id, &head, grace, hour), sig) {
            return;
        }
        let ours = unix_hour(unix_ms());
        let problem = if head != room.chain.head {
            Some("the host's chain doesn't match ours at the radio handover".to_string())
        } else if self.radio.is_none() {
            Some("the host moved the room to radio, and this node has no radio (--radio)".to_string())
        } else if self.rooms.values().any(|r| r.radio.is_some()) {
            Some("the host moved the room to radio, but this node's radio is busy with another room".to_string())
        } else if ours.abs_diff(hour) > 1 {
            // Radio keys change every hour; more skew than that and we'd
            // never hear each other.
            Some("the host moved the room to radio, but our clocks differ by over an hour".to_string())
        } else {
            self.enter_radio(room_id, grace.max(MIN_RADIO_GRACE), hour)
                .err()
                .map(|e| format!("couldn't move to radio: {e}"))
        };
        if let Some(reason) = problem {
            self.nuke(room_id, &reason, true);
        }
    }

    fn enter_radio(&mut self, room_id: &RoomId, grace: u64, hour: u32) -> Result<()> {
        let hw = self.radio.as_ref().ok_or_else(|| anyhow!("no radio"))?;
        let (lora, budget) = (hw.lora, hw.budget);
        let ev = self.events.clone();
        let room = self.rooms.get_mut(room_id).ok_or_else(|| anyhow!("no such room"))?;
        let key = room.keys.get(&room.epoch).ok_or_else(|| anyhow!("no room key"))?;
        let setup = Setup {
            room_id: *room_id,
            me: room.me.clone(),
            members: room.members.iter().map(|m| Member { name: m.name.clone(), id: m.id }).collect(),
            room_key: Locked::from_bytes(key.as_bytes()),
            epoch: room.epoch,
            start_hour: hour,
            ip_head: room.chain.head,
            kill_mode: room.cfg.kill_mode,
            grace_ms: grace * 1000,
            lora,
            budget,
        };
        let radio = Radio::new(setup, unix_ms())?;
        // The radio ratchets its own keys from here; holding the IP room key
        // would undo that forward secrecy, so it goes now.
        room.keys.clear();
        room.pw_invite = None;
        // Radio carries text only: calls and files end here.
        let had_call = room.call.take().is_some();
        room.files.clear();
        if let Role::Host { peers } = &mut room.role {
            peers.clear();
        }
        room.cfg.grace_secs = grace;
        room.radio = Some(radio);
        room.system(
            &ev,
            format!("📻 room moved to radio · text only, up to {MAX_TEXT} bytes a message · grace {grace}s"),
        );
        if had_call {
            ev.send(IpcEvent::Call { room_id: room_id_hex(room_id), call: None });
        }
        ev.send(IpcEvent::Room { room: room.summary() });
        Ok(())
    }

    fn radio_rooms(&self) -> Vec<RoomId> {
        self.rooms.iter().filter(|(_, r)| r.radio.is_some()).map(|(id, _)| *id).collect()
    }

    /// A packet came in over the air. Each room is its own fault domain.
    pub fn on_radio_packet(&mut self, pkt: &[u8]) {
        let now = unix_ms();
        for id in self.radio_rooms() {
            let Some(r) = self.rooms.get_mut(&id).and_then(|r| r.radio.as_mut()) else { continue };
            if contain(|| r.on_packet(pkt, now)).is_err() {
                self.contained_fault(&id);
                continue;
            }
            self.pump_radio(&id);
        }
    }

    /// Once a second, from the kill-switch ticker.
    pub fn radio_tick(&mut self) {
        let now = unix_ms();
        for id in self.radio_rooms() {
            let Some(r) = self.rooms.get_mut(&id).and_then(|r| r.radio.as_mut()) else { continue };
            if contain(|| r.tick(now)).is_err() {
                self.contained_fault(&id);
                continue;
            }
            self.pump_radio(&id);
        }
    }

    /// Put due packets on the air and turn radio events into room lines.
    fn pump_radio(&mut self, id: &RoomId) {
        let now = unix_ms();
        let tx = self.radio.as_ref().map(|h| h.tx.clone());
        let ev = self.events.clone();
        let Some(room) = self.rooms.get_mut(id) else { return };
        let Some(r) = room.radio.as_mut() else { return };
        let mut pkts = Vec::new();
        while let Some(p) = r.poll_transmit(now) {
            pkts.push(p);
        }
        let mut events = Vec::new();
        while let Some(e) = r.poll_event() {
            events.push(e);
        }
        if let Some(tx) = &tx {
            for p in pkts {
                // A full queue is a lost packet; radio is built for those.
                let _ = tx.try_send(p);
            }
        }
        let mut dead = None;
        for e in events {
            match e {
                Event::Msg { from, mine, text } => {
                    let line = ChatLine { from, text: clean(&text), ts_min: commx_core::now_minute(), mine, system: false };
                    room.push(&ev, line);
                }
                Event::Unconfirmed { from, mine } => {
                    let line = if mine {
                        "⚠ the host hasn't sequenced your message yet; it may not have heard it".to_string()
                    } else {
                        format!("⚠ the host hasn't sequenced a message from {from}")
                    };
                    room.system(&ev, line);
                }
                Event::MemberGone { name, id: who, why } => {
                    room.members.retain(|m| m.id != who);
                    room.system(&ev, format!("{name} dropped ({why})"));
                    ev.send(IpcEvent::Room { room: room.summary() });
                }
                Event::Rekeyed { epoch } => room.system(&ev, format!("room key rotated (epoch {epoch})")),
                Event::Nuked { reason } => dead = Some(reason),
            }
        }
        if let Some(reason) = dead {
            self.nuke(id, &reason, false);
        }
    }

    /// Room is being destroyed: the host's `NUKE` goes out over the air.
    pub fn radio_farewell(&self, radio: &mut Radio, reason: &str, tell: bool) {
        let now = unix_ms();
        if tell {
            radio.shutdown(reason, now);
        }
        if let Some(hw) = &self.radio {
            while let Some(p) = radio.poll_transmit(now) {
                let _ = hw.tx.try_send(p);
            }
        }
    }
}
