//! The radio profile on a simulated shared channel: lossy, broadcast, with
//! optional hidden nodes, and a clock we control.

use std::sync::Arc;

use commx_core::identity::Identity;
use commx_core::room::KillMode;
use commx_core::secmem::Locked;
use commx_radio::{Event, LoRa, Member, Radio, Setup, MAX_TEXT};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

const T0: u64 = 1_800_000_000_000;
const MIN: u64 = 60_000;

struct Node {
    r: Radio,
    alive: bool,
    got: Vec<(String, String)>,
    unconfirmed: usize,
    gone: Vec<String>,
    nuked: Option<String>,
    sent: Vec<(u64, f64)>,
}

struct Air {
    nodes: Vec<Node>,
    /// hears[a][b]: b receives what a transmits.
    hears: Vec<Vec<bool>>,
    loss: f64,
    rng: StdRng,
    now: u64,
    lora: LoRa,
    /// Raw packets each node transmitted, for replay tests.
    log: Vec<(usize, Vec<u8>)>,
}

struct Opts {
    n: usize,
    loss: f64,
    kill: KillMode,
    grace: u64,
    budget: f64,
    lora: LoRa,
    seed: u64,
}

impl Default for Opts {
    fn default() -> Self {
        Opts { n: 3, loss: 0.0, kill: KillMode::HostOnly, grace: 20 * MIN, budget: 1.0, lora: LoRa::default(), seed: 7 }
    }
}

fn names(n: usize) -> Vec<String> {
    ["host", "ana", "bo", "cy", "di", "ed"].iter().take(n).map(|s| s.to_string()).collect()
}

fn setups(o: &Opts, ids: &[Arc<Identity>]) -> Vec<Setup> {
    let key = Locked::<32>::random();
    let members: Vec<Member> = ids.iter().map(|i| Member { name: i.name.clone(), id: i.public() }).collect();
    ids.iter()
        .map(|me| Setup {
            room_id: [5; 16],
            me: me.clone(),
            members: members.clone(),
            room_key: key.clone(),
            epoch: 3,
            ip_head: [9; 32],
            kill_mode: o.kill,
            grace_ms: o.grace,
            lora: o.lora,
            budget: o.budget,
        })
        .collect()
}

impl Air {
    fn new(o: Opts) -> Self {
        let ids: Vec<Arc<Identity>> = names(o.n).into_iter().map(|n| Arc::new(Identity::generate(n))).collect();
        Self::from_setups(&o, setups(&o, &ids))
    }

    fn from_setups(o: &Opts, s: Vec<Setup>) -> Self {
        let n = s.len();
        let nodes = s
            .into_iter()
            .enumerate()
            .map(|(i, s)| Node {
                r: {
                    let mut r = Radio::new(s, T0).unwrap();
                    r.reseed(o.seed * 1000 + i as u64);
                    r
                },
                alive: true,
                got: vec![],
                unconfirmed: 0,
                gone: vec![],
                nuked: None,
                sent: vec![],
            })
            .collect();
        Air {
            nodes,
            hears: vec![vec![true; n]; n],
            loss: o.loss,
            rng: StdRng::seed_from_u64(o.seed),
            now: T0,
            lora: o.lora,
            log: vec![],
        }
    }

    fn deliver(&mut self, from: usize, pkt: &[u8]) {
        for j in 0..self.nodes.len() {
            if j == from || !self.nodes[j].alive || !self.hears[from][j] {
                continue;
            }
            if self.loss > 0.0 && self.rng.gen::<f64>() < self.loss {
                continue;
            }
            self.nodes[j].r.on_packet(pkt, self.now);
        }
    }

    fn step(&mut self, dt: u64) {
        self.now += dt;
        let now = self.now;
        let mut out = vec![];
        for (i, n) in self.nodes.iter_mut().enumerate() {
            if !n.alive {
                continue;
            }
            n.r.tick(now);
            while let Some(p) = n.r.poll_transmit(now) {
                n.sent.push((now, self.lora.airtime_ms(p.len())));
                out.push((i, p));
            }
        }
        for (i, p) in &out {
            self.deliver(*i, p);
        }
        self.log.extend(out);
        for n in &mut self.nodes {
            while let Some(ev) = n.r.poll_event() {
                match ev {
                    Event::Msg { from, text, .. } => n.got.push((from, text.to_string())),
                    Event::Unconfirmed { .. } => n.unconfirmed += 1,
                    Event::MemberGone { name, .. } => n.gone.push(name),
                    Event::Rekeyed { .. } => {}
                    Event::Nuked { reason } => n.nuked = Some(reason),
                }
            }
        }
    }

    fn run(&mut self, ms: u64) {
        let end = self.now + ms;
        while self.now < end {
            self.step(500);
        }
    }

    fn say(&mut self, i: usize, text: &str) {
        self.nodes[i].r.send_text(text).unwrap();
    }

    fn texts(&self, i: usize) -> Vec<String> {
        let mut v: Vec<String> = self.nodes[i].got.iter().map(|(f, t)| format!("{f}: {t}")).collect();
        v.sort();
        v
    }

    fn assert_alive(&self) {
        for (i, n) in self.nodes.iter().enumerate() {
            assert!(n.nuked.is_none(), "node {i} died: {:?}", n.nuked);
        }
    }
}

#[test]
fn everyone_hears_and_the_host_sequences() {
    let mut air = Air::new(Opts::default());
    air.say(0, "hi from the host");
    air.say(1, "hi from ana");
    air.say(2, "hi from bo");
    air.run(2 * MIN);
    air.assert_alive();
    let want = vec!["ana: hi from ana", "bo: hi from bo", "host: hi from the host"];
    for i in 0..3 {
        assert_eq!(air.texts(i), want, "node {i}");
        assert_eq!(air.nodes[i].r.seq(), 3, "node {i} chain");
        assert_eq!(air.nodes[i].unconfirmed, 0);
    }
}

#[test]
fn lossy_air_is_repaired_not_fatal() {
    // Deterministic: the channel and every node's jitter are seeded.
    for seed in 1..=40 {
        lossy_run(seed);
    }
}

fn lossy_run(seed: u64) {
    let mut air = Air::new(Opts { n: 4, loss: 0.2, seed, ..Opts::default() });
    let mut want = vec![];
    for k in 0..12 {
        let who = k % 4;
        let text = format!("message {k}");
        air.say(who, &text);
        want.push(format!("{}: {text}", names(4)[who]));
        air.run(MIN);
    }
    air.run(25 * MIN);
    air.assert_alive();
    want.sort();
    for i in 0..4 {
        assert_eq!(air.texts(i), want, "seed {seed} node {i}");
        assert_eq!(air.nodes[i].r.seq(), 12, "seed {seed} node {i} chain {}", air.nodes[i].r.debug_state());
    }
}

#[test]
fn hidden_members_hear_each_other_through_repair() {
    let mut air = Air::new(Opts::default());
    // ana and bo are out of each other's range; both reach the host.
    air.hears[1][2] = false;
    air.hears[2][1] = false;
    air.say(1, "from ana");
    air.say(2, "from bo");
    air.run(5 * MIN);
    air.assert_alive();
    for i in 0..3 {
        assert_eq!(air.texts(i), vec!["ana: from ana", "bo: from bo"], "node {i}");
    }
}

#[test]
fn host_silence_nukes_members_after_the_grace_window() {
    let mut air = Air::new(Opts { grace: 8 * MIN, ..Opts::default() });
    air.run(MIN);
    air.nodes[0].alive = false;
    air.run(7 * MIN);
    assert!(air.nodes[1].nuked.is_none(), "inside the grace window");
    air.run(2 * MIN);
    assert_eq!(air.nodes[1].nuked.as_deref(), Some("host went silent"));
    assert_eq!(air.nodes[2].nuked.as_deref(), Some("host went silent"));
}

#[test]
fn replayed_host_packets_dont_keep_a_dead_host_alive() {
    let mut air = Air::new(Opts { grace: 8 * MIN, ..Opts::default() });
    air.run(6 * MIN);
    let host_pkts: Vec<Vec<u8>> = air.log.iter().filter(|(i, _)| *i == 0).map(|(_, p)| p.clone()).collect();
    assert!(!host_pkts.is_empty());
    air.nodes[0].alive = false;
    for _ in 0..30 {
        air.run(MIN / 2);
        for p in &host_pkts {
            air.deliver(0, p);
        }
    }
    assert_eq!(air.nodes[1].nuked.as_deref(), Some("host went silent"));
}

#[test]
fn host_only_room_drops_a_silent_member_and_rekeys() {
    let mut air = Air::new(Opts { n: 4, grace: 8 * MIN, ..Opts::default() });
    air.say(3, "before I go");
    air.run(MIN);
    air.nodes[3].alive = false;
    air.run(10 * MIN);
    air.assert_alive();
    for i in 0..3 {
        assert_eq!(air.nodes[i].gone, vec!["cy"], "node {i}");
        assert_eq!(air.nodes[i].r.epoch(), 4, "node {i} re-keyed");
    }
    // cy wakes up holding only the old key: it hears nothing new.
    air.nodes[3].alive = true;
    air.say(1, "after cy left");
    air.run(2 * MIN);
    assert!(air.texts(2).contains(&"ana: after cy left".to_string()));
    assert!(!air.texts(3).contains(&"ana: after cy left".to_string()));
}

#[test]
fn member_that_misses_the_rekey_catches_up() {
    let mut air = Air::new(Opts { n: 4, grace: 8 * MIN, ..Opts::default() });
    air.run(MIN);
    air.nodes[3].alive = false;
    air.run(6 * MIN);
    // bo is out of range while the host re-keys.
    air.hears[0][2] = false;
    while air.nodes[0].r.epoch() == 3 {
        air.step(500);
        assert!(air.now < T0 + 12 * MIN, "host never re-keyed");
    }
    assert_eq!(air.nodes[2].r.epoch(), 3, "bo missed the REKEY");
    air.hears[0][2] = true;
    air.run(4 * MIN);
    air.assert_alive();
    assert_eq!(air.nodes[2].r.epoch(), 4, "bo's next beat made the host resend it");
    air.say(0, "everyone still here?");
    air.run(2 * MIN);
    assert!(air.texts(2).contains(&"host: everyone still here?".to_string()));
}

#[test]
fn any_member_room_dies_when_a_member_goes_silent() {
    let mut air = Air::new(Opts { kill: KillMode::AnyMember, grace: 8 * MIN, ..Opts::default() });
    air.run(MIN);
    air.nodes[2].alive = false;
    air.run(9 * MIN);
    assert_eq!(air.nodes[0].nuked.as_deref(), Some("bo went silent"));
    assert_eq!(air.nodes[1].nuked.as_deref(), Some("host nuked the room"));
}

#[test]
fn manual_nuke_reaches_members() {
    let mut air = Air::new(Opts::default());
    air.run(MIN);
    air.nodes[0].r.shutdown("host nuked the room", air.now);
    air.run(MIN);
    for i in 1..3 {
        assert_eq!(air.nodes[i].nuked.as_deref(), Some("host nuked the room"), "node {i}");
    }
}

#[test]
fn equivocating_host_is_caught_by_members() {
    // One host identity runs two radios that tell ana and bo different stories.
    let o = Opts::default();
    let ids: Vec<Arc<Identity>> = names(3).into_iter().map(|n| Arc::new(Identity::generate(n))).collect();
    let mut s = setups(&o, &ids);
    let evil_twin = Setup {
        room_id: s[0].room_id,
        me: s[0].me.clone(),
        members: s[0].members.clone(),
        room_key: s[0].room_key.clone(),
        epoch: s[0].epoch,
        ip_head: s[0].ip_head,
        kill_mode: s[0].kill_mode,
        grace_ms: s[0].grace_ms,
        lora: s[0].lora,
        budget: s[0].budget,
    };
    s.push(evil_twin);
    let mut air = Air::from_setups(&o, s);
    // Node 0 talks only to ana, node 3 (same host) only to bo.
    for (a, b) in [(0, 2), (2, 0), (3, 1), (1, 3), (0, 3), (3, 0)] {
        air.hears[a][b] = false;
    }
    air.say(0, "ana's version");
    air.say(3, "bo's version");
    air.run(2 * MIN);
    // Each sees a consistent chain of length 1 so far...
    assert_eq!(air.nodes[1].r.seq(), 1);
    assert_eq!(air.nodes[2].r.seq(), 1);
    // ...until they compare notes.
    air.say(1, "what did the host say?");
    air.run(MIN);
    let bo = air.nodes[2].nuked.clone().unwrap_or_default();
    assert!(bo.contains("different histories"), "bo: {bo:?}");
}

#[test]
fn airtime_budget_is_respected() {
    // SF12 at 1%: about four full packets an hour.
    let lora = LoRa { sf: 12, ..LoRa::default() };
    let mut air = Air::new(Opts { n: 2, budget: 0.01, lora, grace: 60 * MIN, ..Opts::default() });
    let long = "x".repeat(MAX_TEXT);
    for _ in 0..8 {
        air.say(1, &long);
    }
    assert!(air.nodes[1].r.send_text("one too many").is_err(), "queue is bounded");
    air.run(30 * MIN);
    let used: f64 = air.nodes[1].sent.iter().map(|(_, ms)| ms).sum();
    assert!(used <= 36_000.0, "{used} ms of airtime in under an hour");
    assert!(air.nodes[1].r.queued() > 0, "the rest wait for airtime");
    assert!(!air.texts(0).is_empty(), "but some got through");
}

#[test]
fn text_limits() {
    let mut air = Air::new(Opts::default());
    assert!(air.nodes[1].r.send_text(&"é".repeat(MAX_TEXT / 2)).is_ok());
    assert!(air.nodes[1].r.send_text(&"x".repeat(MAX_TEXT + 1)).is_err());
    assert!(air.nodes[1].r.send_text("  ").is_err());
    air.run(MIN);
    assert_eq!(air.texts(2), vec![format!("ana: {}", "é".repeat(MAX_TEXT / 2))]);
}

#[test]
fn packets_from_other_rooms_are_ignored() {
    let mut a = Air::new(Opts::default());
    let mut b = Air::new(Opts { seed: 99, ..Opts::default() });
    a.say(1, "room a");
    a.run(MIN);
    for (_, p) in a.log.clone() {
        b.nodes[1].r.on_packet(&p, a.now);
    }
    b.run(MIN);
    b.assert_alive();
    assert!(b.texts(1).is_empty());
}
