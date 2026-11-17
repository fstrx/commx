//! commx-radio: the text-only radio profile (SPEC §18) for LoRa and other
//! slow, lossy broadcast links.
//!
//! A room joins over IP as usual, then hands over to radio. Each message is
//! broadcast once by its author; the host sequences what it heard with
//! small signed `ORDER` packets, and lost packets are repaired rather than
//! treated as attacks. [`Radio`] is sans-IO: feed it packets and the clock,
//! pull packets to send. [`link`] has the adapters that move them.

pub mod airtime;
pub mod kiss;
pub mod link;
pub mod packet;
mod room;

pub use airtime::LoRa;
pub use packet::{MAX_TEXT, MTU};
pub use room::{Event, Member, Radio, Setup, ORDER_MAX};
