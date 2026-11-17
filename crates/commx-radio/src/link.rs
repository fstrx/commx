//! Radio links: something that broadcasts packets and hears them.
//!
//! - `rnode:` a LoRa RNode on USB serial (raw LoRa, one hop).
//! - `udp:` UDP datagrams to a fixed set of peers with optional loss, to
//!   run the whole profile on one machine.

use anyhow::{anyhow, bail, Context, Result};
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::airtime::LoRa;
use crate::packet::MTU;

#[derive(Clone, Debug, PartialEq)]
pub enum LinkSpec {
    /// `rnode:/dev/ttyACM0,freq=869525000[,sf=9][,bw=125000][,cr=5][,txp=14]`
    Rnode { path: String, freq_hz: u32, lora: LoRa, txp_dbm: u8 },
    /// `udp:127.0.0.1:4801,peer=127.0.0.1:4802[,peer=...][,loss=0.2][,sf=9][,bw=125000]`
    Udp { bind: SocketAddr, peers: Vec<SocketAddr>, loss: f64, lora: LoRa },
}

impl LinkSpec {
    pub fn parse(s: &str) -> Result<Self> {
        let (scheme, rest) = s.split_once(':').ok_or_else(|| anyhow!("radio link must start with rnode: or udp:"))?;
        let mut parts = rest.split(',');
        let target = parts.next().filter(|t| !t.is_empty()).ok_or_else(|| anyhow!("radio link needs a device or address"))?;
        let mut lora = LoRa::default();
        let (mut freq, mut txp, mut loss, mut peers) = (None, 14u8, 0.0f64, Vec::new());
        for kv in parts {
            let (k, v) = kv.split_once('=').ok_or_else(|| anyhow!("bad radio option '{kv}'"))?;
            let bad = || anyhow!("bad value for radio option '{k}'");
            match k {
                "freq" => freq = Some(v.parse::<u32>().map_err(|_| bad())?),
                "sf" => lora.sf = v.parse().map_err(|_| bad())?,
                "bw" => lora.bw_hz = v.parse().map_err(|_| bad())?,
                "cr" => lora.cr = v.parse().map_err(|_| bad())?,
                "txp" => txp = v.parse().map_err(|_| bad())?,
                "loss" => loss = v.parse().map_err(|_| bad())?,
                "peer" => peers.push(v.parse().map_err(|_| bad())?),
                _ => bail!("unknown radio option '{k}'"),
            }
        }
        if !lora.valid() {
            bail!("LoRa settings out of range (sf 7-12, cr 5-8, bw 7800-500000)");
        }
        match scheme {
            "rnode" => Ok(LinkSpec::Rnode {
                path: target.to_string(),
                // No default: the legal frequency depends on where you are.
                freq_hz: freq.ok_or_else(|| anyhow!("rnode: needs freq=<Hz> (e.g. 869525000 in the EU)"))?,
                lora,
                txp_dbm: txp,
            }),
            "udp" => {
                if !(0.0..1.0).contains(&loss) {
                    bail!("loss must be in [0, 1)");
                }
                Ok(LinkSpec::Udp { bind: target.parse().context("udp: bind address")?, peers, loss, lora })
            }
            _ => bail!("unknown radio link '{scheme}' (rnode: or udp:)"),
        }
    }

    pub fn lora(&self) -> LoRa {
        match self {
            LinkSpec::Rnode { lora, .. } | LinkSpec::Udp { lora, .. } => *lora,
        }
    }
}

/// An open link: packets to broadcast in, packets heard out.
pub struct Link {
    pub tx: mpsc::Sender<Vec<u8>>,
    pub rx: mpsc::Receiver<Vec<u8>>,
}

pub async fn open(spec: &LinkSpec) -> Result<Link> {
    match spec {
        LinkSpec::Udp { bind, peers, loss, .. } => open_udp(*bind, peers.clone(), *loss).await,
        #[cfg(unix)]
        LinkSpec::Rnode { path, freq_hz, lora, txp_dbm } => serial::open_rnode(
            path,
            crate::kiss::RnodeConfig { freq_hz: *freq_hz, bw_hz: lora.bw_hz, sf: lora.sf, cr: lora.cr, txp_dbm: *txp_dbm },
        ),
        #[cfg(not(unix))]
        LinkSpec::Rnode { .. } => bail!("RNode links are only supported on Unix for now"),
    }
}

async fn open_udp(bind: SocketAddr, peers: Vec<SocketAddr>, loss: f64) -> Result<Link> {
    let sock = std::sync::Arc::new(UdpSocket::bind(bind).await.with_context(|| format!("radio udp bind {bind}"))?);
    let (tx, mut out_rx) = mpsc::channel::<Vec<u8>>(64);
    let (in_tx, rx) = mpsc::channel::<Vec<u8>>(256);
    let s = sock.clone();
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        // The air is shared: anyone may transmit, so every sender is heard.
        while let Ok((n, _)) = s.recv_from(&mut buf).await {
            if n > MTU {
                continue;
            }
            if in_tx.send(buf[..n].to_vec()).await.is_err() {
                break;
            }
        }
    });
    let to = peers;
    tokio::spawn(async move {
        while let Some(pkt) = out_rx.recv().await {
            for p in &to {
                if loss == 0.0 || rand::random::<f64>() >= loss {
                    let _ = sock.send_to(&pkt, p).await;
                }
            }
        }
    });
    Ok(Link { tx, rx })
}

#[cfg(unix)]
mod serial {
    use super::*;
    use crate::kiss::{frame, rnode_setup, Deframer, RnodeConfig, CMD_DATA};
    use std::fs::File;
    use std::io::{Read, Write};
    use std::os::fd::FromRawFd;

    /// Open a serial port raw at 115200 8N1.
    fn open_raw(path: &str) -> Result<File> {
        let c = std::ffi::CString::new(path).context("serial path")?;
        // SAFETY: plain libc calls on a descriptor we own; the termios struct
        // is fully initialised by tcgetattr before use.
        unsafe {
            let fd = libc::open(c.as_ptr(), libc::O_RDWR | libc::O_NOCTTY);
            if fd < 0 {
                return Err(std::io::Error::last_os_error()).with_context(|| format!("open {path}"));
            }
            let file = File::from_raw_fd(fd);
            let mut t: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(fd, &mut t) != 0 {
                return Err(std::io::Error::last_os_error()).context("tcgetattr");
            }
            libc::cfmakeraw(&mut t);
            libc::cfsetispeed(&mut t, libc::B115200);
            libc::cfsetospeed(&mut t, libc::B115200);
            t.c_cflag |= libc::CLOCAL | libc::CREAD;
            t.c_cc[libc::VMIN] = 1;
            t.c_cc[libc::VTIME] = 0;
            if libc::tcsetattr(fd, libc::TCSANOW, &t) != 0 {
                return Err(std::io::Error::last_os_error()).context("tcsetattr");
            }
            Ok(file)
        }
    }

    pub fn open_rnode(path: &str, cfg: RnodeConfig) -> Result<Link> {
        let mut w = open_raw(path)?;
        let mut r = w.try_clone()?;
        w.write_all(&rnode_setup(&cfg)).context("configure RNode")?;
        let (tx, mut out_rx) = mpsc::channel::<Vec<u8>>(64);
        let (in_tx, rx) = mpsc::channel::<Vec<u8>>(256);
        std::thread::spawn(move || {
            let mut d = Deframer::default();
            let mut buf = [0u8; 512];
            while let Ok(n) = r.read(&mut buf) {
                if n == 0 {
                    break;
                }
                for &b in &buf[..n] {
                    if let Some((CMD_DATA, data)) = d.push(b) {
                        if data.len() <= MTU && in_tx.blocking_send(data).is_err() {
                            return;
                        }
                    }
                }
            }
        });
        std::thread::spawn(move || {
            while let Some(pkt) = out_rx.blocking_recv() {
                if w.write_all(&frame(CMD_DATA, &pkt)).is_err() {
                    break;
                }
            }
        });
        Ok(Link { tx, rx })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_specs() {
        let s = LinkSpec::parse("rnode:/dev/ttyACM0,freq=869525000,sf=7").unwrap();
        assert_eq!(
            s,
            LinkSpec::Rnode {
                path: "/dev/ttyACM0".into(),
                freq_hz: 869_525_000,
                lora: LoRa { sf: 7, ..LoRa::default() },
                txp_dbm: 14
            }
        );
        assert!(LinkSpec::parse("rnode:/dev/ttyACM0").is_err(), "frequency is required");
        let u = LinkSpec::parse("udp:127.0.0.1:4801,peer=127.0.0.1:4802,peer=127.0.0.1:4803,loss=0.25").unwrap();
        let LinkSpec::Udp { peers, loss, .. } = u else { panic!() };
        assert_eq!((peers.len(), loss), (2, 0.25));
        assert!(LinkSpec::parse("udp:127.0.0.1:1,sf=13").is_err());
        assert!(LinkSpec::parse("tcp:1.2.3.4:5").is_err());
    }

    #[tokio::test]
    async fn udp_link_carries_packets() {
        let a: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let sa = std::net::UdpSocket::bind(a).unwrap();
        let sb = std::net::UdpSocket::bind(a).unwrap();
        let (pa, pb) = (sa.local_addr().unwrap(), sb.local_addr().unwrap());
        drop((sa, sb));
        let la = open_udp(pa, vec![pb], 0.0).await.unwrap();
        let mut lb = open_udp(pb, vec![pa], 0.0).await.unwrap();
        la.tx.send(b"over the air".to_vec()).await.unwrap();
        let got = tokio::time::timeout(std::time::Duration::from_secs(5), lb.rx.recv()).await.unwrap();
        assert_eq!(got.as_deref(), Some(&b"over the air"[..]));
    }
}
