//! SNTPv4 unicast client (RFC 4330 §5).
//!
//! Opens an ephemeral UDP socket, sends a mode 3 request, waits for a mode 4
//! reply and derives the clock offset and the round-trip delay with the
//! formulas of RFC 4330 §5:
//!
//! ```text
//!   t1 = client transmit time     (local clock when the request left)
//!   t2 = server receive time      (server clock on arrival)
//!   t3 = server transmit time     (server clock when the reply left)
//!   t4 = client receive time      (local clock when the reply arrived)
//!
//!   offset      = ((t2 - t1) + (t3 - t4)) / 2
//!   round_trip  =  (t4 - t1) - (t3 - t2)
//! ```
//!
//! Invariants, as in the server: no library path panics, every fallible one
//! returns a [`Result`]; received bytes go through [`SntpPacket::decode`];
//! and the receive timeout is mandatory, so a lost reply cannot block
//! forever.

use std::io;
use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::error::SntpError;
use crate::packet::{LeapIndicator, Mode, SntpPacket, SNTP_PACKET_LEN};
use crate::time::{NtpTimestamp, NTP_UNIX_OFFSET_S};

/// SNTP unicast client.
///
/// # Examples
///
/// ```no_run
/// # use iec61850_sntp::SntpClient;
/// # use std::time::Duration;
/// # async fn demo() -> Result<(), iec61850_sntp::SntpError> {
/// let client = SntpClient::new("pool.ntp.org:123".parse().unwrap());
/// let r = client.query(Duration::from_secs(3)).await?;
/// println!("offset={:.6}s rtt={:.6}s", r.offset_seconds, r.round_trip_seconds);
/// # Ok(()) }
/// ```
#[derive(Debug, Clone)]
pub struct SntpClient {
    server: SocketAddr,
    bind_addr: SocketAddr,
}

impl SntpClient {
    /// Creates a client aimed at `server`, bound locally to an ephemeral port.
    pub fn new(server: SocketAddr) -> Self {
        let bind_addr = if server.is_ipv6() {
            "[::]:0".parse().expect("static literal addr")
        } else {
            "0.0.0.0:0".parse().expect("static literal addr")
        };
        Self { server, bind_addr }
    }

    /// Overrides the local bind address, to select an interface or to pin a
    /// port in a test.
    pub fn with_bind_addr(mut self, addr: SocketAddr) -> Self {
        self.bind_addr = addr;
        self
    }

    /// Sends one query and waits for the reply.
    ///
    /// `recv_timeout` is the wall-clock limit for the reply.
    ///
    /// # Errors
    ///
    /// An I/O error of kind `TimedOut` when no reply arrives in time; the
    /// decode errors of [`SntpPacket::decode`];
    /// [`SntpError::UnexpectedMode`] when the reply is not in server mode;
    /// and [`SntpError::InvalidHeader`] when the reply does not echo the
    /// originate timestamp, or reports an unsynchronized clock.
    pub async fn query(&self, recv_timeout: Duration) -> Result<SntpResponse, SntpError> {
        let socket = UdpSocket::bind(self.bind_addr).await?;
        socket.connect(self.server).await?;

        // Build the request: mode 3, version 4, current time in transmit_ts.
        let t1_ntp = NtpTimestamp::now()?;
        let t1_unix = system_now_unix_s()?;
        let mut req = SntpPacket::client_request();
        req.transmit_ts = t1_ntp;
        let wire = req.encode();
        socket.send(&wire).await?;

        let mut buf = [0u8; SNTP_PACKET_LEN];
        let len = timeout(recv_timeout, socket.recv(&mut buf))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "SNTP recv timed out"))??;

        // Take t4 the instant the reply arrives, as close to the wire as possible.
        let t4_unix = system_now_unix_s()?;

        let reply = SntpPacket::decode(&buf[..len])?;
        if reply.mode != Mode::Server {
            return Err(SntpError::UnexpectedMode(reply.mode as u8));
        }
        // RFC 4330: the reply must echo our transmit timestamp as originate;
        // anything else is another client's reply, or a replay.
        if reply.originate_ts != t1_ntp {
            return Err(SntpError::InvalidHeader("originate_ts mismatch (replay?)"));
        }
        if reply.leap == LeapIndicator::AlarmUnsynchronized || reply.stratum == 0 {
            return Err(SntpError::InvalidHeader(
                "server reports kiss-of-death / unsynchronized",
            ));
        }

        let t2_unix = ntp_to_unix_s(reply.receive_ts);
        let t3_unix = ntp_to_unix_s(reply.transmit_ts);

        let offset = ((t2_unix - t1_unix) + (t3_unix - t4_unix)) / 2.0;
        let round_trip = (t4_unix - t1_unix) - (t3_unix - t2_unix);

        Ok(SntpResponse {
            server_time_unix_s: t3_unix,
            client_receive_unix_s: t4_unix,
            offset_seconds: offset,
            round_trip_seconds: round_trip,
            stratum: reply.stratum,
            poll: reply.poll,
            precision: reply.precision,
            reference_id: reply.reference_id,
            leap_indicator: reply.leap,
            version: reply.version,
        })
    }
}

/// The result of one SNTP query, converted to Unix epoch seconds.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SntpResponse {
    /// Server transmit time (t3) as fractional Unix epoch seconds.
    pub server_time_unix_s: f64,
    /// Client receive time (t4) as Unix epoch seconds, from which a caller
    /// can derive the age of the synchronization point.
    pub client_receive_unix_s: f64,
    /// Clock offset in seconds; positive means the server runs ahead.
    pub offset_seconds: f64,
    /// Round-trip delay in seconds.
    pub round_trip_seconds: f64,
    /// Stratum: 1 for a primary reference, 2 and above for secondary.
    pub stratum: u8,
    /// Poll interval, as log2 seconds.
    pub poll: i8,
    /// Precision, as log2 seconds.
    pub precision: i8,
    /// Reference identifier, four ASCII characters at stratum 1.
    pub reference_id: [u8; 4],
    /// Leap indicator reported by the server.
    pub leap_indicator: LeapIndicator,
    /// SNTP version the server replied with.
    pub version: u8,
}

fn system_now_unix_s() -> Result<f64, SntpError> {
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| SntpError::TimeBeforeEpoch)?;
    Ok(dur.as_secs() as f64 + f64::from(dur.subsec_nanos()) / 1e9)
}

/// 2^32 as `f64`: an NTP fraction divided by this is a count of seconds.
const NTP_FRACTION_PER_SECOND: f64 = 4_294_967_296.0;

fn ntp_to_unix_s(ts: NtpTimestamp) -> f64 {
    // The NTP epoch (1900) precedes the Unix epoch (1970) by 2208988800 s.
    // Only era 0 is handled; `seconds` is a u32 and wraps into era 1 in 2036.
    // TODO: handle NTP era rollover.
    let unix_secs = i64::from(ts.seconds) - NTP_UNIX_OFFSET_S as i64;
    unix_secs as f64 + f64::from(ts.fraction) / NTP_FRACTION_PER_SECOND
}
