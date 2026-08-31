//! SNTP unicast server.
//!
//! `bind` opens the UDP socket and `run` enters the receive loop. Every valid
//! client request is answered with a reply stamped from the current system
//! clock. A per-packet failure is reported with `tracing::warn!` and never
//! breaks the loop.

use std::io;
use std::net::SocketAddr;

use tokio::net::UdpSocket;

use crate::error::SntpError;
use crate::packet::{LeapIndicator, Mode, SntpPacket, SNTP_PACKET_LEN};
use crate::time::NtpTimestamp;

/// SNTP server configuration.
#[derive(Debug, Clone, Copy)]
pub struct SntpServerConfig {
    /// Stratum, 1 for a primary reference. Defaults to 1.
    pub stratum: u8,
    /// Poll interval as log2 seconds. Defaults to 6, that is 64 seconds.
    pub poll: i8,
    /// Precision as log2 seconds. Defaults to -20, roughly microseconds.
    pub precision: i8,
    /// Root delay, an NTP short in fixed point. Defaults to 0.
    pub root_delay: u32,
    /// Root dispersion, an NTP short in fixed point. Defaults to 0.
    pub root_dispersion: u32,
    /// Reference identifier, four ASCII characters at stratum 1. Defaults to
    /// `LOCL`.
    pub reference_id: [u8; 4],
}

impl Default for SntpServerConfig {
    fn default() -> Self {
        Self {
            stratum: 1,
            poll: 6,
            precision: -20,
            root_delay: 0,
            root_dispersion: 0,
            reference_id: *b"LOCL",
        }
    }
}

/// SNTP unicast server.
///
/// # Examples
///
/// ```no_run
/// # use iec61850_sntp::SntpServer;
/// # async fn demo() -> std::io::Result<()> {
/// let server = SntpServer::bind("0.0.0.0:123".parse().unwrap()).await?;
/// server.run().await
/// # }
/// ```
pub struct SntpServer {
    socket: UdpSocket,
    config: SntpServerConfig,
}

impl SntpServer {
    /// Binds the UDP socket. Port 123 is the standard port and needs
    /// privileges; a test can bind port 0 or a high port.
    pub async fn bind(addr: SocketAddr) -> io::Result<Self> {
        let socket = UdpSocket::bind(addr).await?;
        Ok(Self {
            socket,
            config: SntpServerConfig::default(),
        })
    }

    /// Binds the UDP socket with an explicit configuration.
    pub async fn bind_with(addr: SocketAddr, config: SntpServerConfig) -> io::Result<Self> {
        let socket = UdpSocket::bind(addr).await?;
        Ok(Self { socket, config })
    }

    /// Returns the address the socket is actually bound to, which a caller
    /// that bound port 0 has to query.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Enters the receive loop, answering every valid client request.
    ///
    /// Returns only when the socket fails, and then propagates the
    /// unrecoverable I/O error. A per-packet failure, such as a decode error
    /// or a mode other than client, is logged at warn level and the loop
    /// continues.
    pub async fn run(self) -> io::Result<()> {
        let mut buf = [0u8; SNTP_PACKET_LEN];
        loop {
            let (len, peer) = self.socket.recv_from(&mut buf).await?;
            // Stamp the receive time at once, so reply processing does not bias it.
            let recv_ts = match NtpTimestamp::now() {
                Ok(ts) => ts,
                Err(err) => {
                    tracing::warn!(
                        ?err,
                        "system clock cannot be expressed as an NTP timestamp, skipping packet"
                    );
                    continue;
                }
            };

            match build_reply(&self.config, &buf[..len], recv_ts) {
                Ok(reply) => {
                    let wire = reply.encode();
                    if let Err(err) = self.socket.send_to(&wire, peer).await {
                        tracing::warn!(?err, %peer, "failed to send SNTP reply");
                    }
                }
                Err(err) => {
                    tracing::warn!(?err, %peer, len, "rejected SNTP packet");
                }
            }
        }
    }

    /// Decodes one packet, checks its mode and builds the reply. Method form
    /// of `build_reply`.
    pub fn handle_request(
        &self,
        buf: &[u8],
        recv_ts: NtpTimestamp,
    ) -> Result<SntpPacket, SntpError> {
        build_reply(&self.config, buf, recv_ts)
    }
}

/// Builds the reply for one request packet.
///
/// Kept free-standing so it can be tested without a socket or an async
/// runtime.
///
/// # Errors
///
/// Propagates the errors of [`SntpPacket::decode`], and returns
/// [`SntpError::UnexpectedMode`] when the request mode is neither client nor
/// symmetric active.
pub fn build_reply(
    config: &SntpServerConfig,
    buf: &[u8],
    recv_ts: NtpTimestamp,
) -> Result<SntpPacket, SntpError> {
    let req = SntpPacket::decode(buf)?;

    // Only client (3) and symmetric active (1) are answered; replying to any
    // other mode would confuse a broadcast or control association.
    if !matches!(req.mode, Mode::Client | Mode::SymmetricActive) {
        return Err(SntpError::UnexpectedMode(req.mode as u8));
    }

    let xmit_ts = NtpTimestamp::now()?;

    Ok(SntpPacket {
        leap: LeapIndicator::NoWarning,
        version: req.version,
        mode: Mode::Server,
        stratum: config.stratum,
        poll: config.poll,
        precision: config.precision,
        root_delay: config.root_delay,
        root_dispersion: config.root_dispersion,
        reference_id: config.reference_id,
        reference_ts: recv_ts,
        // RFC 4330 §5: the client transmit timestamp is echoed as originate.
        originate_ts: req.transmit_ts,
        receive_ts: recv_ts,
        transmit_ts: xmit_ts,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> SntpServerConfig {
        SntpServerConfig::default()
    }

    #[test]
    fn build_reply_for_client_request() {
        let mut req = SntpPacket::client_request();
        req.transmit_ts = NtpTimestamp {
            seconds: 0x1234_5678,
            fraction: 0xCAFEBABE,
        };
        let recv_ts = NtpTimestamp {
            seconds: 0x9999_AAAA,
            fraction: 0,
        };

        let reply = build_reply(&cfg(), &req.encode(), recv_ts).expect("valid reply");

        assert_eq!(reply.mode, Mode::Server);
        assert_eq!(reply.version, 4);
        assert_eq!(reply.stratum, 1);
        assert_eq!(reply.reference_id, *b"LOCL");
        assert_eq!(reply.originate_ts, req.transmit_ts);
        assert_eq!(reply.receive_ts, recv_ts);
        // The transmit timestamp comes from the real clock, so it cannot be zero.
        assert_ne!(reply.transmit_ts, NtpTimestamp::ZERO);
    }

    #[test]
    fn reject_server_mode_request() {
        let mut req = SntpPacket::client_request();
        req.mode = Mode::Server; // a request that claims to be a server reply must be rejected

        let err = build_reply(&cfg(), &req.encode(), NtpTimestamp::ZERO).expect_err("must reject");
        assert!(matches!(err, SntpError::UnexpectedMode(4)));
    }

    #[test]
    fn reject_too_short() {
        let buf = [0u8; 10];
        let err = build_reply(&cfg(), &buf, NtpTimestamp::ZERO).expect_err("too short");
        assert!(matches!(err, SntpError::InvalidLength { .. }));
    }

    #[test]
    fn accept_symmetric_active() {
        let mut req = SntpPacket::client_request();
        req.mode = Mode::SymmetricActive;
        let reply =
            build_reply(&cfg(), &req.encode(), NtpTimestamp::ZERO).expect("symmetric accepted");
        assert_eq!(reply.mode, Mode::Server);
    }
}
