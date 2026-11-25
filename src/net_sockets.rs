//! Parses Linux `/proc/net/{tcp,tcp6,udp,udp6}` socket tables into typed entries.
//!
//! Keeps IPv4 and IPv6 hex decoding and UDP state formatting isolated here so the
//! TUI and process mapper work with standard `std::net::SocketAddr` values.

use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::path::Path;

/// Formats a `SocketAddr`, unwrapping IPv4-mapped IPv6 (`::ffff:a.b.c.d`) as `a.b.c.d:port`.
pub fn format_socket_addr(addr: SocketAddr) -> String {
    match addr {
        SocketAddr::V4(_) => addr.to_string(),
        SocketAddr::V6(v6) => {
            // Unwrap dual-stack `::ffff:a.b.c.d` addresses into plain IPv4 `a.b.c.d:port`.
            if let Some(v4) = v6.ip().to_ipv4_mapped() {
                SocketAddr::V4(SocketAddrV4::new(v4, v6.port())).to_string()
            } else {
                // Keep native IPv6 formatting (including brackets around the address).
                addr.to_string()
            }
        }
    }
}

/// TCP connection states corresponding to kernel hex codes `01`..=`0B`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    /// Active connection (`TCP_ESTABLISHED`, `0x01`).
    Established,
    /// Outgoing connection attempt (`TCP_SYN_SENT`, `0x02`).
    SynSent,
    /// Incoming connection request seen (`TCP_SYN_RECV`, `0x03`).
    SynRecv,
    /// Local end closed and sent FIN (`TCP_FIN_WAIT1`, `0x04`).
    FinWait1,
    /// Awaiting final FIN from remote end (`TCP_FIN_WAIT2`, `0x05`).
    FinWait2,
    /// Waiting enough time to ensure remote saw FIN ack (`TCP_TIME_WAIT`, `0x06`).
    TimeWait,
    /// Socket is closed (`TCP_CLOSE`, `0x07`).
    Close,
    /// Remote end closed; waiting for local close (`TCP_CLOSE_WAIT`, `0x08`).
    CloseWait,
    /// Remote closed after local FIN; waiting for final ACK (`TCP_LAST_ACK`, `0x09`).
    LastAck,
    /// Socket is listening for incoming connections (`TCP_LISTEN`, `0x0A`).
    Listen,
    /// Both ends closed simultaneously (`TCP_CLOSING`, `0x0B`).
    Closing,
    /// Unrecognized state byte preserved for visibility.
    Unknown(u8),
}

impl TcpState {
    /// Converts a kernel hex state code (such as `"0A"`) into a [`TcpState`].
    pub fn from_hex_byte(hex: &str) -> Result<Self, String> {
        // Parse the 2-digit hex state column from `/proc/net/*`.
        let code = u8::from_str_radix(hex, 16)
            .map_err(|e| format!("invalid TCP state hex '{hex}': {e}"))?;

        // Map known kernel TCP state constants, preserving any unexpected byte value.
        Ok(match code {
            0x01 => Self::Established,
            0x02 => Self::SynSent,
            0x03 => Self::SynRecv,
            0x04 => Self::FinWait1,
            0x05 => Self::FinWait2,
            0x06 => Self::TimeWait,
            0x07 => Self::Close,
            0x08 => Self::CloseWait,
            0x09 => Self::LastAck,
            0x0A => Self::Listen,
            0x0B => Self::Closing,
            other => Self::Unknown(other),
        })
    }

    /// Returns the human-readable uppercase state label used across CLI and TUI views.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Established => "ESTABLISHED",
            Self::SynSent => "SYN-SENT",
            Self::SynRecv => "SYN-RECV",
            Self::FinWait1 => "FIN-WAIT-1",
            Self::FinWait2 => "FIN-WAIT-2",
            Self::TimeWait => "TIME-WAIT",
            Self::Close => "CLOSE",
            Self::CloseWait => "CLOSE-WAIT",
            Self::LastAck => "LAST-ACK",
            Self::Listen => "LISTEN",
            Self::Closing => "CLOSING",
            Self::Unknown(_) => "UNKNOWN",
        }
    }
}

/// Parsed representation of a single socket row from `/proc/net/{tcp,tcp6,udp,udp6}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketEntry {
    /// Protocol label displayed in tables (`"tcp"`, `"tcp6"`, `"udp"`, or `"udp6"`).
    pub proto: &'static str,
    /// Local IP address and port.
    pub local_addr: SocketAddr,
    /// Remote IP address and port.
    pub remote_addr: SocketAddr,
    /// Kernel socket state (decoded via [`TcpState`]).
    pub state: TcpState,
    /// Numeric user ID owning the socket.
    pub uid: u32,
    /// Socket inode number used to join against `/proc/<pid>/fd`.
    pub inode: u64,
}

/// Decodes an 8-character hex IPv4 endpoint (`XXXXXXXX:PPPP`) into a [`SocketAddr`].
fn parse_ipv4_endpoint(token: &str) -> Result<SocketAddr, String> {
    // Split `<hex_ip>:<hex_port>` into address and port hex strings.
    let (ip_hex, port_hex) = token
        .split_once(':')
        .ok_or_else(|| format!("missing ':' in endpoint '{token}'"))?;

    // Reject truncated or oversized IPv4 hex fields before decoding.
    if ip_hex.len() != 8 {
        return Err(format!("expected 8 hex chars for IPv4, got '{}'", ip_hex));
    }

    // `/proc/net/tcp` stores IPv4 addresses as a 32-bit value in little-endian byte order.
    let raw_ip =
        u32::from_str_radix(ip_hex, 16).map_err(|e| format!("invalid IPv4 hex '{ip_hex}': {e}"))?;
    let octets = raw_ip.to_le_bytes();
    let ip = Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]);

    // Ports in `/proc/net/*` are stored in big-endian (network) hex order.
    let port = u16::from_str_radix(port_hex, 16)
        .map_err(|e| format!("invalid port hex '{port_hex}': {e}"))?;

    Ok(SocketAddr::V4(SocketAddrV4::new(ip, port)))
}

/// Decodes a 32-character hex IPv6 endpoint (`XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX:PPPP`) into a [`SocketAddr`].
fn parse_ipv6_endpoint(token: &str) -> Result<SocketAddr, String> {
    // Split `<hex_ipv6>:<hex_port>` into the 128-bit address and 16-bit port fields.
    let (ip_hex, port_hex) = token
        .split_once(':')
        .ok_or_else(|| format!("missing ':' in endpoint '{token}'"))?;

    // Require all 32 hex nibbles for a full 128-bit IPv6 address.
    if ip_hex.len() != 32 {
        return Err(format!("expected 32 hex chars for IPv6, got '{}'", ip_hex));
    }

    // `/proc/net/tcp6` prints four 32-bit words; each word's bytes appear in little-endian order.
    let mut bytes = [0u8; 16];
    let (chunks, _) = ip_hex.as_bytes().as_chunks::<8>();
    for (word_idx, chunk) in chunks.iter().enumerate() {
        let chunk_str =
            std::str::from_utf8(chunk).map_err(|e| format!("non-UTF8 IPv6 hex chunk: {e}"))?;
        let word = u32::from_str_radix(chunk_str, 16)
            .map_err(|e| format!("invalid IPv6 word hex '{chunk_str}': {e}"))?;
        // Convert each 32-bit word from host/little-endian representation into byte order.
        let word_bytes = word.to_le_bytes();
        let start = word_idx * 4;
        bytes[start..start + 4].copy_from_slice(&word_bytes);
    }

    let ip = Ipv6Addr::from(bytes);
    // Decode the big-endian hex port suffix.
    let port = u16::from_str_radix(port_hex, 16)
        .map_err(|e| format!("invalid port hex '{port_hex}': {e}"))?;

    // Scope ID `0` and flowinfo `0` match `/proc/net/tcp6`, which omits link-local scope numbers.
    Ok(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0)))
}

/// Parses a single non-header line from `/proc/net/{tcp,tcp6,udp,udp6}`.
fn parse_socket_line(
    line: &str,
    proto: &'static str,
    endpoint_parser: fn(&str) -> Result<SocketAddr, String>,
) -> Result<SocketEntry, String> {
    let cols: Vec<&str> = line.split_whitespace().collect();
    // Standard `/proc/net/*` rows have at least 10 whitespace-separated columns:
    // sl, local_address, rem_address, st, tx_queue:rx_queue, tr:tm->when, retrnsmt, uid, timeout, inode.
    if cols.len() < 10 {
        return Err(format!("expected at least 10 columns, got {}", cols.len()));
    }

    // Extract local/remote endpoints, socket state, owner UID, and kernel socket inode.
    let local_addr = endpoint_parser(cols[1])?;
    let remote_addr = endpoint_parser(cols[2])?;
    let state = TcpState::from_hex_byte(cols[3])?;
    let uid = cols[7]
        .parse::<u32>()
        .map_err(|e| format!("invalid uid '{}': {e}", cols[7]))?;
    let inode = cols[9]
        .parse::<u64>()
        .map_err(|e| format!("invalid inode '{}': {e}", cols[9]))?;

    Ok(SocketEntry {
        proto,
        local_addr,
        remote_addr,
        state,
        uid,
        inode,
    })
}

/// Reads a `/proc/net/*` reader, skipping the header and malformed rows.
fn parse_tcp_reader<R: BufRead>(
    reader: R,
    proto: &'static str,
    endpoint_parser: fn(&str) -> Result<SocketAddr, String>,
) -> io::Result<Vec<SocketEntry>> {
    let mut entries = Vec::new();

    for (idx, line_res) in reader.lines().enumerate() {
        let line = line_res?;
        // First line is always column headers (`sl local_address rem_address ...`).
        if idx == 0 {
            continue;
        }
        // Ignore empty trailing or blank lines.
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        // Transient kernel updates can emit short or partial lines; skip rather than failing the whole read.
        if let Ok(entry) = parse_socket_line(trimmed, proto, endpoint_parser) {
            entries.push(entry);
        }
    }

    Ok(entries)
}

/// Parses IPv4 TCP sockets from `/proc/net/tcp` (or a mock file in tests).
pub fn parse_proc_net_tcp(path: &Path) -> io::Result<Vec<SocketEntry>> {
    // Stream the file through a buffered reader to avoid allocating the whole table as one string.
    let file = File::open(path)?;
    parse_tcp_reader(BufReader::new(file), "tcp", parse_ipv4_endpoint)
}

/// Parses IPv6 TCP sockets from `/proc/net/tcp6` (or a mock file in tests).
pub fn parse_proc_net_tcp6(path: &Path) -> io::Result<Vec<SocketEntry>> {
    // Stream IPv6 TCP rows using the 32-character hex endpoint parser.
    let file = File::open(path)?;
    parse_tcp_reader(BufReader::new(file), "tcp6", parse_ipv6_endpoint)
}

/// Parses IPv4 UDP sockets from `/proc/net/udp` (or a mock file in tests).
pub fn parse_proc_net_udp(path: &Path) -> io::Result<Vec<SocketEntry>> {
    // Stream IPv4 UDP rows using the shared `/proc/net` line parser.
    let file = File::open(path)?;
    parse_tcp_reader(BufReader::new(file), "udp", parse_ipv4_endpoint)
}

/// Parses IPv6 UDP sockets from `/proc/net/udp6` (or a mock file in tests).
pub fn parse_proc_net_udp6(path: &Path) -> io::Result<Vec<SocketEntry>> {
    // Stream IPv6 UDP rows using the shared `/proc/net` line parser.
    let file = File::open(path)?;
    parse_tcp_reader(BufReader::new(file), "udp6", parse_ipv6_endpoint)
}

/// Returns a display state label suited to the socket protocol.
pub fn display_state_for_proto(proto: &str, state: TcpState) -> &'static str {
    // UDP sockets report kernel state `07` (`TCP_CLOSE`) for unconnected sockets; show `UNCONN` instead.
    if matches!(proto, "udp" | "udp6") {
        match state {
            TcpState::Close => "UNCONN",
            TcpState::Established => "ESTABLISHED",
            other => other.as_str(),
        }
    } else {
        state.as_str()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn decodes_little_endian_ipv4_and_port() {
        // `0100007F:0050` -> 127.0.0.1:80
        let addr = parse_ipv4_endpoint("0100007F:0050").expect("valid IPv4 endpoint");
        assert_eq!(
            addr,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 80))
        );
    }

    #[test]
    fn decodes_ipv6_loopback_and_port() {
        // Loopback `::1` in four little-endian 32-bit words, port `01BB` = 443.
        let addr = parse_ipv6_endpoint("00000000000000000000000001000000:01BB")
            .expect("valid IPv6 endpoint");
        assert_eq!(
            addr,
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 443, 0, 0))
        );
    }

    #[test]
    fn parses_tcp_entries_and_skips_malformed_lines() {
        let sample = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 42100 1 0000000000000000 100 0 0 10 0
   1: malformed_line_here
";
        let entries = parse_tcp_reader(Cursor::new(sample), "tcp", parse_ipv4_endpoint)
            .expect("reader should succeed");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].proto, "tcp");
        assert_eq!(entries[0].state, TcpState::Listen);
        assert_eq!(entries[0].inode, 42100);
    }

    #[test]
    fn parses_tcp6_entries() {
        let sample = "\
  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:0035 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000   101        0 99001 1 0000000000000000 100 0 0 10 0
";
        let entries = parse_tcp_reader(Cursor::new(sample), "tcp6", parse_ipv6_endpoint)
            .expect("reader should succeed");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].proto, "tcp6");
        assert_eq!(
            entries[0].local_addr,
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 53, 0, 0))
        );
        assert_eq!(entries[0].inode, 99001);
    }

    #[test]
    fn parses_udp_entries_and_formats_unconn_state() {
        let sample = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
   0: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   101        0 77812 2 0000000000000000 0
";
        let entries = parse_tcp_reader(Cursor::new(sample), "udp", parse_ipv4_endpoint)
            .expect("reader should succeed");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].proto, "udp");
        assert_eq!(
            display_state_for_proto(entries[0].proto, entries[0].state),
            "UNCONN"
        );
        assert_eq!(entries[0].inode, 77812);
    }

    #[test]
    fn parses_udp6_entries_and_formats_unconn_state() {
        // `::1` port `022B` = 555, state `07` -> `UNCONN` for UDP/UDP6 sockets.
        let sample = "\
  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
   0: 00000000000000000000000001000000:022B 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000   101        0 88210 2 0000000000000000 0
";
        let entries = parse_tcp_reader(Cursor::new(sample), "udp6", parse_ipv6_endpoint)
            .expect("reader should succeed");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].proto, "udp6");
        assert_eq!(
            entries[0].local_addr,
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 555, 0, 0))
        );
        assert_eq!(
            display_state_for_proto(entries[0].proto, entries[0].state),
            "UNCONN"
        );
        assert_eq!(entries[0].inode, 88210);
    }

    #[test]
    fn formats_ipv4_mapped_ipv6_as_ipv4_address_and_port() {
        let mapped: SocketAddr = "[::ffff:192.168.1.42]:8443".parse().unwrap();
        assert_eq!(format_socket_addr(mapped), "192.168.1.42:8443");

        let mapped_unspecified: SocketAddr = "[::ffff:0.0.0.0]:80".parse().unwrap();
        assert_eq!(format_socket_addr(mapped_unspecified), "0.0.0.0:80");
    }

    #[test]
    fn preserves_native_ipv6_and_ipv4_addresses() {
        let loopback_v6: SocketAddr = "[::1]:22".parse().unwrap();
        assert_eq!(format_socket_addr(loopback_v6), "[::1]:22");

        let global_v6: SocketAddr = "[2001:db8::10]:443".parse().unwrap();
        assert_eq!(format_socket_addr(global_v6), "[2001:db8::10]:443");

        let ipv4: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        assert_eq!(format_socket_addr(ipv4), "127.0.0.1:8080");
    }
}
