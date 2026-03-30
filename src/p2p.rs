//! Minimal Ergo P2P protocol implementation.
//!
//! Handles: handshake, GetPeers/Peers exchange, and transaction broadcast.
//! Does NOT handle: block sync, state management, mining, or any full node logic.

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use std::io::{Read, Write, Cursor};
use std::net::{TcpStream, SocketAddr, ToSocketAddrs};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

type Blake2b256 = Blake2b<U32>;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const MAINNET_MAGIC: [u8; 4] = [1, 0, 2, 4];
pub const TESTNET_MAGIC: [u8; 4] = [2, 0, 2, 3];

// Message codes
const MSG_GET_PEERS: u8 = 1;
const MSG_PEERS: u8 = 2;
// const MSG_INV: u8 = 55;
// const MSG_MODIFIER_REQUEST: u8 = 22;
// const MSG_MODIFIER_RESPONSE: u8 = 33;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const READ_TIMEOUT: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------------------
// VLQ encoding/decoding
// ---------------------------------------------------------------------------

fn write_vlq(buf: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            buf.push(byte);
            break;
        } else {
            buf.push(byte | 0x80);
        }
    }
}

fn read_vlq(cursor: &mut Cursor<&[u8]>) -> std::io::Result<u64> {
    let mut result: u64 = 0;
    let mut shift = 0;
    loop {
        let mut byte = [0u8; 1];
        cursor.read_exact(&mut byte)?;
        result |= ((byte[0] & 0x7f) as u64) << shift;
        if byte[0] & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 63 {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "VLQ overflow"));
        }
    }
    Ok(result)
}

/// Read a VLQ value that represents a byte length (capped at 256KB to prevent OOM).
fn read_vlq_length(cursor: &mut Cursor<&[u8]>) -> std::io::Result<usize> {
    let val = read_vlq(cursor)?;
    if val > 256 * 1024 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("VLQ length too large: {} (max 262144)", val),
        ));
    }
    Ok(val as usize)
}

fn write_utf8_byte_len(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    buf.push(bytes.len() as u8);
    buf.extend_from_slice(bytes);
}

fn read_utf8_byte_len(cursor: &mut Cursor<&[u8]>) -> std::io::Result<String> {
    let mut len_byte = [0u8; 1];
    cursor.read_exact(&mut len_byte)?;
    let len = len_byte[0] as usize;
    let mut bytes = vec![0u8; len];
    cursor.read_exact(&mut bytes)?;
    String::from_utf8(bytes).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

// ---------------------------------------------------------------------------
// Handshake
// ---------------------------------------------------------------------------

/// Build a handshake payload (sent raw, no message framing).
pub fn build_handshake(agent_name: &str, peer_name: &str, network: Network) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);

    // Timestamp (VLQ unsigned long = milliseconds since epoch)
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;
    write_vlq(&mut buf, now);

    // Agent name (UTF-8 byte-len prefixed)
    write_utf8_byte_len(&mut buf, agent_name);

    // Protocol version: 6.0.1 (match current Ergo nodes)
    buf.push(6); // major
    buf.push(0); // minor
    buf.push(1); // patch

    // Peer name
    write_utf8_byte_len(&mut buf, peer_name);

    // No public address
    buf.push(0); // hasPublicAddress = false

    // 1 feature: session (id=3) — required for full peer registration
    buf.push(1); // feature count

    // Session feature: id=3, body = 4 bytes magic + 8 bytes random session ID
    buf.push(3); // feature id
    // Body length as unsigned short (2 bytes big-endian)
    let session_body_len: u16 = 12; // 4 magic + 8 session ID
    buf.extend_from_slice(&session_body_len.to_be_bytes());
    buf.extend_from_slice(&network.magic()); // network magic
    let session_id = rand_u64();
    buf.extend_from_slice(&session_id.to_be_bytes());

    buf
}

/// Parse a handshake response, extract peer info.
pub fn parse_handshake(data: &[u8]) -> std::io::Result<PeerInfo> {
    let mut cursor = Cursor::new(data);

    // Timestamp
    let _timestamp = read_vlq(&mut cursor)?;

    // Agent name
    let agent_name = read_utf8_byte_len(&mut cursor)?;

    // Version: 3 bytes
    let mut ver = [0u8; 3];
    cursor.read_exact(&mut ver)?;

    // Peer name
    let peer_name = read_utf8_byte_len(&mut cursor)?;

    // Public address
    let mut has_addr = [0u8; 1];
    cursor.read_exact(&mut has_addr)?;
    let mut public_address: Option<SocketAddr> = None;
    if has_addr[0] != 0 {
        let mut addr_len_byte = [0u8; 1];
        cursor.read_exact(&mut addr_len_byte)?;
        let ip_len = (addr_len_byte[0] as usize).saturating_sub(4);
        let mut ip_bytes = vec![0u8; ip_len];
        cursor.read_exact(&mut ip_bytes)?;
        // Port as unsigned 4-byte int
        let mut port_bytes = [0u8; 4];
        cursor.read_exact(&mut port_bytes)?;
        let port = u32::from_be_bytes(port_bytes) as u16;

        if ip_len == 4 {
            let ip = std::net::Ipv4Addr::new(ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
            public_address = Some(SocketAddr::new(ip.into(), port));
        }
    }

    // Features (skip — parse errors are non-fatal)
    if let Ok(mut feat_count_buf) = {
        let mut buf = [0u8; 1];
        cursor.read_exact(&mut buf).map(|_| buf)
    } {
        let feat_count = feat_count_buf[0] as usize;
        for _ in 0..feat_count {
            let mut fid = [0u8; 1];
            if cursor.read_exact(&mut fid).is_err() { break; }
            if let Ok(flen) = read_vlq_length(&mut cursor) {
                let mut fbody = vec![0u8; flen];
                if cursor.read_exact(&mut fbody).is_err() { break; }
            } else {
                break;
            }
        }
    }

    Ok(PeerInfo {
        agent_name,
        peer_name,
        version: format!("{}.{}.{}", ver[0], ver[1], ver[2]),
        public_address,
    })
}

// ---------------------------------------------------------------------------
// Message framing
// ---------------------------------------------------------------------------

/// Build a framed P2P message.
fn build_message(magic: &[u8; 4], code: u8, body: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(9 + body.len());
    msg.extend_from_slice(magic);
    msg.push(code);
    // Body length: 4 bytes big-endian (NOT VLQ)
    msg.extend_from_slice(&(body.len() as u32).to_be_bytes());
    // Checksum: first 4 bytes of blake2b256(body)
    let hash = Blake2b256::digest(body);
    msg.extend_from_slice(&hash[..4]);
    msg.extend_from_slice(body);
    msg
}

/// Read a framed P2P message from a stream. Returns (code, body).
fn read_message(stream: &mut TcpStream, magic: &[u8; 4]) -> std::io::Result<(u8, Vec<u8>)> {
    // Read header: 4 magic + 1 code + 4 length + 4 checksum = 13 bytes
    let mut header = [0u8; 13];
    stream.read_exact(&mut header)?;

    // Verify magic
    if &header[0..4] != magic {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Bad magic: {:?}", &header[0..4]),
        ));
    }

    let code = header[4];
    let body_len = u32::from_be_bytes([header[5], header[6], header[7], header[8]]) as usize;
    let checksum = &header[9..13];

    // Sanity check: reject oversized messages (max 256KB — normal P2P messages are under 100KB)
    if body_len > 256 * 1024 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Message body too large: {} bytes", body_len),
        ));
    }

    // Read body
    let mut body = vec![0u8; body_len];
    if body_len > 0 {
        stream.read_exact(&mut body)?;
    }

    // Verify checksum
    let hash = Blake2b256::digest(&body);
    if &hash[..4] != checksum {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Checksum mismatch",
        ));
    }

    Ok((code, body))
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub agent_name: String,
    pub peer_name: String,
    pub version: String,
    pub public_address: Option<SocketAddr>,
}

#[derive(Debug, Clone, Copy)]
pub enum Network {
    Mainnet,
    Testnet,
}

impl Network {
    pub fn magic(&self) -> [u8; 4] {
        match self {
            Network::Mainnet => MAINNET_MAGIC,
            Network::Testnet => TESTNET_MAGIC,
        }
    }
}

// ---------------------------------------------------------------------------
// Peer discovery
// ---------------------------------------------------------------------------

/// Connect to a peer, perform handshake, request peers, return discovered peers.
pub fn discover_peers(addr: SocketAddr, network: Network) -> std::io::Result<Vec<SocketAddr>> {
    let mut stream = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)?;
    stream.set_read_timeout(Some(READ_TIMEOUT))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    let magic = network.magic();

    // Send handshake (raw, no message framing)
    let hs = build_handshake("blockhost-ergo", "ergo-peers", network);
    stream.write_all(&hs)?;
    stream.flush()?;

    // Read handshake response (raw, variable length)
    // Give the peer a moment to respond, then read whatever's available
    std::thread::sleep(Duration::from_millis(500));
    let mut hs_buf = vec![0u8; 4096];
    let n = stream.read(&mut hs_buf)?;
    if n == 0 {
        return Err(std::io::Error::new(std::io::ErrorKind::ConnectionReset, "Empty handshake"));
    }
    let peer_info = match parse_handshake(&hs_buf[..n]) {
        Ok(pi) => pi,
        Err(e) => {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData,
                format!("Handshake parse failed ({} bytes): {}", n, e)));
        }
    };
    eprintln!("  Connected to {} ({}) v{}", peer_info.peer_name, peer_info.agent_name, peer_info.version);

    // Send GetPeers
    let get_peers_msg = build_message(&magic, MSG_GET_PEERS, &[]);
    stream.write_all(&get_peers_msg)?;
    stream.flush()?;

    // Read response — expect Peers message
    let mut peers = Vec::new();

    // Try reading a few messages (peer might send other things first)
    for _ in 0..5 {
        match read_message(&mut stream, &magic) {
            Ok((code, body)) => {
                if code == MSG_PEERS {
                    // Parse peer list
                    let mut cursor = Cursor::new(body.as_slice());
                    if let Ok(count) = read_vlq_length(&mut cursor) {
                        for _ in 0..count {
                            if let Ok(pi) = parse_handshake_peer_entry(&mut cursor) {
                                if let Some(addr) = pi {
                                    peers.push(addr);
                                }
                            }
                        }
                    }
                    break;
                }
                // Skip other message types
            }
            Err(_) => break,
        }
    }

    let _ = stream.shutdown(std::net::Shutdown::Both);
    Ok(peers)
}

/// Parse a single peer entry from a Peers message body.
/// Returns the socket address if present, None otherwise.
fn parse_handshake_peer_entry(cursor: &mut Cursor<&[u8]>) -> std::io::Result<Option<SocketAddr>> {
    // Peer format in Peers message is the same as handshake Peer record
    let _agent = read_utf8_byte_len(cursor)?;
    // Version
    let mut ver = [0u8; 3];
    cursor.read_exact(&mut ver)?;
    let _peer_name = read_utf8_byte_len(cursor)?;

    // Public address
    let mut has_addr = [0u8; 1];
    cursor.read_exact(&mut has_addr)?;
    let mut addr: Option<SocketAddr> = None;
    if has_addr[0] != 0 {
        let mut addr_len_byte = [0u8; 1];
        cursor.read_exact(&mut addr_len_byte)?;
        let ip_len = (addr_len_byte[0] as usize).saturating_sub(4);
        let mut ip_bytes = vec![0u8; ip_len];
        cursor.read_exact(&mut ip_bytes)?;
        let mut port_bytes = [0u8; 4];
        cursor.read_exact(&mut port_bytes)?;
        let port = u32::from_be_bytes(port_bytes) as u16;

        if ip_len == 4 {
            let ip = std::net::Ipv4Addr::new(ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
            addr = Some(SocketAddr::new(ip.into(), port));
        }
    }

    // Features (skip)
    let mut feat_count = [0u8; 1];
    cursor.read_exact(&mut feat_count)?;
    for _ in 0..feat_count[0] {
        let mut fid = [0u8; 1];
        cursor.read_exact(&mut fid)?;
        let flen = read_vlq_length(cursor)?;
        let mut fbody = vec![0u8; flen];
        cursor.read_exact(&mut fbody)?;
    }

    Ok(addr)
}

// ---------------------------------------------------------------------------
// Transaction broadcast
// ---------------------------------------------------------------------------

const MSG_INV: u8 = 55;
const MSG_MODIFIER_REQUEST: u8 = 22;
const MSG_MODIFIER_RESPONSE: u8 = 33;
const TX_TYPE_ID: u8 = 2;

/// Broadcast a signed transaction to a single peer via P2P.
///
/// Flow:
///   1. Raw handshake (with session feature containing network magic)
///   2. Wait for peer's first framed message to learn the session-derived magic
///   3. Send Inv(txId) with the peer's magic
///   4. Wait for ModifierRequest → send ModifierResponse(txBytes)
///
/// Returns Ok(()) if the tx was sent, Err if the peer rejected or timed out.
pub fn broadcast_tx(addr: SocketAddr, network: Network, tx_id: &[u8; 32], tx_bytes: &[u8]) -> std::io::Result<()> {
    let mut stream = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)?;
    stream.set_read_timeout(Some(Duration::from_secs(15)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    // 1. Handshake (raw, with session feature)
    let hs = build_handshake("blockhost-ergo", "ergo-relay", network);
    stream.write_all(&hs)?;
    stream.flush()?;

    std::thread::sleep(Duration::from_millis(500));
    let mut hs_buf = vec![0u8; 4096];
    let n = stream.read(&mut hs_buf)?;
    if n == 0 {
        return Err(std::io::Error::new(std::io::ErrorKind::ConnectionReset, "Empty handshake"));
    }
    eprintln!("  Handshake OK ({} bytes)", n);

    // 2. Wait for peer's first framed message to learn the session magic.
    // After handshake, the peer usually sends SyncInfo (code 65).
    // The first 4 bytes of that message are the framing magic.
    std::thread::sleep(Duration::from_secs(3));
    let mut first_msg = vec![0u8; 4096];
    let n = stream.read(&mut first_msg)?;
    if n < 9 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData,
            format!("Expected framed message, got {} bytes", n)));
    }
    let mut peer_magic = [0u8; 4];
    peer_magic.copy_from_slice(&first_msg[..4]);
    eprintln!("  Peer magic: {:02x}{:02x}{:02x}{:02x}, first msg code: {}",
        peer_magic[0], peer_magic[1], peer_magic[2], peer_magic[3], first_msg[4]);

    // 3. Send Inv: announce we have a transaction
    let mut inv_body = Vec::new();
    inv_body.push(TX_TYPE_ID);                        // modifier type = transaction
    write_vlq(&mut inv_body, 1);                      // count = 1 (VLQ-encoded)
    inv_body.extend_from_slice(tx_id);                // 32-byte tx ID

    let inv_msg = build_message(&peer_magic, MSG_INV, &inv_body);
    stream.write_all(&inv_msg)?;
    stream.flush()?;
    eprintln!("  Sent Inv for tx {}", hex_encode(tx_id));

    // 4. Wait for ModifierRequest (peer asks for the tx)
    let mut got_request = false;
    for _ in 0..10 {
        match read_message(&mut stream, &peer_magic) {
            Ok((code, _body)) => {
                if code == MSG_MODIFIER_REQUEST {
                    got_request = true;
                    eprintln!("  Got ModifierRequest!");
                    break;
                }
                eprintln!("  Got message code {} (skipping)", code);
            }
            Err(e) => {
                eprintln!("  Read: {}", e);
                break;
            }
        }
    }

    if !got_request {
        eprintln!("  No ModifierRequest received, sending unsolicited");
    }

    // 5. Send ModifierResponse with the serialized tx
    let mut mod_body = Vec::new();
    mod_body.push(TX_TYPE_ID);                        // modifier type
    write_vlq(&mut mod_body, 1);                      // count = 1 (VLQ)
    mod_body.extend_from_slice(tx_id);                // 32-byte ID
    write_vlq(&mut mod_body, tx_bytes.len() as u64);  // body length (VLQ)
    mod_body.extend_from_slice(tx_bytes);             // serialized tx

    let mod_msg = build_message(&peer_magic, MSG_MODIFIER_RESPONSE, &mod_body);
    stream.write_all(&mod_msg)?;
    stream.flush()?;
    eprintln!("  Sent tx ({} bytes)", tx_bytes.len());

    // Give the peer a moment to process before disconnecting
    std::thread::sleep(Duration::from_secs(1));
    let _ = stream.shutdown(std::net::Shutdown::Both);
    Ok(())
}

/// Broadcast a transaction to multiple peers from a peer list file.
/// Returns the number of peers the tx was successfully sent to.
pub fn broadcast_tx_to_peers(
    peers_file: &str,
    network: Network,
    tx_id: &[u8; 32],
    tx_bytes: &[u8],
    max_peers: usize,
) -> usize {
    // Read peer list
    let peers: Vec<SocketAddr> = match std::fs::read_to_string(peers_file) {
        Ok(contents) => {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&contents) {
                json["peers"]
                    .as_array()
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str()?.parse().ok())
                            .collect()
                    })
                    .unwrap_or_default()
            } else {
                Vec::new()
            }
        }
        Err(_) => Vec::new(),
    };

    if peers.is_empty() {
        eprintln!("  No peers in {}, using seed peers", peers_file);
        // Fall back to seed peers based on network
        let seeds: Vec<SocketAddr> = match network {
            Network::Testnet => vec![
                "128.253.41.110:9020".parse().unwrap(),
                "176.9.15.237:9021".parse().unwrap(),
            ],
            Network::Mainnet => vec![
                "213.239.193.208:9030".parse().unwrap(),
                "176.9.15.237:9030".parse().unwrap(),
            ],
        };
        return broadcast_to_list(&seeds, network, tx_id, tx_bytes, max_peers);
    }

    broadcast_to_list(&peers, network, tx_id, tx_bytes, max_peers)
}

fn broadcast_to_list(
    peers: &[SocketAddr],
    network: Network,
    tx_id: &[u8; 32],
    tx_bytes: &[u8],
    max_peers: usize,
) -> usize {
    let mut sent = 0;
    for addr in peers.iter().take(max_peers) {
        eprint!("  Broadcasting to {}... ", addr);
        match broadcast_tx(*addr, network, tx_id, tx_bytes) {
            Ok(()) => {
                eprintln!("OK");
                sent += 1;
            }
            Err(e) => eprintln!("failed: {}", e),
        }
    }
    sent
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

// ---------------------------------------------------------------------------
// Simple RNG (avoid adding rand crate)
// ---------------------------------------------------------------------------

fn rand_u64() -> u64 {
    let mut buf = [0u8; 8];
    #[cfg(unix)]
    {
        use std::fs::File;
        let mut f = File::open("/dev/urandom").expect("/dev/urandom");
        f.read_exact(&mut buf).expect("read urandom");
    }
    #[cfg(not(unix))]
    {
        // Fallback: use timestamp-based seed (not cryptographic, but good enough for session IDs)
        let t = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64;
        buf = t.to_le_bytes();
    }
    u64::from_le_bytes(buf)
}
