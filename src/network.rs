//! Network related functions

use std::error::Error;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, TcpStream};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dns_lookup::lookup_host;
use log::{debug, error, info};
use rand::seq::SliceRandom;

use crate::util::{decode_compact_size, hash256, pad_vector};

pub const REQUEST_TIMEOUT: u64 = 2; // seconds
const PROTOCOL_VERSION: u32 = 70013;

#[derive(Clone, Debug, Hash, Eq, PartialEq, PartialOrd, Ord)]
pub struct Peer {
    pub ip: IpAddr,
    pub port: u16,
    pub asn: Option<u32>,
    pub org: Option<String>,
}

/// Query DNS seeds for potential peers
pub fn query_dns_seeds(dns_seeds: &[&str], port: u16, network_magic: &[u8]) -> Result<Vec<Peer>, Box<dyn std::error::Error>> {
    const N_PEERS: usize = 10;
    const N_SEEDERS: usize = 3;

    let mut rng = rand::thread_rng();
    let mut seed_candidates = Vec::new();
    let mut validated_peers = Vec::new();

    for &dns_seeder in dns_seeds.iter().take(N_SEEDERS) {
        match lookup_host(dns_seeder) {
            Ok(seeds) => {
                for seed in seeds {
                    seed_candidates.push((seed, port));
                }

                if seed_candidates.len() >= 20 {
                    break;
                }
            }
            Err(e) => {
                debug!("failed to resolve DNS seed {}: {}", dns_seeder, e);
            }
        }
    }

    if seed_candidates.is_empty() {
        return Err("failed to resolve any DNS seeds".into());
    }

    info!("found {} potential seed nodes, making handshakes...", seed_candidates.len());

    seed_candidates.shuffle(&mut rng);

    let mut successful = 0;
    for (ip, port) in seed_candidates {
        match TcpStream::connect_timeout(&(ip, port).into(), Duration::from_secs(REQUEST_TIMEOUT)) {
            Ok(mut stream) => match handshake(&mut stream, network_magic, 0 /* thread_id */) {
                Ok(true) => {
                    validated_peers.push(Peer {
                        ip,
                        port,
                        asn: None,
                        org: None,
                    });

                    successful += 1;
                    if successful >= N_PEERS {
                        // `N_PEERS` is enough to bootstrap the process
                        break;
                    }
                }
                Ok(false) => {
                    debug!("handshake failed with seed node {}:{}", ip, port);
                }
                Err(e) => {
                    debug!("error during handshake with seed node {}:{}: {}", ip, port, e);
                }
            },
            Err(e) => {
                debug!("failed to connect to seed node {}:{}: {}", ip, port, e);
            }
        }
    }

    if validated_peers.is_empty() {
        return Err("failed to connect to any seed nodes".into());
    }

    info!("successful handshakes with {} seed nodes", validated_peers.len());

    Ok(validated_peers)
}

/// Perform a handshake, return success status
pub fn handshake(stream: &mut TcpStream, network_magic: &[u8], thread_id: usize) -> Result<bool, Box<dyn Error>> {
    let addr = stream.peer_addr()?;
    let peer_ip = addr.ip();
    let peer_port = addr.port();

    match peer_ip {
        IpAddr::V4(_) => info!("[thread {}] starting handshake with {}:{}", thread_id, peer_ip, peer_port),
        IpAddr::V6(_) => info!("[thread {}] starting handshake with [{}]:{}", thread_id, peer_ip, peer_port),
    }

    // Set read and write timeouts
    if let Err(e) = stream.set_read_timeout(Some(Duration::from_secs(REQUEST_TIMEOUT))) {
        error!("failed to set read timeout: {}", e);
        return Ok(false);
    }
    if let Err(e) = stream.set_write_timeout(Some(Duration::from_secs(REQUEST_TIMEOUT))) {
        error!("failed to set write timeout: {}", e);
        return Ok(false);
    }

    // send `version`
    let version_payload = make_version_payload(peer_ip, peer_port);
    let send_version = make_packet("version", Some(version_payload), network_magic);
    let sent_count = stream.write_all(&send_version);
    match sent_count {
        Ok(_) => debug!("sent version to {}:{}", peer_ip, peer_port),
        Err(_) => {
            error!("failed handshake with {}:{}", peer_ip, peer_port);
            return Ok(false);
        }
    }

    // recv `version`
    let (command, _) = read_message(stream)?;
    if command == "version" {
        debug!("received version from {}:{}", peer_ip, peer_port);
    } else {
        error!("failed handshake with {}:{}", peer_ip, peer_port);
        return Ok(false);
    }

    // recv `verack`
    let (command, _) = read_message(stream)?;
    if command == "verack" {
        debug!("received verack from {}:{}", peer_ip, peer_port);
    } else {
        debug!("failed handshake with {}:{}", peer_ip, peer_port);
        return Ok(false);
    }

    // send `verack`
    let send_verack = make_packet("verack", None, network_magic);
    let _ = stream.write_all(&send_verack);
    debug!("sent verack to {}:{}", peer_ip, peer_port);

    match peer_ip {
        IpAddr::V4(_) => info!("[thread {}] successful handshake with {}:{}", thread_id, peer_ip, peer_port),
        IpAddr::V6(_) => info!("[thread {}] successful handshake with [{}]:{}", thread_id, peer_ip, peer_port),
    }

    Ok(true)
}

/// Makes a header given a command, network magic and payload
pub fn make_header(command: &str, network_magic: &[u8], payload: Vec<u8>) -> Vec<u8> {
    let mut header: Vec<u8> = Vec::new();

    // network magic, 4 bytes
    header.extend_from_slice(network_magic);
    // command ascii-bytes, 12 bytes
    header.extend_from_slice(pad_vector(command.as_bytes().to_vec(), 12).as_slice());
    // payload size, 4 bytes LE
    header.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    // checksum, 4 bytes
    header.extend_from_slice(&hash256(payload)[..4]);

    header
}

pub fn make_version_payload(peer_ip: IpAddr, peer_port: u16) -> Vec<u8> {
    let mut version_payload: Vec<u8> = Vec::new();

    // protocol version, 4 bytes LE
    version_payload.extend_from_slice(PROTOCOL_VERSION.to_le_bytes().as_slice());
    // services, 8 byte LE bitfield
    version_payload.extend_from_slice(&(0_u64).to_le_bytes());
    // UNIX time, 8 bytes LE
    let unix_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("1.21 gigawatts! 1.21 gigawatts. Great Scott!")
        .as_secs();
    version_payload.extend_from_slice(&(unix_time).to_le_bytes());
    // remote services, 8 byte LE bitfield
    version_payload.extend_from_slice(&(0_u64).to_le_bytes());
    // remote ip, 16 bytes
    version_payload.extend_from_slice(&wrap_in_ipv6(peer_ip));
    // remote port, 2 bytes
    version_payload.extend_from_slice(&(peer_port).to_be_bytes());
    // local services, 8 byte LE bitfield
    version_payload.extend_from_slice(&(0_u64).to_le_bytes());
    // local ip, 16 bytes
    let localhost = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    version_payload.extend_from_slice(&wrap_in_ipv6(localhost));
    // local port, 2 bytes
    version_payload.extend_from_slice(&(peer_port).to_be_bytes());
    // nonce, 8 bytes LE
    version_payload.extend_from_slice(&(0_u64).to_le_bytes());
    // user agent, compact size, ascii (0x00)
    version_payload.extend_from_slice(&(0_u8).to_le_bytes());
    // last block, 4 bytes
    version_payload.extend_from_slice(&(0_u32).to_le_bytes());

    version_payload
}

/// Make a packet (header + payload)
pub fn make_packet(command: &str, payload: Option<Vec<u8>>, network_magic: &[u8]) -> Vec<u8> {
    let mut packet: Vec<u8> = Vec::new();

    let payload = payload.unwrap_or_default();
    let header = make_header(command, network_magic, payload.clone());

    packet.extend(header);
    packet.extend(payload);

    packet
}

/// Reads a message from the stream, return the command and payload
pub fn read_message(stream: &mut TcpStream) -> Result<(String, Vec<u8>), Box<dyn Error>> {
    let mut header = vec![0u8; 24];
    stream.read_exact(&mut header)?;

    let command = parse_header(&header);

    let payload_len = u32::from_le_bytes([header[16], header[17], header[18], header[19]]) as usize;
    let mut payload = vec![0u8; payload_len];
    let _ = stream.read_exact(&mut payload);

    Ok((command.to_string(), payload))
}

/// Parse a message header, return the command
pub fn parse_header(header: &[u8]) -> String {
    let command_bytes = &header[4..16];

    let end_pos = command_bytes.iter().position(|&x| x == 0x00).unwrap_or(12);

    command_bytes[..end_pos]
        .iter()
        .map(|&b| if b.is_ascii() { b as char } else { '?' })
        .collect()
}

/// Parse an `addr` message, return new peers
pub fn parse_addr_response(payload: &mut Vec<u8>, peer_ip: IpAddr, peer_port: u16) -> Vec<Peer> {
    if payload.is_empty() {
        return vec![];
    }

    let mut new_peers: Vec<Peer> = Vec::new();

    // each element from addr is 30 bytes long
    let addr_count = decode_compact_size(payload) / 30;
    debug!("received {} addresses from {}:{}", addr_count, peer_ip, peer_port);

    for _ in 0..addr_count {
        if payload.len() < 30 {
            return new_peers;
        }

        let network_ip: Vec<u8> = payload.drain(..30).collect();

        let ip = &network_ip[12..28];
        let port = &network_ip[28..30];

        let ip_addr: IpAddr = if ip[..10] == [0; 10] && ip[10] == 0xff && ip[11] == 0xff {
            IpAddr::V4(Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]))
        } else {
            IpAddr::V6(Ipv6Addr::new(
                ((ip[0] as u16) << 8) | (ip[1] as u16),
                ((ip[2] as u16) << 8) | (ip[3] as u16),
                ((ip[4] as u16) << 8) | (ip[5] as u16),
                ((ip[6] as u16) << 8) | (ip[7] as u16),
                ((ip[8] as u16) << 8) | (ip[9] as u16),
                ((ip[10] as u16) << 8) | (ip[11] as u16),
                ((ip[12] as u16) << 8) | (ip[13] as u16),
                ((ip[14] as u16) << 8) | (ip[15] as u16),
            ))
        };

        let port = ((port[0] as u16) << 8) | (port[1] as u16);

        let peer = Peer {
            ip: ip_addr,
            port: port,
            asn: None,
            org: None,
        };

        new_peers.push(peer);
    }

    new_peers
}

/// Takes an IpAddr enum, returns an IPv6 or IPv6-wrapped-IPv4 slice
pub fn wrap_in_ipv6(ip: IpAddr) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    match ip {
        IpAddr::V4(addr) => {
            bytes[10] = 0xff;
            bytes[11] = 0xff;
            bytes[12..].copy_from_slice(&addr.octets());
        }
        IpAddr::V6(addr) => {
            bytes.copy_from_slice(&addr.octets());
        }
    }
    bytes
}
