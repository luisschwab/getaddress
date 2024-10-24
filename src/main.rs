//! getaddress
//! Builds a list of reachable Bitcoin nodes by impersonating one
//! and sending `getaddr` messages to known nodes.

#![allow(clippy::redundant_field_names)]

use clap::builder::PossibleValuesParser;
use clap::command;
use clap::Parser;
use dns_lookup::lookup_host;
use fern::colors::Color;
use fern::colors::ColoredLevelConfig;
use fern::FormatCallback;
use log::debug;
use log::error;
use log::info;
use log::warn;
use log::Record;
use rand::Rng;
use rayon::ThreadPoolBuilder;
use sha2::Digest;
use sha2::Sha256;
use std::fmt::Arguments;
use std::fs;
use std::fs::File;
use std::io::Error;
use std::io::Read;
use std::io::Write;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::net::TcpStream;
use std::path::Path;
use std::path::PathBuf;
use std::str;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::time::Instant;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

static RUNNING: AtomicBool = AtomicBool::new(true);

const REQUEST_TIMEOUT: u64 = 2;
const OUTPUT_DIR: &str = "output";

const PROTOCOL_VERSION: u32 = 70013;

const MAGIC_MAINNET: &[u8] = &[0xF9, 0xBE, 0xB4, 0xD9];
const MAGIC_TESTNET: &[u8] = &[0x1C, 0x16, 0x3F, 0x28];
const MAGIC_SIGNET: &[u8] = &[0x0A, 0x03, 0xCF, 0x40]; // This is the magic for the default signet; every custom signet will have a different magic
const MAGIC_REGTEST: &[u8] = &[0xFA, 0xBF, 0xB5, 0xDA];

const PORT_MAINNET: u16 = 8333;
const PORT_TESTNET: u16 = 48333;
const PORT_SIGNET: u16 = 38333;
const PORT_REGTEST: u16 = 18444;

const SEEDS_MAINNET: &[&str] = &[
    "dnsseed.bitcoin.dashjr.org",
    "dnsseed.bluematt.me",
    "dnsseed.emzy.de",
    "seed.bitcoin.jonasschnelli.ch",
    "seed.bitcoin.sipa.be",
    "seed.bitcoin.sprovoost.nl",
    "seed.bitcoin.wiz.biz",
    "seed.bitcoinstats.com",
    "seed.bitnodes.io",
    "seed.btc.petertodd.net",
    "seed.btc.petertodd.org",
    "seed.flowee.cash",
    "seed.mainnet.achownodes.xyz",
];

const SEEDS_TESTNET: &[&str] = &[
    "seed.testnet4.bitcoin.sprovoost.nl",
    "seed.testnet4.wiz.biz",
];

const SEEDS_SIGNET: &[&str] = &[
    "seed.signet.achownodes.xyz",
    "seed.signet.bitcoin.sprovoost.nl",
];

#[derive(Parser, Debug)]
#[command(version, about="getaddress\nA P2P crawler for all Bitcoin networks", long_about = None)]
struct Args {
    #[arg(long, help="Network to crawl", value_parser = PossibleValuesParser::new(["mainnet", "testnet", "signet", "regtest"]))]
    network: Option<String>,

    #[arg(long, help = "Wheter to log below info")]
    debug: Option<bool>,
}

#[derive(Debug, Hash, Eq, PartialEq, PartialOrd, Ord)]
struct Peer {
    ip: IpAddr,
    port: u16,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let mut rng = rand::thread_rng();

    match &args.debug {
        Some(true) => setup_logger(true).unwrap(),
        Some(false) | None => setup_logger(false).unwrap(),
    };

    #[rustfmt::skip]
    let (network_magic, port, dns_seeds, filename) = match &args.network {
        Some(network) => match network.as_str() {
            "mainnet" => (MAGIC_MAINNET, PORT_MAINNET, SEEDS_MAINNET, "mainnet-nodes.txt"),
            "testnet" => (MAGIC_TESTNET,PORT_TESTNET,SEEDS_TESTNET, "testnet-nodes.txt"),
            "signet" => (MAGIC_SIGNET, PORT_SIGNET, SEEDS_SIGNET, "signet-nodes.txt"),
            "regtest" => (MAGIC_REGTEST,PORT_REGTEST, &["localhost"][..], "regtest-nodes.txt"),
            _ => std::process::exit(1),
        },
        None => (MAGIC_MAINNET, PORT_MAINNET, SEEDS_MAINNET, "mainnet-nodes.txt"),
    };

    let t_0 = Instant::now();
    let n_threads = std::cmp::max(1, num_cpus::get() - 2);

    // Pick a random seed node from DNS seeder's record
    let dns_seeder = dns_seeds[rng.gen_range(0..dns_seeds.len())];
    let seeds = lookup_host(dns_seeder).unwrap();

    let mut peers: Vec<Peer> = Vec::new();

    for seed in seeds {
        peers.push(Peer {
            ip: seed,
            port: port,
        });
    }

    ctrlc::set_handler(move || {
        info!("received SIGINT, shutting down...");
        RUNNING.store(false, Ordering::SeqCst);
    })?;

    // run get_address on `$(( $nproc) - 2 ))` threads
    let peers = Arc::new(Mutex::new(peers));
    let pool = ThreadPoolBuilder::new()
        .num_threads(n_threads)
        .build()
        .unwrap();

    pool.scope(|s| {
        while RUNNING.load(Ordering::SeqCst) {
            let peers_clone = Arc::clone(&peers);

            s.spawn(move |_| {
                let mut rng = rand::thread_rng();

                while RUNNING.load(Ordering::SeqCst) {
                    let peer = {
                        let peers_guard = peers_clone.lock().unwrap();
                        if peers_guard.is_empty() {
                            break; // If no peers, exit the loop
                        }
                        let peer = &peers_guard[rng.gen_range(0..peers_guard.len())];
                        (peer.ip, peer.port)
                    };

                    get_address(peer.0, peer.1, network_magic, peers_clone.clone());
                }
            });

            std::thread::sleep(Duration::from_millis(100));
        }
    });

    let mut peers = match Arc::try_unwrap(peers) {
        Ok(mutex) => match mutex.into_inner() {
            Ok(peers) => peers,
            Err(e) => {
                error!("failed to unwrap peers mutex: {}", e);
                std::process::exit(-1);
            }
        },
        Err(e) => {
            error!(
                "failed to unwrap Arc: arc still has {} strong references",
                Arc::strong_count(&e)
            );
            std::process::exit(-1);
        }
    };

    peers.sort();
    peers.dedup();

    let delta = t_0.elapsed().as_secs();
    let hour = delta / 3600;
    let minute = (delta % 3600) / 60;
    let second = delta % 60;

    info!(
        "found {} peers in {:02}h{:02}m{:02}s",
        peers.len(),
        hour,
        minute,
        second
    );

    let path = Path::new(OUTPUT_DIR).join(filename);
    match dump_to_file(&path, &peers) {
        Ok(_) => info!("wrote {} peers to {}", peers.len(), path.display()),
        Err(e) => error!("failed to write peers to {}: {}", filename, e),
    };

    info!("done!");

    Ok(())
}

/// Perform a handshake, return success status
fn handshake(stream: &mut TcpStream, network_magic: &[u8]) -> Result<bool, Error> {
    let (peer_ip, peer_port) = match stream.peer_addr() {
        Ok(addr) => (addr.ip(), addr.port()),
        Err(e) => return Err(e),
    };

    info!("starting handshake with {}:{}", peer_ip, peer_port);

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

    info!("successful handshake with {}:{}", peer_ip, peer_port);
    Ok(true)
}

fn get_address(
    peer_ip: IpAddr,
    peer_port: u16,
    network_magic: &[u8],
    peers: Arc<Mutex<Vec<Peer>>>,
) {
    let socket_addr = SocketAddr::new(peer_ip, peer_port);
    match TcpStream::connect_timeout(&socket_addr, Duration::from_secs(REQUEST_TIMEOUT)) {
        Err(e) => warn!(
            "failed to connect to {}:{}: {}",
            socket_addr.ip(),
            socket_addr.port(),
            e
        ),
        Ok(mut stream) => {
            // Set read and write timeouts
            if let Err(e) = stream.set_read_timeout(Some(Duration::from_secs(REQUEST_TIMEOUT))) {
                error!("failed to set read timeout: {}", e);
                return;
            }
            if let Err(e) = stream.set_write_timeout(Some(Duration::from_secs(REQUEST_TIMEOUT))) {
                error!("failed to set write timeout: {}", e);
                return;
            }

            match handshake(&mut stream, network_magic) {
                Err(e) => warn!("an error occurred while making the handshake: {}", e),
                Ok(false) => (),
                Ok(true) => {
                    let send_getaddr = make_packet("getaddr", None, network_magic);
                    match stream.write_all(&send_getaddr) {
                        Ok(_) => debug!("sent getaddr to {}:{}", peer_ip, peer_port),
                        Err(e) => {
                            warn!("failed to send getaddr to {}:{}: {}", peer_ip, peer_port, e);
                            return;
                        }
                    }

                    let mut recv_command = "";
                    while recv_command != "addr" {
                        match read_message(&mut stream) {
                            Ok((command, mut payload)) => {
                                if command == "addr" {
                                    recv_command = "addr";
                                    debug!("received {} from {}:{}", command, peer_ip, peer_port);
                                    let new_peers =
                                        parse_addr_response(&mut payload, peer_ip, peer_port);

                                    debug!("added {} peers to db", new_peers.len());

                                    // only add new peers if they are responsive (make a successful handshake)
                                    for peer in new_peers {
                                        // catch SIGINT
                                        if !RUNNING.load(Ordering::Relaxed) {
                                            return;
                                        }

                                        let socket_addr = SocketAddr::new(peer.ip, peer.port);
                                        match TcpStream::connect_timeout(
                                            &socket_addr,
                                            Duration::from_secs(REQUEST_TIMEOUT),
                                        ) {
                                            Ok(mut stream) => {
                                                if let Ok(true) =
                                                    handshake(&mut stream, network_magic)
                                                {
                                                    match peer.ip {
                                                        IpAddr::V4(ip) => info!(
                                                            "new peer discovered @ {}:{}",
                                                            ip, peer.port
                                                        ),
                                                        IpAddr::V6(ip) => info!(
                                                            "new peer discovered @ [{}]:{}",
                                                            ip, peer.port
                                                        ),
                                                    }

                                                    if let Ok(mut peers_guard) = peers.lock() {
                                                        peers_guard.push(peer);
                                                    }
                                                }
                                            }
                                            _ => continue,
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                warn!(
                                    "error reading message from {}:{}: {}",
                                    peer_ip, peer_port, e
                                );
                                return;
                            }
                        }
                    }
                }
            }
        }
    }
}

fn make_header(command: &str, network_magic: &[u8], payload: Vec<u8>) -> Vec<u8> {
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

fn make_version_payload(peer_ip: IpAddr, peer_port: u16) -> Vec<u8> {
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
fn make_packet(command: &str, payload: Option<Vec<u8>>, network_magic: &[u8]) -> Vec<u8> {
    let mut packet: Vec<u8> = Vec::new();

    let payload = payload.unwrap_or_default();
    let header = make_header(command, network_magic, payload.clone());

    packet.extend(header);
    packet.extend(payload);

    packet
}

/// Reads a message from the stream, return the command and payload
fn read_message(stream: &mut TcpStream) -> Result<(String, Vec<u8>), Error> {
    let mut header = vec![0u8; 24];
    stream.read_exact(&mut header)?;

    let command = parse_header(&header);

    let payload_len = u32::from_le_bytes([header[16], header[17], header[18], header[19]]) as usize;
    let mut payload = vec![0u8; payload_len];
    let _ = stream.read_exact(&mut payload);

    Ok((command.to_string(), payload))
}

/// Parse a message header, return the command
fn parse_header(header: &[u8]) -> String {
    let command_bytes = &header[4..16];

    let end_pos = command_bytes.iter().position(|&x| x == 0x00).unwrap_or(12);

    command_bytes[..end_pos]
        .iter()
        .map(|&b| if b.is_ascii() { b as char } else { '?' })
        .collect()
}

/// Parse an `addr` message, return new peers
fn parse_addr_response(payload: &mut Vec<u8>, peer_ip: IpAddr, peer_port: u16) -> Vec<Peer> {
    let mut new_peers: Vec<Peer> = Vec::new();

    // each element from addr is 30 bytes long
    let addr_count = decode_compact_size(payload) / 30;
    debug!(
        "received {} addresses from {}:{}",
        addr_count, peer_ip, peer_port
    );

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
                (ip[0] as u16) << 8 | (ip[1] as u16),
                (ip[2] as u16) << 8 | (ip[3] as u16),
                (ip[4] as u16) << 8 | (ip[5] as u16),
                (ip[6] as u16) << 8 | (ip[7] as u16),
                (ip[8] as u16) << 8 | (ip[9] as u16),
                (ip[10] as u16) << 8 | (ip[11] as u16),
                (ip[12] as u16) << 8 | (ip[13] as u16),
                (ip[14] as u16) << 8 | (ip[15] as u16),
            ))
        };

        let port = (port[0] as u16) << 8 | (port[1] as u16);

        let peer = Peer {
            ip: ip_addr,
            port: port,
        };

        new_peers.push(peer);
    }

    new_peers
}

/// Dumps the Peer vector to a file
fn dump_to_file(path: &PathBuf, peers: &Vec<Peer>) -> Result<(), Error> {
    fs::create_dir_all(OUTPUT_DIR)?;

    if path.exists() {
        match fs::remove_file(path) {
            Ok(_) => {}
            Err(e) => {
                error!("error while deleting {:?}: {}", path, e);
            }
        };
    }

    let mut file = File::create(path)?;

    for peer in peers {
        writeln!(file, "{}:{}", peer.ip, peer.port)?;
    }

    Ok(())
}

/// Takes an IpAddr enum, returns an IPv6 or IPv6-wrapped-IPv4 slice
fn wrap_in_ipv6(ip: IpAddr) -> [u8; 16] {
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

fn hash256(data: Vec<u8>) -> [u8; 32] {
    let first_hash = Sha256::digest(&data);
    let second_hash = Sha256::digest(first_hash);
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&second_hash);
    digest
}

fn pad_vector(data: Vec<u8>, total_size: usize) -> Vec<u8> {
    let mut padded = data.clone();
    padded.resize(total_size, 0);
    padded
}

///  <=FC – This byte (0 ~ 252)
///  =FD – The next two bytes (253 ~ 65_535)
///  =FE – The next four bytes (65_536 ~ 4_294_967_295)
///  =FF – The next eight bytes (4_294_967_296 ~ 18_446_744_073_709_551_615)
fn decode_compact_size(buffer: &mut Vec<u8>) -> usize {
    let first = buffer.remove(0);
    match first {
        0..0xFD => first as usize,
        0xFD => (((buffer.remove(0) as u64) << 8) | (buffer.remove(0) as u64)) as usize,
        0xFE => {
            (((buffer.remove(0) as u64) << 24)
                | ((buffer.remove(0) as u64) << 16)
                | ((buffer.remove(0) as u64) << 8)
                | (buffer.remove(0) as u64)) as usize
        }
        0xFF => {
            (((buffer.remove(0) as u64) << 56)
                | ((buffer.remove(0) as u64) << 48)
                | ((buffer.remove(0) as u64) << 40)
                | ((buffer.remove(0) as u64) << 32)
                | ((buffer.remove(0) as u64) << 24)
                | ((buffer.remove(0) as u64) << 16)
                | ((buffer.remove(0) as u64) << 8)
                | (buffer.remove(0) as u64)) as usize
        }
    }
}

fn setup_logger(debug: bool) -> Result<(), fern::InitError> {
    let colors = ColoredLevelConfig::new()
        .error(Color::Red)
        .warn(Color::Yellow)
        .info(Color::Green)
        .debug(Color::Blue);

    let formatter = |use_colors: bool| {
        move |out: FormatCallback, message: &Arguments, record: &Record| {
            out.finish(format_args!(
                "[{} {} {}] {}",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                match use_colors {
                    true => colors.color(record.level()).to_string(),
                    false => record.level().to_string(),
                },
                record.target(),
                message
            ))
        }
    };

    let mut dispatchers = fern::Dispatch::new();
    let stdout_dispatcher = fern::Dispatch::new()
        .format(formatter(true))
        .level(if debug {
            log::LevelFilter::Debug
        } else {
            log::LevelFilter::Info
        })
        .chain(std::io::stdout());

    dispatchers = dispatchers.chain(stdout_dispatcher);

    dispatchers.apply()?;

    Ok(())
}
