//! getaddress
//! Builds a list of reachable Bitcoin nodes by impersonating
//! one and sending `getaddr` messages to known nodes.

#![allow(unused_parens)]
#![allow(clippy::redundant_field_names)]

use std::collections::HashMap;
use std::fmt::Arguments;
use std::io::Write;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::path::Path;
use std::str;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use clap::builder::PossibleValuesParser;
use clap::{command, Parser};
use dns_lookup::lookup_host;
use fern::colors::{Color, ColoredLevelConfig};
use fern::FormatCallback;
use log::{debug, error, info, warn, Record};
use rand::Rng;
use rayon::ThreadPoolBuilder;
use tokio::sync::broadcast;

use network::{handshake, make_packet, parse_addr_response, read_message, Peer, REQUEST_TIMEOUT};
use util::{dump_to_file, fill_asn};

mod network;
mod util;

static RUNNING: AtomicBool = AtomicBool::new(true);

const OUTPUT_DIR: &str = "output";

const MAGIC_MAINNET: &[u8] = &[0xF9, 0xBE, 0xB4, 0xD9];
const MAGIC_TESTNET: &[u8] = &[0x1C, 0x16, 0x3F, 0x28];
const MAGIC_SIGNET: &[u8] = &[0x0A, 0x03, 0xCF, 0x40]; // This is the magic for the default signet; every custom signet will have a different magic
const MAGIC_REGTEST: &[u8] = &[0xFA, 0xBF, 0xB5, 0xDA];

const PORT_MAINNET: u16 = 8333;
const PORT_TESTNET: u16 = 48333;
const PORT_SIGNET: u16 = 38333;
const PORT_REGTEST: u16 = 18444;

const SEEDS_MAINNET: &[&str] = &[
    "seed.bitcoin.luisschwab.com",
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
#[rustfmt::skip]
const SEEDS_TESTNET: &[&str] = &[
    "seed.testnet4.bitcoin.sprovoost.nl",
    "seed.testnet4.wiz.biz"
];
#[rustfmt::skip]
const SEEDS_SIGNET: &[&str] = &[
    "seed.signet.achownodes.xyz",
    "seed.signet.bitcoin.sprovoost.nl"
];

#[derive(Parser, Debug)]
#[command(version, name="getaddress", about="getaddress\nA P2P crawler for all Bitcoin networks", long_about = None)]
struct Args {
    #[arg(long, alias="net", default_value_t=("mainnet".to_string()), help="Network to crawl", value_parser = PossibleValuesParser::new(["mainnet", "testnet4", "signet", "regtest"]))]
    network: String,

    #[rustfmt::skip]
    #[arg(long, default_value_t = true, help = "Wheter to query GeoLite's ASN DB")]
    query_asn: bool,

    #[arg(long, default_value_t = false, help = "Wheter to log below info")]
    debug: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let mut rng = rand::thread_rng();

    setup_logger(args.debug).unwrap();

    let network = &args.network;
    let timestamp = chrono::Local::now().format("%Y%m%d%H%M%S");
    #[rustfmt::skip]
    let (network_magic, port, dns_seeds, filename) = match network.as_str() {
        "mainnet" => (MAGIC_MAINNET, PORT_MAINNET, SEEDS_MAINNET, format!("mainnet-{}.txt", timestamp)),
        "testnet4" => (MAGIC_TESTNET, PORT_TESTNET, SEEDS_TESTNET, format!("testnet4-{}.txt", timestamp)),
        "signet" => (MAGIC_SIGNET, PORT_SIGNET, SEEDS_SIGNET, format!("signet-{}.txt", timestamp)),
        "regtest" => (MAGIC_REGTEST, PORT_REGTEST, &["localhost"][..], format!("regtest-{}.txt", timestamp)),
        _ => (MAGIC_MAINNET, PORT_MAINNET, SEEDS_MAINNET, format!("mainnet-{}.txt", timestamp)),
    };

    let t_0 = Instant::now();
    let n_threads = std::cmp::max(1, num_cpus::get());

    // Pick a random seed node from DNS seeder's record
    let dns_seeder = dns_seeds[rng.gen_range(0..dns_seeds.len())];
    let seeds = lookup_host(dns_seeder).expect("Failure on name resolution");

    let mut peers: Vec<Peer> = Vec::new();

    for seed in seeds {
        peers.push(Peer {
            ip: seed,
            port: port,
            asn: None,
            org: None,
        });
    }

    let (shutdown_tx, _) = broadcast::channel(n_threads);

    ctrlc::set_handler({
        let shutdown_tx = shutdown_tx.clone();
        move || {
            info!("received SIGINT: shutting down, this may take a while...");
            RUNNING.store(false, Ordering::SeqCst);
            let _ = shutdown_tx.send(());
        }
    })?;

    // run get_address on multiple threads
    let peers = Arc::new(Mutex::new(peers));
    let pool = ThreadPoolBuilder::new().num_threads(n_threads).build().unwrap();

    pool.scope(|s| {
        while RUNNING.load(Ordering::SeqCst) {
            let peers_clone = Arc::clone(&peers);

            let mut shutdown_rx = shutdown_tx.subscribe();

            s.spawn(move |_| {
                let mut rng = rand::thread_rng();

                while RUNNING.load(Ordering::SeqCst) {
                    // try to receive shutdown signal
                    if shutdown_rx.try_recv().is_ok() {
                        return;
                    }

                    let peer = {
                        let peers_guard = peers_clone.lock().unwrap();
                        if peers_guard.is_empty() {
                            break;
                        }
                        let peer = &peers_guard[rng.gen_range(0..peers_guard.len())];
                        (peer.ip, peer.port)
                    };

                    if !RUNNING.load(Ordering::SeqCst) {
                        return;
                    }

                    get_address(peer.0, peer.1, network_magic, peers_clone.clone());
                }
            });

            // throttle task spawning
            std::thread::sleep(Duration::from_millis(100));
        }
    });

    let mut peers = match Arc::try_unwrap(peers) {
        Ok(mutex) => match mutex.into_inner() {
            Ok(peers) => peers,
            Err(e) => {
                error!("failed to unwrap peer's vector mutex: {}", e);
                std::process::exit(-1);
            }
        },
        Err(e) => {
            error!("failed to unwrap Arc: arc still has {} strong references", Arc::strong_count(&e));
            std::process::exit(-1);
        }
    };

    info!("deduping peer list...");
    let peers_len_before = peers.len();
    peers.sort();
    peers.dedup();
    let peers_len_after = peers.len();
    info!("deduped peer list: from {} to {} peers", peers_len_before, peers_len_after);

    let delta = t_0.elapsed().as_secs();
    let hour = delta / 3600;
    let minute = (delta % 3600) / 60;
    let second = delta % 60;

    info!(
        "discovered {} unique peers in {:02}h{:02}m{:02}s",
        peers.len(),
        hour,
        minute,
        second
    );

    if args.query_asn {
        fill_asn(&mut peers);

        // compile ASN node amounts and share
        let mut asn_nodes: HashMap<String, u32> = HashMap::new();

        for peer in &peers {
            let key = String::from(format!(
                "AS{} {}",
                peer.asn.unwrap_or(0),
                peer.org.clone().unwrap_or("NO DATA".to_string())
            ));
            *asn_nodes.entry(key).or_insert(1) += 1;
        }

        let mut sorted_asn_nodes: Vec<_> = asn_nodes.into_iter().collect();
        sorted_asn_nodes.sort_by(|a, b| b.1.cmp(&a.1));

        info!("AS node hosting stakes:");

        let mut i = 0;
        let mut accumulated = 0.0;
        for (k, v) in sorted_asn_nodes {
            let stake = (100.0 * v as f64 / peers.len() as f64);
            accumulated += stake;

            info!("{}: {} ({:.2}%)", k, v, stake);

            if i >= 25 || accumulated > 80.0 {
                info!("OTHERS: ({:.2}%)", 100.0 - accumulated);

                break;
            }
            i += 1;
        }
    }

    let path = Path::new(OUTPUT_DIR).join(network);
    match dump_to_file(&path, &filename, &peers) {
        Ok(_) => info!("{} peers written to {:?}", peers.len(), path.join(filename)),
        Err(e) => error!("failed to write peers to {:?}: {}", path, e),
    };

    info!("done!");

    Ok(())
}

fn get_address(peer_ip: IpAddr, peer_port: u16, network_magic: &[u8], peers: Arc<Mutex<Vec<Peer>>>) {
    if !RUNNING.load(Ordering::SeqCst) {
        return;
    }

    let socket_addr = SocketAddr::new(peer_ip, peer_port);
    match TcpStream::connect_timeout(&socket_addr, Duration::from_secs(REQUEST_TIMEOUT)) {
        Err(e) => warn!("failed to connect to {}:{}: {}", socket_addr.ip(), socket_addr.port(), e),
        Ok(mut stream) => {
            // catch SIGINT
            if !RUNNING.load(Ordering::Relaxed) {
                return;
            }

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
                        // catch SIGINT
                        if !RUNNING.load(Ordering::Relaxed) {
                            return;
                        }
                        match read_message(&mut stream) {
                            Ok((command, mut payload)) => {
                                if command == "addr" {
                                    recv_command = "addr";
                                    debug!("received {} from {}:{}", command, peer_ip, peer_port);
                                    let new_peers = parse_addr_response(&mut payload, peer_ip, peer_port);

                                    for peer in new_peers {
                                        // catch SIGINT
                                        if !RUNNING.load(Ordering::Relaxed) {
                                            return;
                                        }

                                        // only add new peers if they are responsive (make a successful handshake)
                                        let socket_addr = SocketAddr::new(peer.ip, peer.port);
                                        match TcpStream::connect_timeout(&socket_addr, Duration::from_secs(REQUEST_TIMEOUT)) {
                                            Ok(mut stream) => {
                                                if let Ok(true) = handshake(&mut stream, network_magic) {
                                                    if let Ok(mut peers_guard) = peers.lock() {
                                                        match peer.ip {
                                                            IpAddr::V4(ip) => {
                                                                info!("new peer discovered @ {}:{}", ip, peer.port)
                                                            }
                                                            IpAddr::V6(ip) => {
                                                                info!("new peer discovered @ [{}]:{}", ip, peer.port)
                                                            }
                                                        }
                                                        peers_guard.push(peer);

                                                        if (peers_guard.len() % 5 == 0) {
                                                            info!("{} non-unique peers in the db", peers_guard.len());
                                                        }
                                                    }
                                                }
                                            }
                                            _ => continue,
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                warn!("error reading message from {}:{}: {}", peer_ip, peer_port, e);
                                return;
                            }
                        }
                    }
                }
            }
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
        .level_for("maxminddb", log::LevelFilter::Warn)
        .format(formatter(true))
        .level(if debug { log::LevelFilter::Debug } else { log::LevelFilter::Info })
        .chain(std::io::stdout());

    dispatchers = dispatchers.chain(stdout_dispatcher);

    dispatchers.apply()?;

    Ok(())
}
