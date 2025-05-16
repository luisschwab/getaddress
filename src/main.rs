//! `getaddress`
//!
//! Builds a list of reachable Bitcoin nodes by impersonating
//! one and recursively sending `getaddr` messages to other known nodes.

#![allow(unused_parens)]
#![allow(clippy::redundant_field_names)]

use std::{
    collections::{HashMap, HashSet},
    io::Write,
    net::{IpAddr, SocketAddr, TcpStream},
    path::Path,
    str,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use anyhow::Result;
use bitcoin::{network::Network, p2p::Magic};
use clap::{builder::PossibleValuesParser, command, Parser};
use log::{debug, error, info};
use network::{handshake, make_packet, parse_addr_response, read_message, request_seeds, Peer, REQUEST_TIMEOUT};
use rayon::ThreadPoolBuilder;
use tokio::sync::broadcast;
use util::{dump_to_file, fill_asn, setup_logger};

mod network;
mod util;

const OUTPUT_DIR: &str = "output";

const PORT_BITCOIN: u16 = 8333;
const PORT_TESTNET: u16 = 48333;
const PORT_SIGNET: u16 = 38333;
const PORT_REGTEST: u16 = 18444;

const SEEDS_BITCOIN: &[&str] = &[
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
const SEEDS_SIGNET: &[&str] = &[
    "seed.signet.achownodes.xyz",
    "seed.signet.bitcoin.sprovoost.nl"
];
#[rustfmt::skip]
const SEEDS_TESTNET4: &[&str] = &[
    "seed.testnet4.bitcoin.sprovoost.nl",
    "seed.testnet4.wiz.biz"
];

#[derive(Parser, Debug)]
#[command(version, name="getaddress", about="getaddress\nA P2P crawler for all Bitcoin networks", long_about = None)]
struct Args {
    #[arg(long, short, alias="network", default_value_t=String::from("bitcoin"), help="Network to crawl", value_parser = PossibleValuesParser::new(["bitcoin", "signet", "testnet4", "regtest"]))]
    network: String,

    #[rustfmt::skip]
    #[arg(long, default_value_t = true, help = "Wheter to query GeoLite's ASN DB")]
    query_asn: bool,

    #[arg(long, default_value_t = false, help = "Wheter to log below info")]
    debug: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // CTRL-C handler
    let running = Arc::new(AtomicBool::new(true));
    let (shutdown_tx, _) = broadcast::channel::<()>(1);
    {
        let shutdown_tx = shutdown_tx.clone();
        let running_clone = Arc::clone(&running);

        ctrlc::set_handler(move || {
            info!("Received SIGINT: shutting down, this may take a while...");
            running_clone.store(false, Ordering::SeqCst);
            let _ = shutdown_tx.send(());
        })?;
    }

    setup_logger(args.debug).unwrap();

    let timestamp = chrono::Local::now().format("%Y%m%d%H%M%S");

    #[rustfmt::skip]
    let (network_magic, port, dns_seeds, filename) = match args.network.parse::<Network>()? {
        Network::Bitcoin => (Magic::BITCOIN, PORT_BITCOIN, SEEDS_BITCOIN, format!("{}-{}.txt", Network::Bitcoin, timestamp)),
        Network::Signet => (Magic::SIGNET, PORT_SIGNET, SEEDS_SIGNET, format!("{}-{}.txt", Network::Signet, timestamp)),
        Network::Testnet4 => (Magic::TESTNET4, PORT_TESTNET, SEEDS_TESTNET4, format!("{}-{}.txt", Network::Testnet4, timestamp)),
        Network::Regtest => (Magic::REGTEST, PORT_REGTEST, &["localhost"][..], format!("{}-{}.txt", Network::Regtest, timestamp)),
        _ => (Magic::BITCOIN, PORT_BITCOIN, SEEDS_BITCOIN, format!("{}-{}.txt", Network::Bitcoin, timestamp)),
    };

    // capture current timestamp
    let t_0 = Instant::now();

    // populate `peers` with a few good peers from DNS seeds
    let bootstrap_peers = request_seeds(dns_seeds, port, network_magic)?;
    info!("using {} peers from seed nodes as bootstrap peers", bootstrap_peers.len());

    // "leave some for the rest of us!"
    let n_threads = std::cmp::max(1, num_cpus::get() - 2);

    let mut peers = crawl(bootstrap_peers, n_threads, network_magic, running, shutdown_tx, t_0).unwrap();
    peers.sort();
    peers.dedup();

    let delta = t_0.elapsed().as_secs();
    info!(
        "discovered {} unique peers in {:02}:{:02}:{:02}",
        peers.len(),
        (delta / 3600),      // hours
        (delta % 3600) / 60, // minutes
        (delta % 60)         // seconds
    );

    if args.query_asn {
        fill_asn(&mut peers);

        // compile ASN node amounts and share
        let mut asn_nodes: HashMap<String, u32> = HashMap::new();

        for peer in &peers {
            let key = format!("AS{} {}", peer.asn.unwrap_or(0), peer.org.clone().unwrap_or("NO DATA".to_string()));
            *asn_nodes.entry(key).or_insert(1) += 1;
        }

        let mut sorted_asn_nodes: Vec<_> = asn_nodes.into_iter().collect();
        sorted_asn_nodes.sort_by(|a, b| b.1.cmp(&a.1));

        info!("AS node hosting stakes:");
        for (k, v) in sorted_asn_nodes {
            let stake = (100.0 * v as f64 / peers.len() as f64);
            info!(" {}: {} ({:.2}%)", k, v, stake);
        }
    }

    let path = Path::new(OUTPUT_DIR).join(args.network);
    match dump_to_file(&path, &filename, &peers) {
        Ok(_) => info!("{} peers written to {:?}", peers.len(), path.join(filename)),
        Err(e) => error!("failed to write peers to {:?}: {}", path, e),
    };

    info!("done!");

    Ok(())
}

fn crawl(
    bootstrap_peers: Vec<Peer>,
    n_threads: usize,
    network_magic: Magic,
    running: Arc<AtomicBool>,
    shutdown_tx: broadcast::Sender<()>,
    t_0: Instant,
) -> Result<Vec<Peer>> {
    info!("starting crawl from {} bootstrap peers", bootstrap_peers.len());

    // threads will pull jobs from this queue
    let work_queue = Arc::new(Mutex::new(
        bootstrap_peers.into_iter().map(|p| (p.ip, p.port)).collect::<HashSet<_>>(),
    ));
    let running_clone = Arc::clone(&running);

    let discovered_peers = Arc::new(Mutex::new(HashSet::new()));
    let discovered_peers_log = Arc::clone(&discovered_peers);

    // dedicated logging thread
    let mut log_shutdown_rx = shutdown_tx.subscribe();
    let _logging_handle = std::thread::spawn(move || {
        let mut last_count = 0; // Track the previous count

        while running_clone.load(Ordering::SeqCst) {
            if log_shutdown_rx.try_recv().is_ok() {
                break;
            }

            // "how you can tap, go sleep, go sleep"
            std::thread::sleep(Duration::from_millis(500));

            let discovered_clone = Arc::clone(&discovered_peers_log);
            let discovered_count = discovered_clone.lock().unwrap().len();

            if discovered_count > last_count {
                let delta = t_0.elapsed().as_secs();
                info!(
                    "discovered {} unique peers in {:02}:{:02}:{:02}",
                    discovered_count,
                    (delta / 3600),      // hours
                    (delta % 3600) / 60, // minutes
                    (delta % 60)         // seconds
                );
                last_count = discovered_count;
            }
        }
    });

    // worker threads
    info!("creating thread pool with {} threads", n_threads);
    let pool = ThreadPoolBuilder::new().num_threads(n_threads).build()?;
    pool.scope(|s| {
        for thread_id in 0..n_threads {
            let work_queue = Arc::clone(&work_queue);
            let discovered_peers = Arc::clone(&discovered_peers);
            let running = Arc::clone(&running);
            let mut worker_shutdown_rx = shutdown_tx.subscribe();

            s.spawn(move |_| {
                let mut local_discoveries = HashSet::new();

                'worker: while running.load(Ordering::SeqCst) {
                    // catch CTRL-C
                    if worker_shutdown_rx.try_recv().is_ok() {
                        break 'worker;
                    }

                    // fetch job from from the work queue
                    let target = {
                        let mut queue = work_queue.lock().unwrap();

                        if queue.is_empty() {
                            info!("empty work queue, thread {} exiting", thread_id);
                            break 'worker;
                        }

                        let peer = *queue.iter().next().unwrap();
                        queue.remove(&peer);
                        peer
                    };

                    // getaddress
                    let new_peers = match get_address(target.0, target.1, network_magic, thread_id, &running) {
                        Ok(peers) => peers,
                        Err(_) => continue,
                    };

                    // add validated peers to `discovered_peers`
                    {
                        let mut peers = discovered_peers.lock().unwrap();
                        for peer in &new_peers {
                            // Convert Peer to the tuple that discovered_peers stores
                            let peer_tuple = (peer.ip, peer.port);
                            peers.insert(peer_tuple);
                        }
                    }

                    // process new peers
                    let peer_count = new_peers.len();
                    if peer_count > 0 {
                        let mut work_to_add = Vec::new();

                        for peer in &new_peers {
                            let peer_tuple = (peer.ip, peer.port);

                            // skip if we've already seen this peer on this thread
                            local_discoveries.insert(peer_tuple);

                            work_to_add.push(peer_tuple);
                        }

                        if !work_to_add.is_empty() {
                            {
                                let mut peers = discovered_peers.lock().unwrap();
                                for peer in &work_to_add {
                                    peers.insert(*peer);
                                }
                            }

                            {
                                let mut queue = work_queue.lock().unwrap();
                                for peer in &work_to_add {
                                    queue.insert(*peer);
                                }
                            }
                        }
                    }
                }
                debug!("thread {} is exiting worker loop", thread_id);
            });
        }
    });

    let peers_set = Arc::try_unwrap(discovered_peers)
        .map_err(|_| anyhow::anyhow!("failed to unwrap Arc: still has references"))?
        .into_inner()?;

    // convert peer set into Vec<Peer>
    let peers: Vec<Peer> = peers_set
        .into_iter()
        .map(|(ip, port)| Peer {
            ip,
            port,
            asn: None,
            org: None,
        })
        .collect();

    Ok(peers)
}

fn get_address(peer_ip: IpAddr, peer_port: u16, network_magic: Magic, thread_id: usize, running: &AtomicBool) -> Result<Vec<Peer>> {
    // capture CTRL-C
    if !running.load(Ordering::SeqCst) {
        return Ok(Vec::new());
    }

    let socket_addr = SocketAddr::new(peer_ip, peer_port);

    // attempt TCP handshake
    let mut stream = TcpStream::connect_timeout(&socket_addr, Duration::from_secs(REQUEST_TIMEOUT)).map_err(|e| {
        debug!("failed to connect to {}:{}: {}", socket_addr.ip(), socket_addr.port(), e);
        e
    })?;

    if !running.load(Ordering::Relaxed) {
        return Ok(Vec::new());
    }

    // set r/w timeouts
    stream.set_read_timeout(Some(Duration::from_secs(REQUEST_TIMEOUT))).map_err(|e| {
        debug!("failed to set read timeout: {}", e);
        e
    })?;
    stream.set_write_timeout(Some(Duration::from_secs(REQUEST_TIMEOUT))).map_err(|e| {
        debug!("failed to set write timeout: {}", e);
        e
    })?;

    // attempt bitcoin handshake
    handshake(&mut stream, network_magic, thread_id)?;

    // build and send `getaddr` message
    let send_getaddr = make_packet("getaddr", None, network_magic);
    stream.write_all(&send_getaddr).map_err(|e| {
        debug!("failed to send getaddr to {}:{}: {}", peer_ip, peer_port, e);
        e
    })?;
    debug!("sent getaddr to {}:{}", peer_ip, peer_port);

    let mut validated_peers = Vec::new();
    let mut recv_command = "";

    while recv_command != "addr" {
        // capture CTRL-C
        if !running.load(Ordering::Relaxed) {
            return Ok(validated_peers);
        }

        let (command, mut payload) = read_message(&mut stream).map_err(|e| {
            debug!("error reading message from {}:{}: {}", peer_ip, peer_port, e);
            e
        })?;

        if command == "addr" {
            recv_command = "addr";
            debug!("received {} from {}:{}", command, peer_ip, peer_port);

            // parse `addr` response
            let potential_peers = parse_addr_response(&mut payload, peer_ip, peer_port);

            // validate receiver peers from `addr`
            for peer in potential_peers {
                // // capture CTRL-C
                if !running.load(Ordering::Relaxed) {
                    return Ok(validated_peers);
                }

                let socket_addr = SocketAddr::new(peer.ip, peer.port);
                match TcpStream::connect_timeout(&socket_addr, Duration::from_secs(REQUEST_TIMEOUT)) {
                    Ok(mut stream) => {
                        if let Ok(true) = handshake(&mut stream, network_magic, thread_id) {
                            match peer.ip {
                                IpAddr::V4(ip) => {
                                    debug!("new peer discovered @ {}:{}", ip, peer.port);
                                }
                                IpAddr::V6(ip) => {
                                    debug!("new peer discovered @ [{}]:{}", ip, peer.port);
                                }
                            }
                            validated_peers.push(peer);
                        }
                    }
                    _ => continue,
                }
            }
        }
    }

    Ok(validated_peers)
}
