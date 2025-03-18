//! Utility functions

use std::error::Error;
use std::fmt::Arguments;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

use fern::colors::{Color, ColoredLevelConfig};
use fern::FormatCallback;
use log::{error, info, Record};
use maxminddb::Reader;
use sha2::{Digest, Sha256};

use crate::network::Peer;

const GEOLITE_DB: &str = "geolite2-asn.mmdb";

pub struct LookupAS {
    reader: Reader<Vec<u8>>,
}

impl LookupAS {
    pub fn new<P: AsRef<Path>>(db_path: P) -> Result<Self, maxminddb::MaxMindDBError> {
        let reader = Reader::open_readfile(db_path)?;

        Ok(Self { reader })
    }

    pub fn lookup_peer(&self, peer: &mut Peer) -> Result<(), maxminddb::MaxMindDBError> {
        match self.reader.lookup::<maxminddb::geoip2::Asn>(peer.ip) {
            Ok(record) => {
                peer.asn = record.autonomous_system_number;
                peer.org = record.autonomous_system_organization.map(|org| org.to_string());

                Ok(())
            }
            Err(maxminddb::MaxMindDBError::AddressNotFoundError(_)) => Ok(()),
            Err(e) => Err(e),
        }
    }
}

/// first <= FC => This byte (0 ~ 252)
/// first == FD => The next two bytes (253 ~ 65_535)
/// first == FE => The next four bytes (65_536 ~ 4_294_967_295)
/// first == FF => The next eight bytes (4_294_967_296 ~ 18_446_744_073_709_551_615)
pub fn decode_compact_size(buffer: &mut Vec<u8>) -> usize {
    let first = buffer.remove(0);
    match first {
        0..=0xFC => first as usize,
        0xFD => {
            let bytes: [u8; 2] = [buffer.remove(0), buffer.remove(0)];
            u16::from_le_bytes(bytes) as usize
        }
        0xFE => {
            let bytes: [u8; 4] = [buffer.remove(0), buffer.remove(0), buffer.remove(0), buffer.remove(0)];
            u32::from_le_bytes(bytes) as usize
        }
        0xFF => {
            let bytes: [u8; 8] = [
                buffer.remove(0),
                buffer.remove(0),
                buffer.remove(0),
                buffer.remove(0),
                buffer.remove(0),
                buffer.remove(0),
                buffer.remove(0),
                buffer.remove(0),
            ];
            u64::from_le_bytes(bytes) as usize
        }
    }
}

/// Double SHA256
pub fn hash256(data: Vec<u8>) -> [u8; 32] {
    let first_hash = Sha256::digest(&data);
    let second_hash = Sha256::digest(first_hash);
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&second_hash);
    digest
}

/// Dumps the Peer vector to a file
pub fn dump_to_file(path: &PathBuf, filename: &String, peers: &Vec<Peer>) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(path)?;

    let file_path = path.join(filename);

    let mut file = File::create(&file_path)?;

    for peer in peers {
        if peer.asn.is_some() {
            writeln!(
                file,
                "{}:{} / AS{:?} / {}",
                peer.ip,
                peer.port,
                peer.asn.unwrap_or(0),
                peer.org.clone().unwrap_or("NO DATA".to_string())
            )?;
        } else {
            writeln!(file, "{}:{}", peer.ip, peer.port)?;
        }
    }

    Ok(())
}

/// Query GEOLITE_DB and try to fill ASN's and Org names based on IP address
pub fn fill_asn(peers: &mut Vec<Peer>) {
    info!("looking up peer's ASNs...");

    if let Ok(lookup_as) = LookupAS::new(GEOLITE_DB) {
        for peer in peers {
            let _ = lookup_as.lookup_peer(peer);
        }
        info!("peer ASNs filled!");
    } else {
        error!("error while reading {}, skipping ASN tagging", GEOLITE_DB);
    }
}

/// Right-pads a vector with zeroes until `total_size`
pub fn pad_vector(data: Vec<u8>, total_size: usize) -> Vec<u8> {
    let mut padded = data.clone();
    padded.resize(total_size, 0);
    padded
}

pub fn setup_logger(debug: bool) -> Result<(), fern::InitError> {
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
