//! ergo-peers — Ergo P2P peer discovery daemon.
//!
//! Discovers reachable Ergo peers by connecting to seed nodes and exchanging
//! peer lists. Writes a JSON file with discovered peers for ergo-signer to
//! use when broadcasting transactions.
//!
//! Usage:
//!   ergo-peers [--testnet] [--output /path/to/peers.json] [--min-peers 10]
//!
//! Runs until min-peers reachable peers are found, then exits.
//! Designed to run as a daily cron/timer job.

mod p2p;

use p2p::{discover_peers, Network};
use std::collections::HashSet;
use std::net::SocketAddr;

const DEFAULT_OUTPUT: &str = "/var/lib/blockhost/ergo-peers.json";
const DEFAULT_MIN_PEERS: usize = 10;
const MAX_ROUNDS: usize = 5;

// Known seed peers (testnet and mainnet)
const TESTNET_SEEDS: &[&str] = &[
    "213.239.193.208:9020",
    "128.253.41.110:9020",
    "176.9.15.237:9021",
];

const MAINNET_SEEDS: &[&str] = &[
    "213.239.193.208:9030",
    "168.138.185.215:9030",
    "176.9.15.237:9030",
];

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let testnet = args.iter().any(|a| a == "--testnet");
    let network = if testnet { Network::Testnet } else { Network::Mainnet };

    let output = args.iter()
        .position(|a| a == "--output")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
        .unwrap_or(DEFAULT_OUTPUT);

    let min_peers = args.iter()
        .position(|a| a == "--min-peers")
        .and_then(|i| args.get(i + 1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_MIN_PEERS);

    let seeds: Vec<SocketAddr> = if testnet { TESTNET_SEEDS } else { MAINNET_SEEDS }
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect();

    eprintln!(
        "ergo-peers: discovering {} peers ({}, {} seeds)",
        min_peers,
        if testnet { "testnet" } else { "mainnet" },
        seeds.len(),
    );

    let mut known: HashSet<SocketAddr> = HashSet::new();
    let mut reachable: HashSet<SocketAddr> = HashSet::new();
    let mut to_try: Vec<SocketAddr> = seeds.clone();

    for round in 0..MAX_ROUNDS {
        if reachable.len() >= min_peers {
            break;
        }

        eprintln!("Round {}: trying {} peers (have {} reachable)", round + 1, to_try.len(), reachable.len());

        let mut new_peers: Vec<SocketAddr> = Vec::new();

        for addr in &to_try {
            if known.contains(addr) {
                continue;
            }
            known.insert(*addr);

            eprint!("  Trying {}... ", addr);
            match discover_peers(*addr, network) {
                Ok(peers) => {
                    eprintln!("got {} peers", peers.len());
                    reachable.insert(*addr);
                    for p in peers {
                        if !known.contains(&p) {
                            new_peers.push(p);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("failed: {}", e);
                }
            }
        }

        to_try = new_peers;
    }

    // Write results
    let peers_list: Vec<String> = reachable.iter().map(|a| a.to_string()).collect();
    eprintln!("Discovered {} reachable peers", peers_list.len());

    let json = serde_json::json!({
        "network": if testnet { "testnet" } else { "mainnet" },
        "peers": peers_list,
        "discovered_at": chrono_timestamp(),
        "count": peers_list.len(),
    });

    // Ensure parent directory exists
    if let Some(parent) = std::path::Path::new(output).parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    match std::fs::write(output, serde_json::to_string_pretty(&json).unwrap()) {
        Ok(()) => eprintln!("Wrote peer list to {}", output),
        Err(e) => {
            eprintln!("Failed to write {}: {}", output, e);
            // Print to stdout as fallback
            println!("{}", serde_json::to_string_pretty(&json).unwrap());
        }
    }
}

fn chrono_timestamp() -> String {
    let dur = SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap();
    format!("{}Z", dur.as_secs())
}

use std::time::SystemTime;
