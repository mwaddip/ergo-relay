//! ergo-peers — Ergo P2P peer discovery daemon.
//!
//! Discovers reachable Ergo peers by connecting to seed nodes and exchanging
//! peer lists. Writes a JSON file with discovered peers for ergo-relay to
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
const DEFAULT_MIN_PEERS: usize = 1;
const MAX_ROUNDS: usize = 5;

// Known seed peers (testnet and mainnet)
const TESTNET_SEEDS: &[&str] = &[
    "213.239.193.208:9023",  // reliable, consistently available
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
    // Detect network: --testnet flag overrides, then ERGO_NETWORK env, then .testing-mode file
    let network = if args.iter().any(|a| a == "--testnet") {
        Network::Testnet
    } else {
        p2p::detect_network()
    };

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

    let testnet = matches!(network, Network::Testnet);
    let seeds: Vec<SocketAddr> = if testnet { TESTNET_SEEDS } else { MAINNET_SEEDS }
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect();

    // Load previously discovered peers (if any) as additional candidates
    let mut previously_known: Vec<SocketAddr> = Vec::new();
    if let Ok(data) = std::fs::read_to_string(output) {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&data) {
            if let Some(peers) = json["peers"].as_array() {
                for p in peers {
                    if let Some(s) = p.as_str() {
                        if let Ok(addr) = s.parse() {
                            previously_known.push(addr);
                        }
                    }
                }
            }
        }
    }

    eprintln!(
        "ergo-peers: discovering {} peers ({}, {} seeds, {} previously known)",
        min_peers,
        if testnet { "testnet" } else { "mainnet" },
        seeds.len(),
        previously_known.len(),
    );

    // Track all peers we've ever verified as reachable (grows across runs)
    let mut all_reachable: HashSet<SocketAddr> = HashSet::new();
    let mut known_this_round: HashSet<SocketAddr> = HashSet::new();

    // Start with: previously known peers first (likely still reachable), then seeds
    let mut to_try: Vec<SocketAddr> = Vec::new();
    for p in &previously_known {
        if !known_this_round.contains(p) {
            to_try.push(*p);
        }
    }
    for s in &seeds {
        if !known_this_round.contains(s) {
            to_try.push(*s);
        }
    }

    for round in 0..MAX_ROUNDS {
        if all_reachable.len() >= min_peers {
            break;
        }

        eprintln!("Round {}: trying {} peers (have {} reachable)",
            round + 1, to_try.len(), all_reachable.len());

        let mut new_peers: Vec<SocketAddr> = Vec::new();

        for addr in &to_try {
            if known_this_round.contains(addr) {
                continue;
            }
            known_this_round.insert(*addr);

            eprint!("  Trying {}... ", addr);
            match discover_peers(*addr, network) {
                Ok(peers) => {
                    eprintln!("got {} peers", peers.len());
                    all_reachable.insert(*addr);
                    for p in peers {
                        if !known_this_round.contains(&p) {
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

    if all_reachable.len() < min_peers {
        eprintln!("Warning: only found {} peer(s) (wanted {})", all_reachable.len(), min_peers);
    }

    // Write results — union of all reachable peers (list grows over runs)
    let peers_list: Vec<String> = all_reachable.iter().map(|a| a.to_string()).collect();
    eprintln!("Total reachable peers: {}", peers_list.len());

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
