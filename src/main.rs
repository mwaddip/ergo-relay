//! ergo-relay — Minimal Ergo transaction signing HTTP service.
//!
//! Exposes two endpoints on localhost:
//!   POST /wallet/transaction/sign  — sign an unsigned transaction
//!   GET  /info                     — health check
//!
//! Uses sigma-rust (ergo-lib) for transaction signing. No JRE needed.

mod p2p;

use ergo_lib::chain::transaction::unsigned::UnsignedTransaction;
use ergo_lib::wallet::Wallet;
use ergo_lib::wallet::secret_key::SecretKey;
use ergotree_interpreter::sigma_protocol::private_input::DlogProverInput;
use serde::{Deserialize, Serialize};
use std::io::Read;
use tiny_http::{Header, Method, Response, Server, StatusCode};

const DEFAULT_PORT: u16 = 9064;
const VERSION: &str = env!("CARGO_PKG_VERSION");

// ---------------------------------------------------------------------------
// Request/response types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct SignRequest {
    tx: serde_json::Value,
    secrets: SecretsMap,
    #[serde(default)]
    height: Option<u32>,
}

#[derive(Deserialize)]
struct SecretsMap {
    #[serde(default)]
    dlog: Vec<String>,
}

#[derive(Serialize)]
struct InfoResponse<'a> {
    name: &'a str,
    version: &'a str,
    status: &'a str,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: u16,
    reason: &'static str,
    detail: String,
}

// ---------------------------------------------------------------------------
// Signing logic
// ---------------------------------------------------------------------------

fn do_sign(body: &[u8]) -> Result<serde_json::Value, String> {
    let req: SignRequest =
        serde_json::from_slice(body).map_err(|e| format!("Invalid request JSON: {}", e))?;

    // Parse unsigned transaction
    let unsigned_tx: UnsignedTransaction = serde_json::from_value(req.tx.clone())
        .map_err(|e| format!("Invalid unsigned transaction: {}", e))?;

    // Parse secret keys
    if req.secrets.dlog.is_empty() {
        return Err("No secret keys provided in secrets.dlog".into());
    }

    let secret_keys: Vec<SecretKey> = req
        .secrets
        .dlog
        .iter()
        .map(|hex_key| {
            let bytes = hex_decode(hex_key)?;
            if bytes.len() != 32 {
                return Err(format!("Key must be 32 bytes, got {}", bytes.len()));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            let dlog = DlogProverInput::from_bytes(&arr)
                .ok_or_else(|| "Invalid private key scalar".to_string())?;
            Ok(SecretKey::DlogSecretKey(dlog))
        })
        .collect::<Result<Vec<_>, String>>()?;

    // Create wallet from secrets
    let wallet = Wallet::from_secrets(secret_keys);

    // We need input boxes to create the TransactionContext.
    // The boxes should be embedded in the tx JSON's inputs (full box data).
    let inputs_json = req.tx.get("inputs")
        .ok_or("Transaction has no 'inputs' field")?;
    let input_boxes: Vec<ergo_lib::ergotree_ir::chain::ergo_box::ErgoBox> =
        serde_json::from_value(inputs_json.clone())
            .map_err(|e| format!("Failed to parse input boxes: {}", e))?;

    // Data inputs (optional)
    let data_boxes: Vec<ergo_lib::ergotree_ir::chain::ergo_box::ErgoBox> =
        req.tx.get("dataInputs")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();

    // Create transaction context
    let tx_context = ergo_lib::wallet::tx_context::TransactionContext::new(
        unsigned_tx,
        input_boxes,
        data_boxes,
    )
    .map_err(|e| format!("Failed to create tx context: {:?}", e))?;

    let state_context = make_state_context(req.height.unwrap_or(0));

    // Sign
    let signed_tx = wallet
        .sign_transaction(tx_context, &state_context, None)
        .map_err(|e| format!("Signing failed: {:?}", e))?;

    serde_json::to_value(&signed_tx).map_err(|e| format!("Failed to serialize signed tx: {}", e))
}

fn make_state_context(height: u32) -> ergo_lib::chain::ergo_state_context::ErgoStateContext {
    // The height is used by scripts that check HEIGHT (like our subscription guard).
    // The caller should pass the current blockchain height.
    let header_json = serde_json::json!({
        "version": 2,
        "id": "0000000000000000000000000000000000000000000000000000000000000000",
        "parentId": "0000000000000000000000000000000000000000000000000000000000000000",
        "adProofsRoot": "0000000000000000000000000000000000000000000000000000000000000000",
        "stateRoot": "000000000000000000000000000000000000000000000000000000000000000000",
        "transactionsRoot": "0000000000000000000000000000000000000000000000000000000000000000",
        "timestamp": 0u64,
        "nBits": 16842752u64,
        "height": height,
        "extensionHash": "0000000000000000000000000000000000000000000000000000000000000000",
        "powSolutions": {
            "pk": "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            "w": "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            "n": "0000000000000000",
            "d": 0
        },
        "votes": "000000"
    });
    let h: ergo_chain_types::Header =
        serde_json::from_value(header_json).expect("dummy header should parse");
    let pre_header = ergo_chain_types::PreHeader::from(h.clone());
    let headers: ergo_lib::chain::ergo_state_context::Headers = [
        h.clone(), h.clone(), h.clone(), h.clone(), h.clone(),
        h.clone(), h.clone(), h.clone(), h.clone(), h,
    ];
    ergo_lib::chain::ergo_state_context::ErgoStateContext::new(
        pre_header,
        headers,
        ergo_lib::chain::parameters::Parameters::default(),
    )
}

// ---------------------------------------------------------------------------
// HTTP server
// ---------------------------------------------------------------------------

fn json_response<S: Serialize>(status: u16, body: &S) -> Response<std::io::Cursor<Vec<u8>>> {
    let json = serde_json::to_vec(body).unwrap_or_default();
    let len = json.len();
    let header = Header::from_bytes("Content-Type", "application/json").unwrap();
    Response::new(
        StatusCode(status),
        vec![header],
        std::io::Cursor::new(json),
        Some(len),
        None,
    )
}

fn main() {
    let port = std::env::var("ERGO_SIGNER_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_PORT);

    let bind = format!("127.0.0.1:{}", port);
    let server = Server::http(&bind).unwrap_or_else(|e| {
        eprintln!("Failed to bind to {}: {}", bind, e);
        std::process::exit(1);
    });

    eprintln!("ergo-relay v{} listening on {}", VERSION, bind);

    for mut request in server.incoming_requests() {
        let url = request.url().to_string();
        let method = request.method().clone();

        match (method, url.as_str()) {
            (Method::Get, "/info") => {
                let info = InfoResponse {
                    name: "ergo-relay",
                    version: VERSION,
                    status: "ok",
                };
                let _ = request.respond(json_response(200, &info));
            }

            (Method::Post, "/wallet/transaction/sign") => {
                let mut body = Vec::new();
                if let Err(e) = request.as_reader().read_to_end(&mut body) {
                    let err = ErrorResponse {
                        error: 400,
                        reason: "bad.request",
                        detail: format!("Failed to read request body: {}", e),
                    };
                    let _ = request.respond(json_response(400, &err));
                    continue;
                }

                match do_sign(&body) {
                    Ok(signed) => {
                        let _ = request.respond(json_response(200, &signed));
                    }
                    Err(detail) => {
                        eprintln!("Sign error: {}", detail);
                        let err = ErrorResponse {
                            error: 400,
                            reason: "bad.request",
                            detail,
                        };
                        let _ = request.respond(json_response(400, &err));
                    }
                }
            }

            (Method::Post, "/transactions") => {
                let mut body = Vec::new();
                if let Err(e) = request.as_reader().read_to_end(&mut body) {
                    let err = ErrorResponse {
                        error: 400,
                        reason: "bad.request",
                        detail: format!("Failed to read request body: {}", e),
                    };
                    let _ = request.respond(json_response(400, &err));
                    continue;
                }

                match do_broadcast(&body) {
                    Ok(tx_id) => {
                        // Return tx ID as a JSON string (same as Ergo node)
                        let _ = request.respond(json_response(200, &tx_id));
                    }
                    Err(detail) => {
                        eprintln!("Broadcast error: {}", detail);
                        // Distinguish between "no peers" (503) and "bad tx" (400)
                        let (code, reason) = if detail.contains("broadcast to any peer") {
                            (503, "service.unavailable")
                        } else {
                            (400, "bad.request")
                        };
                        let err = ErrorResponse {
                            error: code,
                            reason,
                            detail,
                        };
                        let _ = request.respond(json_response(code as u16, &err));
                    }
                }
            }

            _ => {
                let err = ErrorResponse {
                    error: 404,
                    reason: "not.found",
                    detail: format!("Unknown endpoint: {}", request.url()),
                };
                let _ = request.respond(json_response(404, &err));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Transaction broadcast via P2P
// ---------------------------------------------------------------------------

fn do_broadcast(body: &[u8]) -> Result<String, String> {
    use ergo_lib::chain::transaction::Transaction;
    use ergotree_ir::serialization::SigmaSerializable;

    // Parse signed transaction from JSON
    let tx: Transaction = serde_json::from_slice(body)
        .map_err(|e| format!("Invalid signed transaction JSON: {}", e))?;

    // Serialize to bytes for P2P wire format
    let tx_bytes = tx.sigma_serialize_bytes()
        .map_err(|e| format!("Failed to serialize tx: {}", e))?;

    // Get tx ID (32 bytes)
    let tx_id = tx.id();
    let tx_id_ref: &[u8] = tx_id.as_ref();
    let mut tx_id_bytes = [0u8; 32];
    tx_id_bytes.copy_from_slice(tx_id_ref);

    let tx_id_hex = tx_id_bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>();
    eprintln!("Broadcasting tx {} ({} bytes)", tx_id_hex, tx_bytes.len());

    // Determine network from env or default to testnet if .testing-mode exists
    let network = if std::path::Path::new("/etc/blockhost/.testing-mode").exists() {
        p2p::Network::Testnet
    } else {
        p2p::Network::Mainnet
    };

    let peers_file = std::env::var("ERGO_PEERS_FILE")
        .unwrap_or_else(|_| "/var/lib/blockhost/ergo-peers.json".to_string());

    let sent = p2p::broadcast_tx_to_peers(&peers_file, network, &tx_id_bytes, &tx_bytes, 3);

    if sent == 0 {
        return Err("Failed to broadcast to any peer".to_string());
    }

    eprintln!("Broadcast to {} peer(s)", sent);
    Ok(tx_id_hex)
}

// ---------------------------------------------------------------------------
// Hex decode helper
// ---------------------------------------------------------------------------

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("Odd-length hex string".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|e| format!("Invalid hex at position {}: {}", i, e))
        })
        .collect()
}
