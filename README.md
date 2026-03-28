# ergo-signer

Minimal Ergo transaction signing and P2P broadcast service. Ships as a standalone Debian package that any Ergo-based BlockHost component can depend on.

## What it does

- **Signs transactions** via sigma-rust (Schnorr/Sigma protocol proofs)
- **Broadcasts transactions** directly to the Ergo P2P network
- **Discovers peers** for reliable broadcast

No JRE, no Ergo node, no WASM. Two small Rust binaries:

| Binary | Size | Purpose |
|--------|------|---------|
| `ergo-signer` | 2.7 MB | HTTP service: signing + P2P broadcast |
| `ergo-peers` | 379 KB | Peer discovery (cron job) |

## Endpoints

`ergo-signer` listens on `127.0.0.1:9064` (configurable via `ERGO_SIGNER_PORT`):

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/wallet/transaction/sign` | POST | Sign an unsigned transaction |
| `/transactions` | POST | Broadcast a signed transaction via P2P |
| `/info` | GET | Health check |

### Sign request format

Same as the Ergo node's `/wallet/transaction/sign`:

```json
{
  "tx": { "...unsigned transaction..." },
  "secrets": { "dlog": ["hex_private_key"] }
}
```

### Broadcast request format

Same as the Ergo node's `/transactions` — accepts a signed transaction JSON.

## Peer discovery

`ergo-peers` connects to seed nodes, exchanges peer lists, and writes a JSON file for `ergo-signer` to read when broadcasting.

```bash
ergo-peers [--testnet] [--output /path/to/peers.json] [--min-peers 10]
```

Default output: `/var/lib/blockhost/ergo-peers.json`

Designed to run as a daily cron/timer job.

## Building

```bash
cargo build --release
```

Binaries at `target/release/ergo-signer` and `target/release/ergo-peers`.

### Debian package

```bash
./packaging/build.sh
```

Produces `ergo-signer_0.1.0_amd64.deb`.

## Systemd services

The .deb installs:
- `ergo-signer.service` — signing + broadcast daemon
- `ergo-peers.timer` — daily peer discovery

## Package dependencies

Other BlockHost packages declare: `Depends: ergo-signer (>= 0.1.0)`

## License

MIT
