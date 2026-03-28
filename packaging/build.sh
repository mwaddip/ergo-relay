#!/bin/bash
set -e

VERSION="0.1.0"
ARCH=$(dpkg --print-architecture 2>/dev/null || uname -m | sed 's/x86_64/amd64/')
PKG_NAME="ergo-relay_${VERSION}_${ARCH}"
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PKG_DIR="$PROJECT_DIR/packaging/$PKG_NAME"

cleanup() { rm -rf "$PKG_DIR"; }
trap cleanup EXIT

echo "Building ergo-relay $VERSION ($ARCH)..."

# ── Build Rust binaries ─────────────────────────────────
echo "Compiling..."
cd "$PROJECT_DIR"
cargo build --release

SIGNER="$PROJECT_DIR/target/release/ergo-relay"
PEERS="$PROJECT_DIR/target/release/ergo-peers"

if [ ! -f "$SIGNER" ] || [ ! -f "$PEERS" ]; then
    echo "ERROR: Rust build failed — binaries not found"
    exit 1
fi

echo "  ergo-relay: $(du -h "$SIGNER" | cut -f1)"
echo "  ergo-peers:  $(du -h "$PEERS" | cut -f1)"

# ── Create package directory structure ──────────────────
rm -rf "$PKG_DIR"
mkdir -p "$PKG_DIR/DEBIAN"
mkdir -p "$PKG_DIR/usr/bin"
mkdir -p "$PKG_DIR/usr/share/blockhost"
mkdir -p "$PKG_DIR/lib/systemd/system"

# ── DEBIAN control ──────────────────────────────────────
cat > "$PKG_DIR/DEBIAN/control" << CTRL
Package: ergo-relay
Version: $VERSION
Architecture: $ARCH
Depends: libgcc-s1
Provides: ergo-relay
Description: Ergo transaction signing and P2P broadcast service
 Minimal sigma-rust based signing service and peer discovery
 for BlockHost Ergo components. No JRE required.
Maintainer: BlockHost <noreply@blockhost.io>
CTRL

# ── Install binaries ────────────────────────────────────
cp "$SIGNER" "$PKG_DIR/usr/bin/ergo-relay"
cp "$PEERS" "$PKG_DIR/usr/bin/ergo-peers"
chmod 755 "$PKG_DIR/usr/bin/ergo-relay" "$PKG_DIR/usr/bin/ergo-peers"

# ── Systemd service for ergo-relay ─────────────────────
cat > "$PKG_DIR/lib/systemd/system/ergo-relay.service" << 'UNIT'
[Unit]
Description=Ergo Transaction Signer (BlockHost)
After=network.target

[Service]
Type=simple
User=blockhost
Group=blockhost
ExecStart=/usr/bin/ergo-relay
Restart=always
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/blockhost

[Install]
WantedBy=multi-user.target
UNIT

# ── Systemd timer for ergo-peers ────────────────────────
cat > "$PKG_DIR/lib/systemd/system/ergo-peers.service" << 'UNIT'
[Unit]
Description=Ergo P2P Peer Discovery
After=network.target

[Service]
Type=oneshot
User=blockhost
Group=blockhost
ExecStart=/usr/bin/ergo-peers
ReadWritePaths=/var/lib/blockhost
UNIT

cat > "$PKG_DIR/lib/systemd/system/ergo-peers.timer" << 'UNIT'
[Unit]
Description=Daily Ergo peer discovery

[Timer]
OnCalendar=daily
RandomizedDelaySec=3600
Persistent=true

[Install]
WantedBy=timers.target
UNIT

# ── Post-install: enable services ───────────────────────
cat > "$PKG_DIR/DEBIAN/postinst" << 'SCRIPT'
#!/bin/sh
set -e
mkdir -p /var/lib/blockhost
if getent group blockhost >/dev/null; then
    chown root:blockhost /var/lib/blockhost
fi
systemctl daemon-reload
systemctl enable ergo-relay ergo-peers.timer
systemctl start ergo-relay ergo-peers.timer || true
SCRIPT
chmod 755 "$PKG_DIR/DEBIAN/postinst"

# ── Build .deb ──────────────────────────────────────────
dpkg-deb --build "$PKG_DIR"
DEB_FILE="$PROJECT_DIR/packaging/${PKG_NAME}.deb"

echo ""
echo "Built: $DEB_FILE ($(du -h "$DEB_FILE" | cut -f1))"
