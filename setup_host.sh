#!/bin/bash

set -e

echo "=== RNS TUN Host Installer ==="

# Check if Python is installed
if ! command -v python3 &> /dev/null && ! command -v python &> /dev/null; then
    echo "[X] Error: Python is not installed on this host! Please install Python 3 first."
    exit 1
fi

# 1. Detect default internet interface
DEFAULT_IFACE=$(ip route | grep '^default' | awk '{print $5}' | head -n1)
if [ -z "$DEFAULT_IFACE" ]; then
    DEFAULT_IFACE="ens3"
    echo "[!] Could not detect default interface, using fallback: $DEFAULT_IFACE"
else
    echo "[+] Detected default internet interface: $DEFAULT_IFACE"
fi

# 2. Enable IP forwarding
echo "[+] Enabling IP forwarding..."
sudo sysctl -w net.ipv4.ip_forward=1
if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf; then
    echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
fi

# 3. Configure iptables rules
echo "[+] Configuring iptables firewall rules..."
sudo iptables -A FORWARD -i tun0 -o "$DEFAULT_IFACE" -j ACCEPT
sudo iptables -A FORWARD -i "$DEFAULT_IFACE" -o tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo iptables -t nat -A POSTROUTING -s 10.244.0.0/24 -o "$DEFAULT_IFACE" -j MASQUERADE





# 5. Install Reticulum
echo "[+] Installing Reticulum..."
pip3 install rns --break-system-packages || pip3 install rns || pip install rns

# 6. Configure Reticulum Backbone
RNS_CONFIG_DIR="$HOME/.reticulum"
mkdir -p "$RNS_CONFIG_DIR"
RNS_CONFIG="$RNS_CONFIG_DIR/config"

if [ -f "$RNS_CONFIG" ]; then
    echo "[!] Reticulum config already exists at $RNS_CONFIG. Skipping config modifications."
else
    echo "[+] Creating default Reticulum config with Backbone interface..."
    cat <<EOF > "$RNS_CONFIG"
[reticulum]
  share_instance = Yes
  enable_transport = Yes
  instance_name = tun-host

[[Backbone]]
  type = BackboneInterface
  enabled = yes
  port = 4242
  listen_on = 0.0.0.0
EOF
fi

# 7. Setup Auto-Start Service (systemd)
echo "[+] Creating installation directory /etc/rns-tunnel..."
sudo mkdir -p /etc/rns-tunnel

# Download host script to /etc/rns-tunnel
echo "[+] Downloading host script..."
GITHUB_USER="Eternal-Entropia"
GITHUB_REPO="tun-rns-py"
GITHUB_BRANCH="main"

RAW_URL="https://raw.githubusercontent.com/${GITHUB_USER}/${GITHUB_REPO}/${GITHUB_BRANCH}/tun_rns_linux_host.py"
echo "Downloading from: $RAW_URL"
sudo curl -fsSL "$RAW_URL" -o /etc/rns-tunnel/tun_rns_linux_host.py || sudo wget -q "$RAW_URL" -O /etc/rns-tunnel/tun_rns_linux_host.py
sudo chmod +x /etc/rns-tunnel/tun_rns_linux_host.py

echo "[+] Creating start_host.sh wrapper script..."
sudo tee /etc/rns-tunnel/start_host.sh > /dev/null <<'EOF'
#!/bin/bash
set -e

# Detect default interface
DEFAULT_IFACE=$(ip route | grep '^default' | awk '{print $5}' | head -n1)
if [ -z "$DEFAULT_IFACE" ]; then
    DEFAULT_IFACE="ens3"
fi

echo "[+] Using network interface: $DEFAULT_IFACE"

# Enable IP forwarding
sysctl -w net.ipv4.ip_forward=1

# Configure iptables rules (avoiding duplicates)
iptables -D FORWARD -i tun0 -o "$DEFAULT_IFACE" -j ACCEPT 2>/dev/null || true
iptables -A FORWARD -i tun0 -o "$DEFAULT_IFACE" -j ACCEPT

iptables -D FORWARD -i "$DEFAULT_IFACE" -o tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
iptables -A FORWARD -i "$DEFAULT_IFACE" -o tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT

iptables -t nat -D POSTROUTING -s 10.244.0.0/24 -o "$DEFAULT_IFACE" -j MASQUERADE 2>/dev/null || true
iptables -t nat -A POSTROUTING -s 10.244.0.0/24 -o "$DEFAULT_IFACE" -j MASQUERADE

# Start the python host script
python3 /etc/rns-tunnel/tun_rns_linux_host.py --ip 10.244.0.1 --mss-clamp
EOF
sudo chmod +x /etc/rns-tunnel/start_host.sh

echo "[+] Creating systemd service file..."
sudo tee /etc/systemd/system/rns-tunnel.service > /dev/null <<EOF
[Unit]
Description=Reticulum TUN VPN Tunnel Host
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash /etc/rns-tunnel/start_host.sh
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF

echo "[+] Enabling and starting rns-tunnel service..."
sudo systemctl daemon-reload
sudo systemctl enable rns-tunnel
sudo systemctl restart rns-tunnel

echo "================================="
echo "[+] Host setup and autostart configuration completed successfully!"
echo ""
echo "The host script is now running in the background as a systemd service."
echo "You can check status or control it using:"
echo "  sudo systemctl status rns-tunnel"
echo "  sudo systemctl stop rns-tunnel"
echo "  sudo systemctl start rns-tunnel"
echo ""
echo "Logs can be viewed using: journalctl -u rns-tunnel -f"
echo "================================="
