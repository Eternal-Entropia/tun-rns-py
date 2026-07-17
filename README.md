# tun-rns-py

Reticulum Internel TUNnel on python for Windows And Linux.

L3-VPN: (client) ↔ RNS.Link ↔ Linux (server) → Internet.

```
  Windows                                 Linux
  ┌──────────────────────┐              ┌──────────────────────┐
  │ tun0  10.244.0.2     │              │ tun0  10.244.0.1     │
  │        │             │   TCP:4242   │        │             │
  │ tun_rns_win.py ──────┤── Backbone ──┤ tun_rns_linux_host.py│
  │   default route      │   RNS Link   │   FORWARD + MASQ     │
  │   → 10.244.0.1       │   AES-256    │   → ens3 → internet  │
  └──────────────────────┘              └──────────────────────┘
```

How to run:

1) Set up the host:

You can automatically configure the host (enable forwarding, setup iptables, configure Reticulum, and download the host script) by running:
```bash
curl -fsSL https://raw.githubusercontent.com/Eternal-Entropia/tun-rns-py/main/setup_host.sh | bash
```
Or set up manually:

```bash
sysctl -w net.ipv4.ip_forward=1

# (Replace ens3 with your default network interface name if different)
iptables -A FORWARD -i tun0 -o ens3 -j ACCEPT
iptables -A FORWARD -i ens3 -o tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -t nat -A POSTROUTING -s 10.244.0.0/24 -o ens3 -j MASQUERADE
```

Then run the host script manually or check the autostart service:

* **If you used the automated script**, it runs in the background via systemd automatically! You can control it using:
  ```bash
  sudo systemctl status rns-tunnel
  sudo systemctl restart rns-tunnel
  sudo systemctl stop rns-tunnel
  ```
  And view real-time logs using:
  ```bash
  journalctl -u rns-tunnel -f
  ```

* **If you set up manually**, run the script using:
  ```bash
  sudo python3 tun_rns_linux_host.py --ip 10.244.0.1 --mss-clamp --daemon --pidfile /var/run/rns-tunnel.pid --logfile /var/log/rns-tunnel.log --mtu 1500
  ```

2) edit ~/.reticulum/config on host:

[[Backbone]]

  type = BackboneInterface

  enabled = yes

  port = 4242

  listen_on = 0.0.0.0

3)Run as admin client EXE for Windows(to run on windows download wintun.dll for you arch and replace to script. https://www.wintun.net/)

OR

4)run client script:

Linux client GUI: python3 tun_rns_linux_gui.py

Windows: python tun_rns_win.py

Windows CLI: python tun_rns_win.py --cli --dest (end-point) --tun-ip 10.244.0.2 --tun-peer 10.244.0.1 --tun-name tun0 --tun-mtu 1500 --tun-mask 24 (RUN AS ADMINISTRATOR!)

build.sh not work

update:
v2: added android version, added multiple link support for host (up to 254 users) and auto IP assignment for clients. 