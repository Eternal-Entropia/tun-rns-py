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
1) set in host:
sysctl -w net.ipv4.ip_forward=1
iptables -A FORWARD -i tun0 -o ens3 -j ACCEPT
iptables -A FORWARD -i ens3 -o tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -t nat -A POSTROUTING -s 10.244.0.0/24 -o ens3 -j MASQUERADE
sudo python3 tun_rns_linux_host.py --ip 10.244.0.1 --peer 10.244.0.2 --mss-clamp --daemon --pidfile /var/run/rns-tunnel.pid --logfile /var/log/rns-tunnel.log --mtu 1500

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