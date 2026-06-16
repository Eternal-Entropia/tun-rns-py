#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TUN tunnel client over Reticulum (Linux) — CLI.

Connects to a remote TUN endpoint by destination hash,
creates a TUN adapter and routes all IPv4 traffic through the tunnel.

TUN <-> Link bridge protocol:
    TUN <--ip packet--> bridge <--RNS.Resource--> Link <-- Reticulum

Dependencies: pip install rns

Usage:

    # foreground
    sudo python3 tun_rns_linux_cli.py --dest <hash>

    # in background
    sudo python3 tun_rns_linux_cli.py --dest <hash> --daemon \\
        --pidfile /var/run/rns-client.pid --logfile /var/log/rns-client.log

    # status / stop
    python3 tun_rns_linux_cli.py --status
    python3 tun_rns_linux_cli.py --stop
"""

import argparse
import atexit
import errno
import fcntl
import json
import os
import select
import shutil
import signal
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

import RNS


APP_NAME = "rnstunnel"
ASPECT   = "endpoint"


TUNSETIFF = 0x400454CA
IFF_TUN   = 0x0001
IFF_NO_PI = 0x1000

DEFAULT_PIDFILE = "/var/run/rns-client.pid"
DEFAULT_LOGFILE = "/var/log/rns-client.log"


# ============================================================================
# Helpers
# ============================================================================
def _netmask_to_cidr(mask):
    return sum(bin(int(x)).count("1") for x in mask.split("."))


def _run(cmd, dry_run=False, check=False):
    if dry_run:
        print(f"[dry-run] {cmd}")
        return (0, "", "")
    try:
        p = subprocess.run(
            cmd, shell=True, check=False,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        return (p.returncode, p.stdout, p.stderr)
    except Exception as e:
        return (1, "", str(e))


# ============================================================================
# Daemon / pidfile
# ============================================================================
def _daemonize(logfile):
    Path(logfile).parent.mkdir(parents=True, exist_ok=True)
    if os.fork() > 0:
        sys.exit(0)
    os.setsid()
    if os.fork() > 0:
        sys.exit(0)
    os.chdir("/")
    os.umask(0o022)
    sys.stdout.flush()
    sys.stderr.flush()
    devnull = open(os.devnull, "rb")
    os.dup2(devnull.fileno(), sys.stdin.fileno())
    log = open(logfile, "ab", buffering=0)
    os.dup2(log.fileno(), sys.stdout.fileno())
    os.dup2(log.fileno(), sys.stderr.fileno())


def _read_pidfile(path):
    try:
        with open(path, "r") as f:
            return int(f.read().strip())
    except (OSError, ValueError):
        return None


def _pid_alive(pid):
    if pid is None or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError as e:
        return e.errno == errno.EPERM


def _write_pidfile(path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        f.write(str(os.getpid()))


def _remove_pidfile(path):
    try:
        os.unlink(path)
    except OSError:
        pass


# ============================================================================
# TUN
# ============================================================================
class TUNDevice:
    def __init__(self, name, local_ip, peer_ip, netmask, mtu, log=None):
        self.name       = name
        self.local_ip   = local_ip
        self.peer_ip    = peer_ip
        self.netmask    = netmask
        self.mtu        = mtu
        self.log        = log or (lambda *a, **kw: None)
        self._fd        = None
        self._stop_evt  = threading.Event()
        self._thread    = None
        self.tx_lock    = threading.Lock()
        self.on_packet  = None
        self.rx_bytes   = 0
        self.tx_bytes   = 0
        self.opened     = False

    def open(self):
        if os.geteuid() != 0:
            raise RuntimeError("Creating TUN on Linux requires root privileges")
        if shutil.which("ip") is None:
            raise RuntimeError("`ip` utility (iproute2) not found")

        self._fd = os.open("/dev/net/tun", os.O_RDWR)
        ifr = struct.pack("16sH", self.name.encode(), IFF_TUN | IFF_NO_PI)
        fcntl.ioctl(self._fd, TUNSETIFF, ifr)

        cidr = _netmask_to_cidr(self.netmask)
        for cmd in [
            f"link set dev {self.name} up",
            f"link set dev {self.name} mtu {self.mtu}",
            f"addr add {self.local_ip}/{cidr} dev {self.name}",
            f"route add {self.peer_ip}/32 dev {self.name}",
        ]:
            rc, _, err = _run(f"ip {cmd}")
            if rc != 0:
                self.log(f"[TUN] ip {cmd} failed: {err.strip()}", "warn")

        self._stop_evt.clear()
        self._thread = threading.Thread(
            target=self._reader, daemon=True, name="tun-rx"
        )
        self._thread.start()
        self.opened = True
        self.log(f"[TUN] {self.name} up ({self.local_ip}/{cidr})", "ok")

    def _reader(self):
        while not self._stop_evt.is_set():
            try:
                r, _, _ = select.select([self._fd], [], [], 0.5)
                if not r:
                    continue
                data = os.read(self._fd, self.mtu + 32)
                if not data:
                    break
                self.rx_bytes += len(data)
                if self.on_packet:
                    try:
                        self.on_packet(data)
                    except Exception as e:
                        self.log(f"[TUN] on_packet: {e}", "err")
            except OSError as e:
                if not self._stop_evt.is_set():
                    self.log(f"[TUN] read: {e}", "err")
                break

    def write(self, data):
        if not self.opened or self._fd is None:
            return False
        with self.tx_lock:
            try:
                os.write(self._fd, data)
                self.tx_bytes += len(data)
                return True
            except OSError as e:
                self.log(f"[TUN] write: {e}", "err")
                return False

    def close(self):
        self._stop_evt.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
        if self._fd is not None:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = None
        self.opened = False
        _run(f"ip link set dev {self.name} down")


# ============================================================================
# Config helpers
# ============================================================================
def find_config_dir():
    for p in [os.path.expanduser("~/.reticulum"),
              os.path.expanduser("~/.config/Reticulum")]:
        if os.path.isdir(p):
            return p
    return None


def parse_reticulum_config(path):
    with open(path, "r", encoding="utf-8") as f:
        lines = f.readlines()
    interfaces = []
    in_interfaces = False
    cur = None
    for i, line in enumerate(lines):
        stripped = line.strip()
        if not in_interfaces and stripped.startswith("[interfaces]"):
            in_interfaces = True
            continue
        if in_interfaces and stripped.startswith("[") and not stripped.startswith("[["):
            in_interfaces = False
            if cur:
                cur["end_line"] = i - 1
                interfaces.append(cur)
                cur = None
            continue
        if in_interfaces:
            if stripped.startswith("[[") and stripped.endswith("]]"):
                if cur is not None:
                    cur["end_line"] = i - 1
                    interfaces.append(cur)
                name = stripped[2:-2].strip()
                cur = {"name": name, "params": {}, "start_line": i, "end_line": i}
            elif cur is not None and "=" in stripped and not stripped.startswith("#"):
                k, _, v = stripped.partition("=")
                cur["params"][k.strip()] = v.strip()
    if cur is not None:
        cur["end_line"] = len(lines) - 1
        interfaces.append(cur)
    return {"interfaces": interfaces, "lines": lines}


def get_rns_server(config_path):
    try:
        parsed = parse_reticulum_config(config_path)
        for it in parsed["interfaces"]:
            p = it["params"]
            if "target_host" in p:
                return p["target_host"]
            if "forward_ip" in p and p["forward_ip"] != "255.255.255.255":
                return p["forward_ip"]
    except Exception:
        pass
    return None


def get_default_gateway():
    try:
        r = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=5,
        )
        for line in r.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[0] == "default":
                return parts[2]
    except Exception:
        pass
    return None


def get_physical_interface():
    try:
        r = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=5,
        )
        for line in r.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 5 and parts[0] == "default":
                return parts[4]
    except Exception:
        pass
    return None


# ============================================================================
# Client
# ============================================================================
class TunnelClient:
    def __init__(self, tun, config_dir, log):
        self.tun        = tun
        self.config_dir = config_dir
        self.log        = log
        self.identity   = None
        self.destination= None
        self.link       = None
        self._link_lock = threading.Lock()
        self._stop_evt  = threading.Event()
        self._ready     = threading.Event()
        self.rx_bytes   = 0
        self.tx_bytes   = 0
        self.rx_packets = 0
        self.tx_packets = 0
        self.link_active= False

        if self.tun is not None:
            self.tun.on_packet = self._tun_to_link

        self._bootstrap()
        if not self._ready.wait(timeout=15):
            self.log("[RNS] bootstrap timeout", "err")

    def connect(self, dest_hash, timeout=30):
        self.dest_hash = dest_hash
        self.timeout = timeout
        self.log(f"[RNS] connecting to {dest_hash}...", "info")
        ok = self._do_connect()
        if ok:
            self.log("[RNS] connected", "ok")
        else:
            self.log("[RNS] connection failed", "err")
        return ok

    def _run(self):
        while not self._stop_evt.is_set():
            time.sleep(0.1)

    def _bootstrap(self):
        try:
            if self.config_dir:
                RNS.Reticulum(configdir=self.config_dir)
            else:
                RNS.Reticulum()
        except Exception as e:
            self.log(f"[RNS] init error: {e}", "err")
            self._ready.set()
            return

        self.log("[RNS] initialised", "ok")

        id_path = None
        if self.config_dir:
            storage = os.path.join(self.config_dir, "storage")
            os.makedirs(storage, exist_ok=True)
            id_path = os.path.join(storage, "linux_cli_identity")
        try:
            if id_path and os.path.isfile(id_path):
                self.identity = RNS.Identity.from_file(id_path)
            else:
                self.identity = RNS.Identity()
                if id_path:
                    self.identity.to_file(id_path)
        except Exception:
            self.identity = RNS.Identity()
            if id_path:
                self.identity.to_file(id_path)

        self.destination = RNS.Destination(
            self.identity,
            RNS.Destination.IN,
            RNS.Destination.SINGLE,
            APP_NAME,
            ASPECT,
        )
        self.destination.set_proof_strategy(RNS.Destination.PROVE_ALL)
        self.destination.set_packet_callback(self._on_direct_packet)
        self.destination.set_link_established_callback(self._on_link_established)
        self.destination.announce()
        self.log(f"[RNS] my hash: {RNS.prettyhexrep(self.destination.hash)}", "ok")
        self._ready.set()

    def _do_connect(self):
        try:
            dest_bytes = bytes.fromhex(self.dest_hash)
        except ValueError:
            self.log(f"[RNS] invalid hash: {self.dest_hash}", "err")
            return False

        if not RNS.Transport.has_path(dest_bytes):
            self.log("[RNS] requesting path...", "info")
            RNS.Transport.request_path(dest_bytes)
            t0 = time.time()
            while not RNS.Transport.has_path(dest_bytes) and time.time() - t0 < self.timeout:
                time.sleep(0.2)
            if not RNS.Transport.has_path(dest_bytes):
                self.log("[RNS] path not found (timeout)", "err")
                return False

        try:
            server_identity = RNS.Identity.recall(dest_bytes)
        except Exception as e:
            self.log(f"[RNS] identity recall: {e}", "err")
            return False

        server_dest = RNS.Destination(
            server_identity,
            RNS.Destination.OUT,
            RNS.Destination.SINGLE,
            APP_NAME,
            ASPECT,
        )
        self.log("[RNS] establishing link...", "info")
        link = RNS.Link(server_dest)
        t0 = time.time()
        while link.status not in (RNS.Link.ACTIVE, RNS.Link.CLOSED) and time.time() - t0 < self.timeout:
            time.sleep(0.1)
        if link.status != RNS.Link.ACTIVE:
            self.log(f"[RNS] link status={link.status}, not active", "err")
            return False
        self._attach_link(link)
        return True

    def _attach_link(self, link):
        with self._link_lock:
            self.link = link
        link.set_link_closed_callback(self._on_link_closed)
        link.set_resource_callback(self._on_resource_advertised)
        link.set_packet_callback(self._on_link_packet)
        self.link_active = True
        self.log("[RNS] link active", "ok")

    def _on_link_established(self, link):
        self._attach_link(link)

    def _on_link_closed(self, link):
        with self._link_lock:
            if self.link is link:
                self.link = None
        self.link_active = False
        self.log("[RNS] link closed", "warn")

    def _on_link_packet(self, message, packet):
        self.rx_bytes += len(message)
        self.rx_packets += 1
        self._tun_write(message)

    def _on_resource_advertised(self, resource):
        resource.set_callback(self._on_resource_complete)
        return True

    def _on_resource_complete(self, resource):
        try:
            data = bytes(resource.data)
        except Exception:
            return
        self.rx_bytes += len(data)
        self.rx_packets += 1
        self._tun_write(data)

    def _on_direct_packet(self, data, packet):
        self._tun_write(data)

    def _tun_to_link(self, data):
        if len(data) < 20:
            return
        version = (data[0] >> 4) & 0xF
        if version == 4:
            dst = data[16:20]
            if dst[0] >= 224 or dst == b'\xff\xff\xff\xff':
                return
        elif version == 6:
            if data[24] == 0xff:
                return
        link = self.link
        if not link or link.status != RNS.Link.ACTIVE:
            return
        try:
            pkt = RNS.Packet(link, data)
            pkt.send()
            self.tx_bytes += len(data)
            self.tx_packets += 1
        except Exception as e:
            self.log(f"[RNS] link.send: {e}", "err")

    def _tun_write(self, data):
        if self.tun and self.tun.opened:
            try:
                self.tun.write(data)
            except Exception:
                pass

    def disconnect(self):
        with self._link_lock:
            link = self.link
            self.link = None
        if link:
            try:
                link.teardown()
            except Exception:
                pass

    def shutdown(self):
        self._stop_evt.set()


# ============================================================================
# Route management
# ============================================================================
class RouteManager:
    def __init__(self, config_path, tun_name, peer_ip, log):
        self.config_path = config_path
        self.tun_name    = tun_name
        self.peer_ip     = peer_ip
        self.log         = log
        self._orig_gw    = None
        self._orig_iface = None
        self._active     = False

    def setup(self):
        gw = get_default_gateway()
        iface = get_physical_interface()
        rns_server = get_rns_server(self.config_path)

        if not gw or not iface:
            self.log("[ROUTES] cannot determine gateway/interface", "err")
            return

        self._orig_gw = gw
        self._orig_iface = iface
        self.log(f"[ROUTES] gateway={gw} iface={iface} peer={self.peer_ip}", "info")

        if rns_server:
            subprocess.run(
                ["ip", "route", "replace", rns_server, "via", gw, "dev", iface, "metric", "5"],
                capture_output=True, timeout=5, check=False,
            )
            self.log(f"[ROUTES] {rns_server} -> {gw} dev {iface} metric 5", "ok")

        subprocess.run(
            ["ip", "route", "replace", "0.0.0.0/0", "via", self.peer_ip, "dev", self.tun_name],
            capture_output=True, timeout=5, check=False,
        )
        self.log(f"[ROUTES] default -> {self.peer_ip} dev {self.tun_name}", "ok")
        self._active = True

    def teardown(self):
        if not self._active:
            return
        self._active = False
        self.log("[ROUTES] removing VPN routes...", "info")
        rns_server = get_rns_server(self.config_path)

        r = subprocess.run(
            ["ip", "route", "del", "0.0.0.0/0", "via", self.peer_ip, "dev", self.tun_name],
            capture_output=True, timeout=5, check=False,
        )
        tun_deleted = r.returncode == 0

        if rns_server:
            subprocess.run(
                ["ip", "route", "del", rns_server],
                capture_output=True, timeout=5, check=False,
            )

        if tun_deleted and self._orig_gw and self._orig_iface:
            subprocess.run(
                ["ip", "route", "add", "default", "via", self._orig_gw, "dev", self._orig_iface],
                capture_output=True, timeout=5, check=False,
            )
            self.log(f"[ROUTES] restored original via {self._orig_gw} dev {self._orig_iface}", "ok")

        self.log("[ROUTES] done", "ok")


# ============================================================================
# Management
# ============================================================================
def _do_status(pidfile):
    pid = _read_pidfile(pidfile)
    if pid is None:
        print(f"[X] no pidfile at {pidfile}", file=sys.stderr)
        return 1
    if _pid_alive(pid):
        print(f"[+] running, pid={pid}, pidfile={pidfile}")
        return 0
    print(f"[X] stale pidfile (pid {pid} dead)")
    return 1


def _do_stop(pidfile):
    pid = _read_pidfile(pidfile)
    if pid is None:
        print(f"[X] no pidfile at {pidfile}", file=sys.stderr)
        return 1
    if not _pid_alive(pid):
        print(f"[X] process {pid} not running")
        _remove_pidfile(pidfile)
        return 1
    print(f"[*] stopping pid={pid}...")
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError as e:
        print(f"[X] kill failed: {e}", file=sys.stderr)
        return 1
    for _ in range(30):
        time.sleep(0.5)
        if not _pid_alive(pid):
            print("[+] stopped")
            _remove_pidfile(pidfile)
            return 0
    print("[!] not stopped in 15s, sending SIGKILL")
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass
    _remove_pidfile(pidfile)
    return 0


# ============================================================================
# main
# ============================================================================
def main():
    ap = argparse.ArgumentParser(
        description="TUN tunnel client over Reticulum (Linux) — CLI",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    ap.add_argument("--dest",       default=os.environ.get("RNS_TUN_DEST"),
                    help="remote TUN endpoint destination hash")
    ap.add_argument("--tun",        default="tun0",       help="TUN interface name")
    ap.add_argument("--tun-ip",     default="10.244.0.2",  help="local TUN IP")
    ap.add_argument("--tun-peer",   default="10.244.0.1",  help="remote TUN peer IP")
    ap.add_argument("--netmask",    default="255.255.255.0", help="TUN netmask")
    ap.add_argument("--mtu",        type=int, default=1500, help="TUN MTU")
    ap.add_argument("--config-dir", default=None,          help="Reticulum config path")
    ap.add_argument("--timeout",    type=int, default=30,   help="connection timeout (seconds)")
    ap.add_argument("--no-stats",   action="store_true",   help="disable statistics output")
    ap.add_argument("--pidfile",    default=DEFAULT_PIDFILE, help="PID file")
    ap.add_argument("--logfile",    default=DEFAULT_LOGFILE, help="log file (for --daemon)")
    ap.add_argument("--daemon",     action="store_true",    help="double fork to background")
    ap.add_argument("--status",     action="store_true",    help="check daemon status")
    ap.add_argument("--stop",       action="store_true",    help="stop daemon")
    args = ap.parse_args()

    if args.status:
        return _do_status(args.pidfile)
    if args.stop:
        return _do_stop(args.pidfile)

    if not args.dest:
        print("[X] specify --dest or environment variable RNS_TUN_DEST", file=sys.stderr)
        return 1

    if os.geteuid() != 0:
        print("[X] root required for TUN. Run with sudo.", file=sys.stderr)
        return 1
    if shutil.which("ip") is None:
        print("[X] iproute2 not found", file=sys.stderr)
        return 1

    if args.pidfile:
        existing = _read_pidfile(args.pidfile)
        if existing and _pid_alive(existing):
            print(f"[X] already running, pid={existing}, pidfile={args.pidfile}", file=sys.stderr)
            return 1

    if args.daemon:
        _daemonize(args.logfile)

    if args.pidfile:
        _write_pidfile(args.pidfile)
        atexit.register(_remove_pidfile, args.pidfile)

    if args.config_dir:
        config_dir = os.path.expanduser(args.config_dir)
    else:
        config_dir = find_config_dir() or os.path.expanduser("~/.reticulum")
    config_dir = os.path.expanduser(config_dir)

    os.environ["RETICULUM_CONFIGDIR"] = config_dir
    cfg_path = os.path.join(config_dir, "config")

    def log(msg, level="info"):
        prefix = {"info": "[*] ", "ok": "[+] ", "warn": "[!] ", "err": "[X] "}.get(level, "[*] ")
        print(prefix + msg, file=sys.stderr, flush=True)

    log(f"config: {config_dir}")
    log(f"dest: {args.dest}")
    log(f"TUN: {args.tun} ip={args.tun_ip} peer={args.tun_peer} mtu={args.mtu}")

    tun = TUNDevice(
        args.tun, args.tun_ip, args.tun_peer, args.netmask, args.mtu, log=log,
    )
    tun.open()

    routes = RouteManager(cfg_path, args.tun, args.tun_peer, log)

    client = TunnelClient(tun, config_dir, log)
    if not client.destination:
        tun.close()
        return 1

    ok = client.connect(args.dest, timeout=args.timeout)
    if not ok:
        routes.teardown()
        tun.close()
        return 1

    routes.setup()

    client._thread = threading.Thread(
        target=client._run, daemon=True, name="rns-client"
    )
    client._thread.start()

    stop_evt = threading.Event()

    def _sig(_a, _b):
        log("signal received, stopping...", "warn")
        stop_evt.set()
    signal.signal(signal.SIGINT, _sig)
    signal.signal(signal.SIGTERM, _sig)

    if not args.no_stats:
        def _stats():
            while not stop_evt.is_set():
                sys.stdout.write(
                    f"\r[TUN:{tun.name}] "
                    f"link={'Y' if client.link_active else 'N'}  "
                    f"rx={tun.rx_bytes:>10} B  tx={tun.tx_bytes:>10} B  "
                    f"pkts rx={client.rx_packets} tx={client.tx_packets}  "
                )
                sys.stdout.flush()
                time.sleep(2)
        threading.Thread(target=_stats, daemon=True).start()

    try:
        while not stop_evt.is_set():
            time.sleep(0.5)
    finally:
        log("stopping...", "info")
        routes.teardown()
        client.disconnect()
        client.shutdown()
        tun.close()
        try:
            RNS.Transport.detach_interfaces()
        except Exception:
            pass
        log("done", "ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
