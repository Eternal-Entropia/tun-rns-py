#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import atexit
import errno
import fcntl
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


DEFAULT_PIDFILE = "/var/run/rns-tunnel.pid"
DEFAULT_LOGFILE = "/var/log/rns-tunnel.log"


# ============================================================================
# Helpers
# ============================================================================
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


def _netmask_to_cidr(mask):
    return sum(bin(int(x)).count("1") for x in mask.split("."))


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
    def __init__(self, name, local_ip, peer_ip, netmask, mtu,
                 mss_clamp=False, dry_run=False, log=print):
        self.name      = name
        self.local_ip  = local_ip
        self.peer_ip   = peer_ip
        self.netmask   = netmask
        self.mtu       = mtu
        self.mss_clamp = mss_clamp
        self.dry_run   = dry_run
        self.log       = log
        self._fd       = None
        self._stop_evt = threading.Event()
        self._reader_th = None
        self.on_packet = None
        self.tx_lock   = threading.Lock()
        self.rx_bytes  = 0
        self.tx_bytes  = 0
        self._rollbacks = []

    def open(self):
        cidr = _netmask_to_cidr(self.netmask)
        if self.dry_run:
            self.log(f"[dry-run] open TUN {self.name} ip={self.local_ip}/{cidr} mtu={self.mtu}")
            self._configure_ip(cidr)
            return
        self._fd = os.open("/dev/net/tun", os.O_RDWR)
        ifr = struct.pack("16sH", self.name.encode("utf-8"), IFF_TUN | IFF_NO_PI)
        fcntl.ioctl(self._fd, TUNSETIFF, ifr)
        self._configure_ip(cidr)
        self._stop_evt.clear()
        self._reader_th = threading.Thread(
            target=self._reader, daemon=True, name=f"tun-{self.name}"
        )
        self._reader_th.start()

    def _configure_ip(self, cidr):
        cmds = [
            ("ip",   f"link set dev {self.name} up"),
            ("ip",   f"link set dev {self.name} mtu {self.mtu}"),
            ("ip",   f"addr add {self.local_ip}/{cidr} dev {self.name}"),
            ("ip",   f"route add {self.peer_ip}/32 dev {self.name}"),
        ]
        if self.mss_clamp:
            mss = max(500, self.mtu - 60)
            cmds.append((
                "iptables",
                f"-t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN "
                f"-o {self.name} -j TCPMSS --set-mss {mss}"
            ))

        for kind, body in cmds:
            full = f"{kind} {body}"
            rc, _, err = _run(full, dry_run=self.dry_run)
            if rc == 0:
                self._rollbacks.append((kind, body))
            else:
                RNS.log(
                    f"{kind} cmd failed (rc={rc}): {body} :: {err.strip()}",
                    RNS.LOG_WARNING,
                )

    def _reader(self):
        RNS.log(f"TUN reader started on {self.name}", RNS.LOG_DEBUG)
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
                        RNS.log(f"TUN on_packet error: {e}", RNS.LOG_ERROR)
            except OSError as e:
                if not self._stop_evt.is_set():
                    RNS.log(f"TUN read error on {self.name}: {e}", RNS.LOG_ERROR)
                break
        RNS.log(f"TUN reader stopped on {self.name}", RNS.LOG_DEBUG)

    def write(self, data):
        if self._fd is None:
            return
        with self.tx_lock:
            try:
                os.write(self._fd, data)
                self.tx_bytes += len(data)
            except OSError as e:
                RNS.log(f"TUN write error on {self.name}: {e}", RNS.LOG_ERROR)

    def close(self):
        self._stop_evt.set()
        if self._reader_th is not None:
            self._reader_th.join(timeout=2.0)
        if self._fd is not None:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = None
        for kind, body in reversed(self._rollbacks):
            if kind == "ip":
                if body.startswith("link set"):
                    rev = body.replace(" up", " down")
                elif body.startswith("addr add"):
                    rev = body.replace("addr add", "addr del")
                elif body.startswith("route add"):
                    rev = body.replace("route add", "route del")
                else:
                    rev = body
                _run(f"ip {rev}", check=False)
            elif kind == "iptables":
                rev = body.replace(" -A ", " -D ")
                _run(f"iptables {rev}", check=False)
        self._rollbacks.clear()
        if not self.dry_run:
            _run(f"ip link set dev {self.name} down", check=False)


# ============================================================================
# Endpoint
# ============================================================================
class TunnelEndpoint:
    def __init__(self, tun, identity_path, log=print):
        self.tun          = tun
        self.identity_path = identity_path
        self.log          = log
        self.identity     = None
        self.destination  = None
        self.links        = []
        self._lock        = threading.Lock()
        self._stop_evt    = threading.Event()
        self._ready       = threading.Event()
        if self.tun is not None:
            self.tun.on_packet = self._on_tun_packet
        self._bootstrap()
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="rns-endpoint"
        )
        self._thread.start()
        if not self._ready.wait(timeout=15):
            self.log("[RNS] bootstrap timeout (15s)", "err")

    def _run(self):
        while not self._stop_evt.is_set():
            time.sleep(0.1)

    def _bootstrap(self):
        try:
            RNS.Reticulum()
        except Exception as e:
            self.log(f"[RNS] init error: {e}", "err")
            self._ready.set()
            return

        storage = os.path.dirname(self.identity_path)
        if storage:
            os.makedirs(storage, exist_ok=True)
        try:
            self.identity = RNS.Identity.from_file(self.identity_path)
            self.log(f"[RNS] identity loaded: {RNS.prettyhexrep(self.identity.hash)}", "ok")
        except Exception:
            self.identity = RNS.Identity()
            self.identity.to_file(self.identity_path)
            self.log(f"[RNS] identity created: {RNS.prettyhexrep(self.identity.hash)}", "ok")

        self.destination = RNS.Destination(
            self.identity,
            RNS.Destination.IN,
            RNS.Destination.SINGLE,
            APP_NAME,
            ASPECT,
        )
        self.destination.set_proof_strategy(RNS.Destination.PROVE_ALL)
        self.destination.set_packet_callback(self._on_direct_packet)
        self.destination.set_link_established_callback(self._on_link)
        self.destination.announce()
        self.log(f"[RNS] endpoint hash: {RNS.prettyhexrep(self.destination.hash)}", "info")
        self._ready.set()

    def _on_link(self, link):
        with self._lock:
            self.links.append(link)
        link.set_link_closed_callback(self._on_link_closed)
        link.set_resource_callback(self._on_resource_advertised)
        link.set_packet_callback(self._on_direct_packet)
        self.log(
            f"[RNS] link established with "
            f"{RNS.prettyhexrep(link.destination.hash) if link.destination else '?'}",
            "ok",
        )

    def _on_link_closed(self, link):
        with self._lock:
            if link in self.links:
                self.links.remove(link)
        self.log("[RNS] link closed", "warn")

    def _on_resource_advertised(self, resource):
        resource.set_callback(self._on_resource_complete)
        return True

    def _on_resource_complete(self, resource):
        try:
            data = bytes(resource.data)
        except Exception as e:
            self.log(f"Bad resource: {e}", "err")
            return
        if self.tun is not None:
            self.tun.write(data)

    def _on_direct_packet(self, data, packet):
        if self.tun is not None:
            self.tun.write(data)

    def _on_tun_packet(self, data):
        if self.identity is None or not self.links:
            return
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
        self.send_to_links(data)

    def send_to_links(self, data):
        with self._lock:
            links = [l for l in self.links if l.status == RNS.Link.ACTIVE]
        for link in links:
            try:
                pkt = RNS.Packet(link, data)
                pkt.send()
            except Exception as e:
                self.log(f"Link send failed: {e}", "err")

    def shutdown(self):
        self._stop_evt.set()


# ============================================================================
# Config
# ============================================================================
def find_config_dir():
    for p in [os.path.expanduser("~/.reticulum"),
              os.path.expanduser("~/.config/Reticulum")]:
        if os.path.isdir(p):
            return p
    return None


def generate_default_config(config_dir):
    config_dir = Path(config_dir).expanduser()
    config_dir.mkdir(parents=True, exist_ok=True)
    cfg = config_dir / "config"
    if not cfg.exists():
        cfg.write_text("""# Minimal Reticulum config generated by tun_rns_linux.py
[reticulum]
  share_instance = True
  enable_transport = True
  instance_name = tun-node

[interfaces]
  # [[Default Interface]]
  #   type = TCPInterface
  #   enabled = True
  #   listen_ip = 0.0.0.0
  #   listen_port = 4242
""")
    return str(config_dir)


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
    print(f"[X] pidfile exists but process {pid} is dead (stale pidfile)")
    return 1


def _do_stop(pidfile):
    pid = _read_pidfile(pidfile)
    if pid is None:
        print(f"[X] no pidfile at {pidfile}", file=sys.stderr)
        return 1
    if not _pid_alive(pid):
        print(f"[X] process {pid} not running (cleaning stale pidfile)")
        _remove_pidfile(pidfile)
        return 1
    print(f"[*] sending SIGTERM to pid={pid} ...")
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
def _make_argparser():
    p = argparse.ArgumentParser(
        description="TUN tunnel endpoint over Reticulum (Linux)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--tun",        default="tun0",          help="name of TUN-interface")
    p.add_argument("--ip",         default="10.244.0.1",      help="local IP TUN")
    p.add_argument("--peer",       default="10.244.0.2",      help="IP dest (route with TUN)")
    p.add_argument("--netmask",    default="255.255.255.0", help="netmask")
    p.add_argument("--mtu",        type=int, default=1500,  help="MTU TUN-interface")
    p.add_argument("--config-dir", default=None,           help="config dir Reticulum")
    p.add_argument("--no-stats",   action="store_true",    help="no stats")
    p.add_argument("--mss-clamp",  action="store_true",    help="iptables TCPMSS on tun0 (PMTUD for traffic through the tunnel)")
    p.add_argument("--pidfile",    default=DEFAULT_PIDFILE, help="PID-file")
    p.add_argument("--logfile",    default=DEFAULT_LOGFILE, help="log-file (for --daemon)")
    p.add_argument("--daemon",     action="store_true",    help="double fork in the background")
    p.add_argument("--status",     action="store_true",    help="show status daemon and exit")
    p.add_argument("--stop",       action="store_true",    help="stop daemon and exit")
    p.add_argument("--dry-run",    action="store_true",    help="print command: ip/iptables without executing")
    return p


def main():
    ap = _make_argparser()
    args = ap.parse_args()

    if args.status:
        return _do_status(args.pidfile)
    if args.stop:
        return _do_stop(args.pidfile)

    if not args.dry_run and os.geteuid() != 0:
        print("!!! Нужен root для создания TUN. Запустите через sudo.", file=sys.stderr)
        return 1
    if not args.dry_run and shutil.which("ip") is None:
        print("!!! Утилита `ip` (iproute2) не найдена в PATH.", file=sys.stderr)
        return 1

    if not args.dry_run and args.pidfile:
        existing = _read_pidfile(args.pidfile)
        if existing and _pid_alive(existing):
            print(f"[X] already running, pid={existing}, pidfile={args.pidfile}", file=sys.stderr)
            return 1

    if args.daemon:
        if args.dry_run:
            print(f"[dry-run] would daemonize, logfile={args.logfile}, pidfile={args.pidfile}")
        else:
            _daemonize(args.logfile)

    if not args.dry_run and args.pidfile:
        _write_pidfile(args.pidfile)
        atexit.register(_remove_pidfile, args.pidfile)

    if args.config_dir:
        config_dir = os.path.expanduser(args.config_dir)
    else:
        config_dir = find_config_dir() or "~/.reticulum"
    config_dir = os.path.expanduser(config_dir)
    if not args.dry_run and not os.path.isdir(config_dir):
        config_dir = generate_default_config(config_dir)

    os.environ["RETICULUM_CONFIGDIR"] = config_dir
    identity_path = os.path.join(config_dir, "storage", "tunnel_endpoint_identity")

    def log(msg, level="info"):
        prefix = {"info": "[*] ", "ok": "[+] ", "warn": "[!] ", "err": "[X] "}.get(level, "[*] ")
        print(prefix + msg, file=sys.stderr, flush=True)

    log(f"TUN: name={args.tun} ip={args.ip} peer={args.peer} mtu={args.mtu} mss_clamp={args.mss_clamp}")
    log(f"config: {config_dir}")
    if args.daemon:
        log(f"daemon mode: logfile={args.logfile} pidfile={args.pidfile}")
    if args.dry_run:
        log("DRY-RUN: changes are not applied", "warn")

    tun = TUNDevice(
        args.tun, args.ip, args.peer, args.netmask, args.mtu,
        mss_clamp=args.mss_clamp, dry_run=args.dry_run, log=log,
    )
    if not args.dry_run:
        tun.open()

    endpoint = TunnelEndpoint(
        tun if not args.dry_run else None,
        identity_path,
        log=log,
    )
    if not args.dry_run and not endpoint.identity:
        print("[X] error for init Reticulum endpoint", file=sys.stderr)
        return 1

    if endpoint.destination:
        log(f"endpoint hash: {RNS.prettyhexrep(endpoint.destination.hash)}")
    log("waiting for RNS.Link-connect ... (Ctrl-C, SIGTERM or --stop for exit)")

    stop_evt = threading.Event()

    def _sig(_a, _b):
        log("signal received, stopping...", "warn")
        stop_evt.set()
    signal.signal(signal.SIGINT, _sig)
    signal.signal(signal.SIGTERM, _sig)

    if not args.no_stats and not args.dry_run:
        def _stats():
            while not stop_evt.is_set():
                with endpoint._lock:
                    nlinks = len(endpoint.links)
                sys.stdout.write(
                    f"\r[TUN:{tun.name} {tun.local_ip}] "
                    f"links={nlinks}  "
                    f"rx={tun.rx_bytes:>10} B  tx={tun.tx_bytes:>10} B   "
                )
                sys.stdout.flush()
                time.sleep(5)
        threading.Thread(target=_stats, daemon=True).start()

    try:
        while not stop_evt.is_set():
            time.sleep(0.5)
    finally:
        log("stoping...", "info")
        endpoint.shutdown()
        if not args.dry_run:
            tun.close()
            try:
                RNS.Transport.detach_interfaces()
            except Exception:
                pass
        log("ready.", "ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
