#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TUN tunnel over Reticulum — Linux GUI client (Tkinter).

GUI program for Linux. Uses standard Reticulum config
(~/.reticulum) — NOT isolated. Features:
  - displays own destination hash;
  - connects to a TUN endpoint by its hash;
  - accepts incoming RNS.Link connections (server mode);
  - starts a TUN adapter (via /dev/net/tun);
  - displays traffic, sends test data through the tunnel.

TUN <-> Link bridge protocol matches tun_rns_linux.py:
    TUN <--ip packet--> bridge <--RNS.Resource--> Link <-- Reticulum

Dependencies:
    pip install rns

Build to executable (Linux):
    build.sh
"""

import argparse
import atexit
import errno
import fcntl
import json
import os
import queue
import select
import shutil
import signal
import struct
import subprocess
import sys
import threading
import time
import traceback
import tkinter as tk
from pathlib import Path
from tkinter import ttk, messagebox, scrolledtext

import RNS


# ============================================================================
# Protocol constants (must match tun_rns_linux.py)
# ============================================================================
APP_NAME    = "rnstunnel"
ASPECT      = "endpoint"
APP_DIRNAME = "ReticulumTUN"

TUNSETIFF = 0x400454CA
IFF_TUN   = 0x0001
IFF_NO_PI = 0x1000


# ============================================================================
# Standard Reticulum config location (NOT isolated)
# ============================================================================
def default_config_dir():
    return str(Path.home() / ".reticulum")


def ensure_default_config(config_dir):
    config_dir = Path(config_dir)
    config_dir.mkdir(parents=True, exist_ok=True)
    cfg = config_dir / "config"
    if cfg.exists():
        return str(config_dir)
    cfg.write_text(f"""# Reticulum config for ReticulumTUN (Linux)
# Config dir: {config_dir}

[reticulum]
  share_instance = True
  enable_transport = True
  instance_name = rnstunnel-linux

[interfaces]
""", encoding="utf-8")
    (config_dir / "storage").mkdir(exist_ok=True)
    return str(config_dir)


# ============================================================================
# Linux TUN
# ============================================================================
def _netmask_to_cidr(mask):
    return sum(bin(int(x)).count("1") for x in mask.split("."))


class LinuxTunInterface:
    def __init__(self, name="tun0", local_ip="10.244.0.2", peer_ip="10.244.0.1",
                 netmask="255.255.255.0", mtu=1500, log=None):
        self.name      = name
        self.local_ip  = local_ip
        self.peer_ip   = peer_ip
        self.netmask   = netmask
        self.mtu       = mtu
        self.log       = log or (lambda *a, **kw: None)
        self._fd       = None
        self._stop_evt = threading.Event()
        self._thread   = None
        self.tx_lock   = threading.Lock()
        self.on_packet = None
        self.rx_bytes  = 0
        self.tx_bytes  = 0
        self.opened    = False

    def open(self):
        if os.geteuid() != 0:
            raise RuntimeError(
                "Creating TUN on Linux requires root privileges.\n"
                "Run with sudo."
            )
        if shutil.which("ip") is None:
            raise RuntimeError("`ip` utility (iproute2) not found in PATH.")

        self._fd = os.open("/dev/net/tun", os.O_RDWR)
        ifr = struct.pack("16sH", self.name.encode("utf-8"), IFF_TUN | IFF_NO_PI)
        fcntl.ioctl(self._fd, TUNSETIFF, ifr)

        cidr = _netmask_to_cidr(self.netmask)
        cmds = [
            f"link set dev {self.name} up",
            f"link set dev {self.name} mtu {self.mtu}",
            f"addr add {self.local_ip}/{cidr} dev {self.name}",
            f"route add {self.peer_ip}/32 dev {self.name}",
        ]
        for cmd in cmds:
            rc, _, err = self._run(f"ip {cmd}")
            if rc != 0:
                self.log(f"[TUN] ip {cmd} failed: {err.strip()}", "warn")

        self._stop_evt.clear()
        self._thread = threading.Thread(target=self._reader, daemon=True, name="tun-rx")
        self._thread.start()
        self.opened = True
        self.log(f"[TUN] adapter '{self.name}' started ({self.local_ip}/{cidr})", "ok")

    def _run(self, cmd):
        try:
            p = subprocess.run(
                cmd, shell=True, check=False,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            return (p.returncode, p.stdout, p.stderr)
        except Exception as e:
            return (1, "", str(e))

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
                        self.log(f"[TUN] on_packet error: {e}", "err")
            except OSError as e:
                if not self._stop_evt.is_set():
                    self.log(f"[TUN] read error: {e}", "err")
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
                self.log(f"[TUN] write error: {e}", "err")
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
        # reset TUN settings
        self._run(f"ip link set dev {self.name} down")


# ============================================================================
# Reticulum node
# ============================================================================
class ReticulumNode:
    def __init__(self, log_fn, config_dir=None):
        self.log_fn     = log_fn
        self.config_dir = config_dir
        self._ready     = threading.Event()
        self._stop_evt  = threading.Event()
        self.identity   = None
        self.destination= None
        self.link       = None
        self._link_lock = threading.Lock()
        self.tun        = None
        self._tun_active= False
        self.on_link_state = None
        self.rx_bytes   = 0
        self.tx_bytes   = 0
        self.rx_packets = 0
        self.tx_packets = 0
        self._bootstrap()
        self._thread    = threading.Thread(target=self._run, daemon=True, name="rns-core")
        self._thread.start()
        self._ready.wait(timeout=10)

    def set_tun(self, tun):
        if self.tun:
            self.tun.on_packet = None
        self.tun = tun
        if tun:
            tun.on_packet = self._tun_to_link
            self._tun_active = True
        else:
            self._tun_active = False

    def _run(self):
        while not self._stop_evt.is_set():
            time.sleep(0.1)

    def _bootstrap(self):
        log = self.log_fn
        try:
            log("[RNS] initializing Reticulum...", "info")
            if self.config_dir:
                RNS.Reticulum(configdir=self.config_dir)
            else:
                RNS.Reticulum()
            log("[RNS] Reticulum initialized", "ok")
        except SystemExit as e:
            log(f"[RNS] SystemExit: {e}", "err")
            self._ready.set()
            return
        except Exception as e:
            tb = traceback.format_exc()
            log(f"[RNS] init error: {e}", "err")
            for line in tb.splitlines():
                log(f"  {line}", "err")
            self._ready.set()
            return

        id_path = None
        if self.config_dir:
            storage = os.path.join(self.config_dir, "storage")
            os.makedirs(storage, exist_ok=True)
            id_path = os.path.join(storage, "linux_gui_identity")
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
        self.log_fn(f"[RNS] ready, hash: {RNS.prettyhexrep(self.destination.hash)}", "ok")
        self._ready.set()

    def re_announce(self):
        if self.destination:
            self.destination.announce()
            self.log_fn("[RNS] announce sent", "info")

    def connect_to(self, dest_hash_hex, timeout=30):
        try:
            dest_hash = bytes.fromhex(dest_hash_hex)
        except ValueError:
            self.log_fn("[RNS] invalid hash", "err")
            return False

        if not RNS.Transport.has_path(dest_hash):
            self.log_fn("[RNS] requesting path to endpoint...", "info")
            RNS.Transport.request_path(dest_hash)
            t0 = time.time()
            while not RNS.Transport.has_path(dest_hash) and time.time() - t0 < timeout:
                time.sleep(0.2)
            if not RNS.Transport.has_path(dest_hash):
                self.log_fn("[RNS] path not found (timeout)", "err")
                return False

        try:
            server_identity = RNS.Identity.recall(dest_hash)
        except Exception as e:
            self.log_fn(f"[RNS] identity recall failed: {e}", "err")
            return False

        server_dest = RNS.Destination(
            server_identity,
            RNS.Destination.OUT,
            RNS.Destination.SINGLE,
            APP_NAME,
            ASPECT,
        )

        self.log_fn("[RNS] establishing link...", "info")
        if self.on_link_state:
            self.on_link_state("connecting")
        link = RNS.Link(server_dest)
        t0 = time.time()
        while link.status not in (RNS.Link.ACTIVE, RNS.Link.CLOSED) and time.time() - t0 < timeout:
            time.sleep(0.1)
        if link.status != RNS.Link.ACTIVE:
            self.log_fn(f"[RNS] link status={link.status}, not activated", "err")
            if self.on_link_state:
                self.on_link_state("failed")
            return False
        self._attach_link(link)
        return True

    def _attach_link(self, link):
        with self._link_lock:
            self.link = link
        link.set_link_closed_callback(self._on_link_closed)
        link.set_resource_callback(self._on_resource_advertised)
        link.set_packet_callback(self._on_link_packet)
        if self.on_link_state:
            self.on_link_state("active")
        self.log_fn("[RNS] link active", "ok")

    def _on_link_established(self, link):
        self._attach_link(link)

    def _on_link_closed(self, link):
        with self._link_lock:
            if self.link is link:
                self.link = None
        if self.on_link_state:
            self.on_link_state("closed")
        self.log_fn("[RNS] link closed", "warn")

    def _on_link_packet(self, message, packet):
        self.rx_bytes   += len(message)
        self.rx_packets += 1
        self._tun_write(message)

    def _on_resource_advertised(self, resource):
        resource.set_callback(self._on_resource_complete)
        return True

    def _on_resource_complete(self, resource):
        try:
            data = bytes(resource.data)
        except Exception as e:
            self.log_fn(f"[RNS] bad resource: {e}", "err")
            return
        self.rx_bytes   += len(data)
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
            self.tx_bytes   += len(data)
            self.tx_packets += 1
        except Exception as e:
            self.log_fn(f"[RNS] link.send failed: {e}", "err")

    def _tun_write(self, data):
        if self._tun_active and self.tun:
            try:
                self.tun.write(data)
            except Exception as e:
                self.log_fn(f"[TUN] write failed: {e}", "err")

    def disconnect(self):
        link = self.link
        if link:
            try:
                link.teardown()
            except Exception:
                pass

    def shutdown(self):
        self._stop_evt.set()


# ============================================================================
# File logger with rotation
# ============================================================================
class FileLogger:
    MAX_BYTES = 2 * 1024 * 1024

    def __init__(self, log_dir):
        from datetime import datetime
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.path = self.log_dir / "rnstunnel.log"
        self._lock = threading.Lock()
        try:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(f"\n{'='*60}\n")
                f.write(f"  {datetime.now().isoformat(timespec='seconds')}  PID={os.getpid()}\n")
                f.write(f"  cwd={os.getcwd()}\n")
                f.write(f"  log={self.path}\n")
                f.write(f"{'='*60}\n")
        except Exception as e:
            print(f"[FileLogger] cannot open log file: {e}", file=sys.stderr)

    def write(self, msg, level="info"):
        from datetime import datetime
        ts = datetime.now().strftime('%H:%M:%S.%f')[:-3]
        line = f"{ts} [{level.upper():5}] {msg}"
        with self._lock:
            try:
                if self.path.exists() and self.path.stat().st_size > self.MAX_BYTES:
                    self._rotate()
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
                    f.flush()
            except Exception:
                pass

    def _rotate(self):
        try:
            backup = self.path.with_suffix(self.path.suffix + ".1")
            if backup.exists():
                backup.unlink()
            self.path.rename(backup)
        except Exception:
            pass

    def path_str(self):
        return str(self.path)


# ============================================================================
# Reticulum config parser/serializer
# ============================================================================
def parse_reticulum_config(path):
    with open(path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    interfaces = []
    in_interfaces = False
    cur = None
    interfaces_start = -1
    interfaces_end   = -1

    for i, line in enumerate(lines):
        stripped = line.strip()
        if not in_interfaces and stripped.startswith("[interfaces]"):
            in_interfaces = True
            interfaces_start = i
            continue
        if in_interfaces and stripped.startswith("[") and not stripped.startswith("[["):
            in_interfaces = False
            if cur:
                cur["end_line"] = i - 1
                interfaces.append(cur)
                cur = None
            interfaces_end = i - 1
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
    if interfaces_start >= 0 and interfaces_end < 0:
        interfaces_end = len(lines) - 1

    return {
        "interfaces": interfaces,
        "lines": lines,
        "interfaces_start": interfaces_start,
        "interfaces_end":   interfaces_end,
    }


def serialize_interfaces(interfaces):
    out = ["[interfaces]\n"]
    for iface in interfaces:
        name = iface["name"]
        out.append(f"  [[{name}]]\n")
        params = iface.get("params", {})
        order = ["type", "enabled"] + [k for k in params if k not in ("type", "enabled")]
        for k in order:
            if k in params:
                out.append(f"    {k} = {params[k]}\n")
        out.append("\n")
    return out


VALID_INTERFACE_TYPES = {
    "TCPServerInterface",
    "TCPClientInterface",
    "UDPInterface",
}


def validate_interfaces(interfaces):
    errors = []
    for it in interfaces:
        name = it["name"]
        p = it["params"]
        t = p.get("type", "")
        if t not in VALID_INTERFACE_TYPES:
            errors.append(f"[[{name}]]: type={t!r} — invalid type (need: {', '.join(sorted(VALID_INTERFACE_TYPES))})")
        if t == "UDPInterface":
            if "listen_ip" not in p or "listen_port" not in p:
                errors.append(f"[[{name}]]: UDPInterface requires listen_ip + listen_port (otherwise RNS crashes)")
            if "forward_ip" not in p:
                errors.append(f"[[{name}]]: UDPInterface without forward_ip — nothing to send (need broadcast or specific IP)")
    return errors


def update_config_interfaces(path, interfaces):
    errors = validate_interfaces(interfaces)
    if errors:
        return False, errors

    parsed = parse_reticulum_config(path)
    lines = parsed["lines"]
    new_block = serialize_interfaces(interfaces)

    if parsed["interfaces_start"] >= 0:
        start = parsed["interfaces_start"]
        end   = parsed["interfaces_end"] + 1
        new_lines = lines[:start] + new_block + lines[end:]
    else:
        if lines and not lines[-1].endswith("\n"):
            lines.append("\n")
        new_lines = lines + ["\n"] + new_block

    with open(path, "w", encoding="utf-8") as f:
        f.writelines(new_lines)
    return True, []


# ============================================================================
# Interface settings window
# ============================================================================
class InterfaceSettingsDialog(tk.Toplevel):
    def __init__(self, parent, config_path, on_close=None):
        super().__init__(parent)
        self.title("Interface Settings")
        self.configure(bg="#1e1e1e")
        self.transient(parent)
        self.grab_set()
        self.resizable(False, False)
        self.geometry("420x320")

        self.config_path = config_path
        self.on_close    = on_close

        self._load_current()

        frm = ttk.Frame(self, padding=16)
        frm.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frm, text="Protocol:", font=("Segoe UI", 10, "bold")).grid(row=0, column=0, sticky=tk.W, pady=4)
        self.var_proto = tk.StringVar(value=self._current_proto)
        r0 = ttk.Frame(frm); r0.grid(row=0, column=1, sticky=tk.W, pady=4)
        ttk.Radiobutton(r0, text="UDP", variable=self.var_proto, value="udp").pack(side=tk.LEFT, padx=(0, 12))
        ttk.Radiobutton(r0, text="TCP", variable=self.var_proto, value="tcp").pack(side=tk.LEFT)

        ttk.Label(frm, text="Mode:", font=("Segoe UI", 10, "bold")).grid(row=1, column=0, sticky=tk.W, pady=4)
        self.var_role = tk.StringVar(value=self._current_role)
        r1 = ttk.Frame(frm); r1.grid(row=1, column=1, sticky=tk.W, pady=4)
        ttk.Radiobutton(r1, text="Client", variable=self.var_role, value="client").pack(side=tk.LEFT, padx=(0, 12))
        ttk.Radiobutton(r1, text="Server", variable=self.var_role, value="server").pack(side=tk.LEFT)

        ttk.Label(frm, text="IP address:", font=("Segoe UI", 10, "bold")).grid(row=2, column=0, sticky=tk.W, pady=4)
        self.var_ip = tk.StringVar(value=self._current_ip)
        ent_ip = ttk.Entry(frm, textvariable=self.var_ip, width=24, font=("Consolas", 11))
        ent_ip.grid(row=2, column=1, sticky=tk.W, pady=4, padx=(0, 0))

        ttk.Label(frm, text="Port:", font=("Segoe UI", 10, "bold")).grid(row=3, column=0, sticky=tk.W, pady=4)
        self.var_port = tk.StringVar(value=self._current_port)
        ent_port = ttk.Entry(frm, textvariable=self.var_port, width=10, font=("Consolas", 11))
        ent_port.grid(row=3, column=1, sticky=tk.W, pady=4)

        self.lbl_hint = ttk.Label(frm, text="", foreground="#888", wraplength=380)
        self.lbl_hint.grid(row=4, column=0, columnspan=2, sticky=tk.W, pady=(8, 4))
        self._update_hint()

        self.var_proto.trace_add("write", lambda *_: self._update_hint())
        self.var_role.trace_add("write", lambda *_: self._update_hint())

        btn_row = ttk.Frame(frm)
        btn_row.grid(row=5, column=0, columnspan=2, pady=(16, 0))
        ttk.Button(btn_row, text="Save", command=self._on_save).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(btn_row, text="Cancel", command=self.destroy).pack(side=tk.LEFT)

        frm.columnconfigure(1, weight=1)

    def _load_current(self):
        self._current_proto = "udp"
        self._current_role  = "client"
        self._current_ip    = ""
        self._current_port  = "4242"

        try:
            parsed = parse_reticulum_config(self.config_path)
            ifaces = parsed.get("interfaces", [])
            if ifaces:
                it = ifaces[0]
                p = it.get("params", {})
                t = p.get("type", "")
                if "UDPInterface" in t:
                    self._current_proto = "udp"
                elif "TCPClient" in t:
                    self._current_proto = "tcp"
                    self._current_role = "client"
                elif "TCPServer" in t:
                    self._current_proto = "tcp"
                    self._current_role = "server"

                if self._current_proto == "udp":
                    if self._current_role == "client":
                        self._current_ip = p.get("forward_ip", "")
                        self._current_port = p.get("forward_port", p.get("listen_port", "4242"))
                    else:
                        self._current_ip = p.get("listen_ip", "0.0.0.0")
                        self._current_port = p.get("listen_port", "4242")
                else:
                    if self._current_role == "client":
                        self._current_ip = p.get("target_host", "")
                        self._current_port = p.get("target_port", "4242")
                    else:
                        self._current_ip = p.get("listen_ip", "0.0.0.0")
                        self._current_port = p.get("listen_port", "4242")
        except Exception:
            pass

    def _update_hint(self):
        proto = self.var_proto.get()
        role  = self.var_role.get()
        hints = {
            ("udp", "client"): "UDP Client: packets sent to specified IP:port",
            ("udp", "server"): "UDP Server: listens and responds to all (broadcast)",
            ("tcp", "client"): "TCP Client: connects to specified IP:port",
            ("tcp", "server"): "TCP Server: listens for incoming connections",
        }
        self.lbl_hint.config(text=hints.get((proto, role), ""))

    def _on_save(self):
        proto = self.var_proto.get()
        role  = self.var_role.get()
        ip    = self.var_ip.get().strip()
        port  = self.var_port.get().strip() or "4242"

        if not ip:
            messagebox.showwarning("No IP", "Enter an IP address.", parent=self)
            return
        try:
            int(port)
        except ValueError:
            messagebox.showwarning("Invalid port", "Port must be a number.", parent=self)
            return

        if proto == "udp":
            if role == "client":
                iface = {
                    "name": "UDP Client",
                    "params": {
                        "type": "UDPInterface",
                        "enabled": "True",
                        "listen_ip": "0.0.0.0",
                        "listen_port": "4242",
                        "forward_ip": ip,
                        "forward_port": port,
                    }
                }
            else:
                iface = {
                    "name": "UDP Server",
                    "params": {
                        "type": "UDPInterface",
                        "enabled": "True",
                        "listen_ip": ip,
                        "listen_port": port,
                        "forward_ip": "255.255.255.255",
                        "forward_port": port,
                    }
                }
        else:
            if role == "client":
                iface = {
                    "name": "TCP Client",
                    "params": {
                        "type": "TCPClientInterface",
                        "enabled": "True",
                        "target_host": ip,
                        "target_port": port,
                    }
                }
            else:
                iface = {
                    "name": "TCP Server",
                    "params": {
                        "type": "TCPServerInterface",
                        "enabled": "True",
                        "listen_ip": ip,
                        "listen_port": port,
                    }
                }

        errors = validate_interfaces([iface])
        if errors:
            messagebox.showerror("Error", "\n".join(errors), parent=self)
            return

        ok, write_errors = update_config_interfaces(self.config_path, [iface])
        if not ok:
            messagebox.showerror("Write error", "\n".join(write_errors), parent=self)
            return

        if self.on_close:
            self.on_close()
        self.destroy()


# ============================================================================
# GUI
# ============================================================================
class App(tk.Tk):
    BG     = "#1e1e1e"
    FG     = "#e0e0e0"
    ACCENT = "#4fc3f7"
    OK     = "#81c784"
    WARN   = "#ffb74d"
    ERR    = "#e57373"
    PANEL  = "#252526"
    BTN    = "#007acc"
    ENTRY  = "#3c3c3c"

    def __init__(self, args):
        super().__init__()
        self.args = args
        self.title("Reticulum TUN Tunnel — Linux GUI")
        self.geometry("820x600")
        self.minsize(720, 520)
        self.configure(bg=self.BG)

        self._configure_style()
        self._build_ui()
        self._log_queue = queue.Queue()

        cfg_dir = args.config_dir if args.config_dir else default_config_dir()
        cfg_dir = os.path.expanduser(cfg_dir)
        cfg_dir = ensure_default_config(cfg_dir)
        args.config_dir = cfg_dir

        self.file_logger = FileLogger(Path(cfg_dir) / "logs")
        self._file_log("APP START", f"exe={__file__}")
        self._file_log("APP START", f"config_dir={cfg_dir}")
        self._file_log("APP START", f"python={sys.version}")
        self._file_log("APP START", f"platform={sys.platform}")

        cfg_path = Path(cfg_dir) / "config"
        if cfg_path.exists():
            try:
                content = cfg_path.read_text(encoding="utf-8")
                self._file_log("CONFIG", f"=== {cfg_path} ===")
                for line in content.splitlines():
                    self._file_log("CONFIG", line)
            except Exception as e:
                self._file_log("CONFIG", f"read error: {e}")

        self.after(50, self._drain_log_queue)

        self.node = ReticulumNode(
            log_fn=self._qlog,
            config_dir=cfg_dir,
        )
        self.node.on_link_state = self._on_link_state

        self.after(800, lambda: self._qlog(f"Config dir: {cfg_dir}", "info"))
        self.after(820, lambda: self._qlog(f"Log file : {self.file_logger.path_str()}", "info"))

        if os.geteuid() == 0:
            self.after(850, lambda: self._qlog("TUN: root privileges available", "ok"))
        else:
            self.after(850, lambda: self._qlog("TUN: NO root privileges (TUN will be unavailable without sudo)", "warn"))

        self.after(500, self._refresh_identity)
        self.after(500, self._refresh_stats)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        if args.pidfile:
            _write_pidfile(args.pidfile)
            atexit.register(_remove_pidfile, args.pidfile)
            self._file_log("PIDFILE", f"wrote pid={os.getpid()} to {args.pidfile}")

        self._load_tunnel_settings()

    def _configure_style(self):
        s = ttk.Style(self)
        s.theme_use("clam")
        s.configure("TFrame",        background=self.BG)
        s.configure("Panel.TFrame",  background=self.PANEL)
        s.configure("TLabel",        background=self.BG, foreground=self.FG)
        s.configure("Panel.TLabel",  background=self.PANEL, foreground=self.FG)
        s.configure("Header.TLabel", background=self.BG, foreground=self.ACCENT, font=("Segoe UI", 11, "bold"))
        s.configure("Stat.TLabel",   background=self.PANEL, foreground=self.ACCENT, font=("Consolas", 10, "bold"))
        s.configure("TButton",       background=self.BTN, foreground="#ffffff", padding=(10, 5))
        s.map("TButton",     background=[("active", "#1188dd")])
        s.configure("TEntry",        fieldbackground=self.ENTRY, foreground=self.FG, insertcolor=self.FG)
        s.configure("TLabelframe",   background=self.BG, foreground=self.ACCENT)
        s.configure("TLabelframe.Label", background=self.BG, foreground=self.ACCENT, font=("Segoe UI", 10, "bold"))

    def _build_ui(self):
        top = ttk.Frame(self, style="Panel.TFrame", padding=10)
        top.pack(side=tk.TOP, fill=tk.X)
        ttk.Label(top, text="My destination hash:", style="Panel.TLabel").pack(side=tk.LEFT)
        self.lbl_hash = ttk.Label(top, text="(initializing...)", style="Stat.TLabel")
        self.lbl_hash.pack(side=tk.LEFT, padx=8)
        ttk.Button(top, text="Logs",   command=self._open_logs).pack(side=tk.RIGHT, padx=(0, 6))
        ttk.Button(top, text="Interfaces", command=self._open_settings).pack(side=tk.RIGHT, padx=(0, 6))
        ttk.Button(top, text="Copy", command=self._copy_hash).pack(side=tk.RIGHT)

        box_log = ttk.LabelFrame(self, text="Log")
        box_log.pack(side=tk.BOTTOM, fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        self.txt_log = scrolledtext.ScrolledText(box_log, height=8, bg="#101010", fg=self.FG, insertbackground=self.FG, font=("Consolas", 9))
        self.txt_log.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        self.txt_log.tag_config("info", foreground=self.FG)
        self.txt_log.tag_config("ok",   foreground=self.OK)
        self.txt_log.tag_config("warn", foreground=self.WARN)
        self.txt_log.tag_config("err",  foreground=self.ERR)

        mid = ttk.Frame(self, padding=10)
        mid.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        left  = ttk.Frame(mid)
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        right = ttk.Frame(mid)
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(5, 0))

        box_conn = ttk.LabelFrame(left, text="Connect to endpoint")
        box_conn.pack(fill=tk.X, pady=(0, 8))
        ttk.Label(box_conn, text="Remote destination hash:").pack(anchor=tk.W, padx=6, pady=(6, 0))
        self.ent_dest = ttk.Entry(box_conn, font=("Consolas", 10))
        self.ent_dest.pack(fill=tk.X, padx=6, pady=(2, 6))
        self.ent_dest.insert(0, self.args.dest or "")
        self.btn_connect = ttk.Button(box_conn, text="Connect", command=self._do_connect)
        self.btn_connect.pack(side=tk.LEFT, padx=6, pady=(0, 6))
        self.btn_disconnect = ttk.Button(box_conn, text="Disconnect", command=self._do_disconnect, state=tk.DISABLED)
        self.btn_disconnect.pack(side=tk.LEFT, padx=6, pady=(0, 6))
        ttk.Button(box_conn, text="Re-announce", command=self._do_announce).pack(side=tk.LEFT, padx=6, pady=(0, 6))
        self.lbl_state = ttk.Label(box_conn, text="● no link", foreground=self.WARN, style="Panel.TLabel")
        self.lbl_state.pack(side=tk.RIGHT, padx=8)

        box_tun = ttk.LabelFrame(left, text="TUN (Linux, requires root)")
        box_tun.pack(fill=tk.X, pady=(0, 8))
        frm = ttk.Frame(box_tun); frm.pack(fill=tk.X, padx=6, pady=6)
        ttk.Label(frm, text="Name:").grid(row=0, column=0, sticky=tk.W)
        self.ent_tun_name = ttk.Entry(frm, width=14); self.ent_tun_name.insert(0, "tun0")
        self.ent_tun_name.grid(row=0, column=1, padx=4, pady=2, sticky=tk.W)
        ttk.Label(frm, text="Local IP:").grid(row=0, column=2, sticky=tk.W, padx=(10, 0))
        self.ent_tun_ip = ttk.Entry(frm, width=14); self.ent_tun_ip.insert(0, "10.244.0.2")
        self.ent_tun_ip.grid(row=0, column=3, padx=4, pady=2, sticky=tk.W)
        ttk.Label(frm, text="Peer IP:").grid(row=0, column=4, sticky=tk.W, padx=(10, 0))
        self.ent_tun_peer = ttk.Entry(frm, width=14); self.ent_tun_peer.insert(0, "10.244.0.1")
        self.ent_tun_peer.grid(row=0, column=5, padx=4, pady=2, sticky=tk.W)

        frm2 = ttk.Frame(box_tun); frm2.pack(fill=tk.X, padx=6, pady=(0, 6))
        ttk.Label(frm2, text="Mask:").grid(row=0, column=0, sticky=tk.W)
        self.ent_tun_mask = ttk.Entry(frm2, width=14); self.ent_tun_mask.insert(0, "255.255.255.0")
        self.ent_tun_mask.grid(row=0, column=1, padx=4, pady=2, sticky=tk.W)
        ttk.Label(frm2, text="MTU:").grid(row=0, column=2, sticky=tk.W, padx=(10, 0))
        self.ent_tun_mtu = ttk.Entry(frm2, width=8); self.ent_tun_mtu.insert(0, "1500")
        self.ent_tun_mtu.grid(row=0, column=3, padx=4, pady=2, sticky=tk.W)
        self.btn_tun_on  = ttk.Button(frm2, text="Enable TUN", command=self._do_tun_on)
        self.btn_tun_on.grid(row=0, column=4, padx=(10, 2))
        self.btn_tun_off = ttk.Button(frm2, text="Disable TUN", command=self._do_tun_off, state=tk.DISABLED)
        self.btn_tun_off.grid(row=0, column=5, padx=2)
        self.lbl_tun_state = ttk.Label(frm2, text="TUN: off", foreground=self.WARN, style="Panel.TLabel")
        self.lbl_tun_state.grid(row=0, column=6, padx=8, sticky=tk.W)

        box_stat = ttk.LabelFrame(right, text="Statistics")
        box_stat.pack(fill=tk.X, pady=(0, 8))
        ttk.Label(box_stat, text="RX: ", style="Panel.TLabel").grid(row=0, column=0, sticky=tk.W, padx=6, pady=4)
        self.lbl_rx_b = ttk.Label(box_stat, text="0 B", style="Stat.TLabel"); self.lbl_rx_b.grid(row=0, column=1, sticky=tk.W)
        ttk.Label(box_stat, text="   pkts: ", style="Panel.TLabel").grid(row=0, column=2, sticky=tk.W)
        self.lbl_rx_p = ttk.Label(box_stat, text="0", style="Stat.TLabel"); self.lbl_rx_p.grid(row=0, column=3, sticky=tk.W)

        ttk.Label(box_stat, text="TX: ", style="Panel.TLabel").grid(row=1, column=0, sticky=tk.W, padx=6, pady=4)
        self.lbl_tx_b = ttk.Label(box_stat, text="0 B", style="Stat.TLabel"); self.lbl_tx_b.grid(row=1, column=1, sticky=tk.W)
        ttk.Label(box_stat, text="   pkts: ", style="Panel.TLabel").grid(row=1, column=2, sticky=tk.W)
        self.lbl_tx_p = ttk.Label(box_stat, text="0", style="Stat.TLabel"); self.lbl_tx_p.grid(row=1, column=3, sticky=tk.W)

    def _copy_hash(self):
        h = self.lbl_hash.cget("text")
        if h and h != "(initializing...)":
            self.clipboard_clear()
            self.clipboard_append(h)
            self._qlog("Hash copied to clipboard", "ok")

    def _open_settings(self):
        cfg = Path(self.node.config_dir) / "config"
        if not cfg.is_file():
            messagebox.showerror("No config", f"File not found:\n{cfg}")
            return
        def _after():
            try:
                parsed = parse_reticulum_config(str(cfg))
                for it in parsed["interfaces"]:
                    p = it["params"]
                    short = ", ".join(f"{k}={v}" for k, v in p.items())
                    self._qlog(f"  [[{it['name']}]] {short}", "info")
                self._file_log("SETTINGS", f"saved {len(parsed['interfaces'])} interfaces")
                for it in parsed["interfaces"]:
                    self._file_log("SETTINGS", f"  [[{it['name']}]] {it['params']}")
            except Exception as e:
                self._qlog(f"(failed to read final config: {e})", "err")
            self._restart_node()
        InterfaceSettingsDialog(self, str(cfg), on_close=_after)

    def _restart_node(self):
        log = self._qlog
        log("=== Restarting Reticulum to apply new config ===", "warn")
        old_tun = self.node.tun if self.node is not None else None
        if old_tun is not None:
            try:
                self.node.set_tun(None)
            except Exception:
                pass
        if self.node is not None:
            try:
                self.node.disconnect()
            except Exception:
                pass
            try:
                self.node.shutdown()
            except Exception:
                pass
        self._reticulum_teardown()
        try:
            self.node = ReticulumNode(
                log_fn=self._qlog,
                config_dir=self.args.config_dir,
            )
            self.node.on_link_state = self._on_link_state
        except Exception as e:
            tb = traceback.format_exc()
            log(f"[RNS] failed to restart ReticulumNode: {e}", "err")
            for line in tb.splitlines():
                log(f"  {line}", "err")
            return
        if old_tun is not None:
            self.node.set_tun(old_tun)
        self._on_link_state("closed")
        log("=== Reticulum restarted ===", "ok")

    def _reticulum_teardown(self):
        log = self._qlog
        try:
            RNS.Transport.detach_interfaces()
            log("[RNS] interfaces detached", "info")
        except Exception as e:
            log(f"[RNS] detach_interfaces: {e}", "warn")
        try:
            RNS.Transport._should_run = False
        except Exception:
            pass
        time.sleep(0.3)
        try:
            RNS.Reticulum._Reticulum__instance = None
            RNS.Reticulum._Reticulum__exit_handler_ran = False
            RNS.Reticulum._Reticulum__interface_detach_ran = False
            log("[RNS] singleton reset", "info")
        except Exception as e:
            log(f"[RNS] reset singleton: {e}", "warn")
        T = RNS.Transport
        T.interfaces                  = []
        T.destinations                = []
        T.destinations_map            = {}
        T.pending_links               = []
        T.active_links                = []
        T.packet_hashlist             = set()
        T.packet_hashlist_prev        = set()
        T.receipts                    = []
        T.announce_table              = {}
        T.path_table                  = {}
        T.reverse_table               = {}
        T.link_table                  = {}
        T.held_announces              = {}
        T.announce_handlers           = []
        T.tunnels                     = {}
        T.announce_rate_table         = {}
        T.path_requests               = {}
        T.path_states                 = {}
        T.blackholed_identities       = {}
        T.discovery_path_requests     = {}
        T.discovery_pr_tags           = []
        T.control_destinations        = []
        T.control_hashes              = []
        T.mgmt_destinations           = []
        T.mgmt_hashes                 = []
        T.local_client_interfaces     = []
        T.local_client_rssi_cache     = []
        T.local_client_snr_cache      = []
        T.local_client_q_cache        = []
        T.pending_local_path_requests = {}
        T.ready                       = False
        T.start_time                  = None
        T.identity                    = None
        T.network_identity            = None
        T._should_run                 = True
        log("[RNS] Transport state reset", "info")

    def _open_logs(self):
        log_dir = Path(self.file_logger.log_dir)
        log_dir.mkdir(parents=True, exist_ok=True)
        try:
            subprocess.run(["xdg-open", str(log_dir)], check=False)
            self._qlog(f"Opened log folder: {log_dir}", "ok")
        except Exception as e:
            self._qlog(f"Failed to open log folder: {e}", "err")
            messagebox.showerror("Logs", f"Path:\n{log_dir}\n\nError: {e}")

    def _do_connect(self):
        dest = self.ent_dest.get().strip()
        if not dest:
            messagebox.showwarning("No hash", "Enter the endpoint destination hash.")
            return
        self.btn_connect.config(state=tk.DISABLED)
        threading.Thread(target=self._connect_worker, args=(dest,), daemon=True).start()

    def _connect_worker(self, dest):
        ok = self.node.connect_to(dest)
        self.after(0, lambda: self.btn_connect.config(state=tk.NORMAL))
        if not ok:
            self.after(0, lambda: self._on_link_state("failed"))

    def _do_disconnect(self):
        self.node.disconnect()

    def _do_announce(self):
        self.node.re_announce()

    def _do_tun_on(self):
        if os.geteuid() != 0:
            messagebox.showwarning(
                "Root required",
                "Creating TUN on Linux requires root privileges.\n"
                "Run with sudo."
            )
            return
        try:
            tun = LinuxTunInterface(
                name    = self.ent_tun_name.get().strip() or "tun0",
                local_ip= self.ent_tun_ip.get().strip() or "10.244.0.2",
                peer_ip = self.ent_tun_peer.get().strip() or "10.244.0.1",
                netmask = self.ent_tun_mask.get().strip() or "255.255.255.0",
                mtu     = int(self.ent_tun_mtu.get().strip() or "1500"),
                log     = self._qlog,
            )
            tun.open()
            self.node.set_tun(tun)
            self.btn_tun_on.config(state=tk.DISABLED)
            self.btn_tun_off.config(state=tk.NORMAL)
            self.lbl_tun_state.config(text=f"TUN: {tun.name}", foreground=self.OK)
            self._setup_routes(tun.peer_ip)
        except Exception as e:
            self._qlog(f"TUN open failed: {e}", "err")
            messagebox.showerror("TUN", str(e))

    def _do_tun_off(self):
        self._teardown_routes()
        try:
            if self.node.tun:
                self.node.tun.close()
        except Exception as e:
            self._qlog(f"TUN close: {e}", "warn")
        self.node.set_tun(None)
        self.btn_tun_on.config(state=tk.NORMAL)
        self.btn_tun_off.config(state=tk.DISABLED)
        self.lbl_tun_state.config(text="TUN: off", foreground=self.WARN)

    # saved original default gateway for restore in _teardown_routes
    _saved_orig_gw   = None
    _saved_orig_iface = None

    def _get_default_gateway(self):
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

    def _get_physical_interface(self):
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

    def _get_rns_server(self):
        try:
            cfg_path = Path(self.node.config_dir) / "config"
            parsed = parse_reticulum_config(str(cfg_path))
            for it in parsed["interfaces"]:
                p = it["params"]
                if "target_host" in p:
                    return p["target_host"]
                if "forward_ip" in p and p.get("forward_ip", "255.255.255.255") != "255.255.255.255":
                    return p["forward_ip"]
        except Exception:
            pass
        return None

    def _setup_routes(self, peer_ip):
        gw = self._get_default_gateway()
        iface = self._get_physical_interface()
        rns_server = self._get_rns_server()
        tun_name = self.ent_tun_name.get().strip() or "tun0"

        if not gw or not iface:
            self._qlog("[ROUTES] cannot determine gateway/interface", "warn")
        else:
            self._qlog(f"[ROUTES] gateway={gw}, interface={iface}, peer={peer_ip}", "info")

        if rns_server and gw and iface:
            subprocess.run(
                ["ip", "route", "replace", rns_server, "via", gw, "dev", iface, "metric", "5"],
                capture_output=True, timeout=5, check=False,
            )
            self._qlog(f"[ROUTES] {rns_server} -> {gw} dev {iface} metric 5", "ok")

        if gw and iface:
            self._saved_orig_gw = gw
            self._saved_orig_iface = iface
        # atomically replace default route with TUN
        subprocess.run(
            ["ip", "route", "replace", "0.0.0.0/0", "via", peer_ip, "dev", tun_name],
            capture_output=True, timeout=5, check=False,
        )
        self._qlog(f"[ROUTES] default -> {peer_ip} via {tun_name} (replaced original)", "ok")

    def _teardown_routes(self):
        rns_server = self._get_rns_server()
        tun_name = self.ent_tun_name.get().strip() or "tun0"
        peer_ip = self.ent_tun_peer.get().strip() or "10.244.0.1"
        self._qlog("[ROUTES] removing VPN routes...", "info")
        tun_exists = False
        try:
            r = subprocess.run(
                ["ip", "route", "del", "0.0.0.0/0", "via", peer_ip, "dev", tun_name],
                capture_output=True, timeout=5, check=False,
            )
            tun_exists = r.returncode == 0
        except Exception:
            pass
        if rns_server:
            try:
                subprocess.run(
                    ["ip", "route", "del", rns_server],
                    capture_output=True, timeout=5, check=False,
                )
            except Exception:
                pass
        # restore original default route
        if tun_exists and self._saved_orig_gw and self._saved_orig_iface:
            subprocess.run(
                ["ip", "route", "add", "default", "via", self._saved_orig_gw, "dev", self._saved_orig_iface],
                capture_output=True, timeout=5, check=False,
            )
            self._qlog(f"[ROUTES] restored original default via {self._saved_orig_gw} dev {self._saved_orig_iface}", "ok")
        self._qlog("[ROUTES] VPN routes removed", "ok")

    def _on_link_state(self, state):
        cmap = {
            "connecting": ("● connecting...", self.WARN),
            "active":     ("● link active",  self.OK),
            "closed":     ("● link closed",   self.WARN),
            "failed":     ("● link error",  self.ERR),
        }
        text, color = cmap.get(state, (f"● {state}", self.WARN))
        self.lbl_state.config(text=text, foreground=color)
        if state == "active":
            self.btn_disconnect.config(state=tk.NORMAL)
        else:
            self.btn_disconnect.config(state=tk.DISABLED)

    def _refresh_identity(self):
        if self.node.destination:
            self.lbl_hash.config(text=RNS.prettyhexrep(self.node.destination.hash))
        else:
            self.lbl_hash.config(text="(no identity)")
        self.after(1000, self._refresh_identity)

    def _refresh_stats(self):
        self.lbl_rx_b.config(text=f"{self.node.rx_bytes:,} B".replace(",", " "))
        self.lbl_rx_p.config(text=str(self.node.rx_packets))
        self.lbl_tx_b.config(text=f"{self.node.tx_bytes:,} B".replace(",", " "))
        self.lbl_tx_p.config(text=str(self.node.tx_packets))
        self.after(500, self._refresh_stats)

    def _qlog(self, msg, level="info"):
        self._log_queue.put((msg, level))

    def _file_log(self, tag, msg):
        if getattr(self, "file_logger", None) is not None:
            self.file_logger.write(f"[{tag}] {msg}")

    def _drain_log_queue(self):
        try:
            while True:
                msg, level = self._log_queue.get_nowait()
                self.txt_log.insert(tk.END, msg + "\n", level)
                self.txt_log.see(tk.END)
                if getattr(self, "file_logger", None) is not None:
                    self.file_logger.write(msg, level)
        except queue.Empty:
            pass
        self.after(50, self._drain_log_queue)

    def _settings_path(self):
        cfg_dir = Path(self.node.config_dir) if self.node.config_dir else Path(".")
        return cfg_dir / "tunnel_settings.json"

    def _save_tunnel_settings(self):
        data = {
            "dest":          self.ent_dest.get().strip(),
            "tun_name":      self.ent_tun_name.get().strip(),
            "tun_ip":        self.ent_tun_ip.get().strip(),
            "tun_peer":      self.ent_tun_peer.get().strip(),
            "tun_mask":      self.ent_tun_mask.get().strip(),
            "tun_mtu":       self.ent_tun_mtu.get().strip(),
        }
        try:
            path = self._settings_path()
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            self._qlog(f"Save settings error: {e}", "warn")

    def _load_tunnel_settings(self):
        path = self._settings_path()
        if not path.is_file():
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            return
        mapping = {
            "dest":     self.ent_dest,
            "tun_name": self.ent_tun_name,
            "tun_ip":   self.ent_tun_ip,
            "tun_peer": self.ent_tun_peer,
            "tun_mask": self.ent_tun_mask,
            "tun_mtu":  self.ent_tun_mtu,
        }
        for key, widget in mapping.items():
            val = data.get(key)
            if val is not None:
                widget.delete(0, tk.END)
                widget.insert(0, val)

    def _on_close(self):
        self._save_tunnel_settings()
        self._teardown_routes()
        try:
            if self.node.tun:
                self.node.tun.close()
        except Exception:
            pass
        try:
            self.node.shutdown()
        except Exception:
            pass
        if self.args.pidfile:
            _remove_pidfile(self.args.pidfile)
        self.destroy()


# ============================================================================
# Management helpers
# ============================================================================
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


def _do_stop(pidfile, force=False):
    pid = _read_pidfile(pidfile)
    if pid is None:
        print(f"[X] no pidfile at {pidfile}", file=sys.stderr)
        return 1
    if not _pid_alive(pid):
        print(f"[X] process {pid} not running (cleaning stale pidfile)")
        _remove_pidfile(pidfile)
        return 1
    label = "force-killing" if force else "stopping"
    print(f"[*] {label} pid={pid} ...")
    sig = signal.SIGKILL if force else signal.SIGTERM
    try:
        os.kill(pid, sig)
    except OSError as e:
        print(f"[X] kill failed: {e}", file=sys.stderr)
        return 1
    for _ in range(30):
        time.sleep(0.5)
        if not _pid_alive(pid):
            print("[+] stopped")
            _remove_pidfile(pidfile)
            return 0
    print("[!] not stopped in 15s")
    return 1


# ============================================================================
def main():
    ap = argparse.ArgumentParser(
        description="Reticulum TUN tunnel — Linux GUI (standard config ~/.reticulum)",
        formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=40),
    )
    ap.add_argument("--config-dir", default=None,
                    help="Reticulum config directory (default: ~/.reticulum)")
    ap.add_argument("--dest",       default=None,
                    help="endpoint destination hash for auto-connect on startup")
    ap.add_argument("--pidfile",    default=None,
                    help="PID file (default: <config-dir>/tun_rns_linux_gui.pid)")
    ap.add_argument("--status",     action="store_true",
                    help="check if instance is running and exit")
    ap.add_argument("--stop",       action="store_true",
                    help="send SIGTERM and exit")
    ap.add_argument("--force-stop", action="store_true",
                    help="force kill process (SIGKILL)")
    ap.add_argument("--tun-name",   default="tun0",
                    help="TUN adapter name (default: tun0)")
    ap.add_argument("--tun-ip",     default="10.244.0.2",
                    help="TUN adapter IP (default: 10.244.0.2)")
    ap.add_argument("--tun-peer",   default="10.244.0.1",
                    help="peer IP (default: 10.244.0.1)")
    ap.add_argument("--tun-mask",   default="255.255.255.0",
                    help="TUN mask (default: 255.255.255.0)")
    ap.add_argument("--tun-mtu",    type=int, default=1500,
                    help="MTU TUN (default: 1500)")
    args = ap.parse_args()

    if args.config_dir:
        config_dir = os.path.expanduser(args.config_dir)
    else:
        config_dir = default_config_dir()

    if args.pidfile is None:
        args.pidfile = os.path.join(config_dir, "tun_rns_linux_gui.pid")

    if args.status:
        return _do_status(args.pidfile)
    if args.stop or args.force_stop:
        return _do_stop(args.pidfile, force=args.force_stop)

    if args.pidfile:
        existing = _read_pidfile(args.pidfile)
        if existing and _pid_alive(existing):
            print(f"[X] already running, pid={existing}, pidfile={args.pidfile}", file=sys.stderr)
            return 1

    print(f"[i] Reticulum config: {config_dir}", file=sys.stderr)
    print(f"[i] Pidfile: {args.pidfile}", file=sys.stderr)

    app = App(args)
    app.mainloop()


if __name__ == "__main__":
    sys.exit(main() or 0)
