#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TUN tunnel over Reticulum — Windows GUI client (Tkinter).

A lightweight GUI application that creates an ISOLATED Reticulum node
(own config dir, own identity and storage — does not interfere with other
Reticulum installations on the system). Features:
  - displays own destination hash;
  - connects to a TUN endpoint by its hash;
  - accepts incoming RNS.Link connections (server mode);
  - optionally starts a wintun adapter for real TUN;
  - displays traffic, sends test data through the tunnel.

TUN <-> Link bridge protocol matches tun_rns_linux.py:
    TUN <--ip packet--> bridge <--RNS.Resource--> Link <-- Reticulum

Dependencies:
    pip install rns

Build to .exe:
    build.bat
"""

import argparse
import atexit
import errno
import json
import os
import queue
import signal
import subprocess
import sys
import threading
import time
import traceback
import tkinter as tk
from pathlib import Path
from tkinter import ttk, messagebox, scrolledtext

# ── CRITICAL: patch RNS.Interfaces.__all__ BEFORE `import RNS` ──
# In frozen exe, glob.glob(__file__) returns nothing → __all__ is empty →
# `from RNS.Interfaces import *` imports nothing → RNS.Reticulum fails.
import RNS.Interfaces
import RNS.Interfaces.Interface
import RNS.Interfaces.LocalInterface
import RNS.Interfaces.AutoInterface
import RNS.Interfaces.TCPInterface
import RNS.Interfaces.UDPInterface
import RNS.Interfaces.PipeInterface
RNS.Interfaces.__all__ = [
    "Interface", "LocalInterface", "AutoInterface",
    "TCPInterface", "UDPInterface", "PipeInterface",
]
import RNS

# After import RNS, inject missing names into RNS.Reticulum module scope.
# The `from RNS.Interfaces import *` in Reticulum.py may have imported nothing
# in a frozen exe, leaving names like `Interface` undefined.
_rns_ret = sys.modules.get("RNS.Reticulum")
if _rns_ret is not None:
    for _n in ("Interface", "LocalInterface", "AutoInterface",
               "TCPInterface", "UDPInterface", "PipeInterface"):
        if not hasattr(_rns_ret, _n):
            setattr(_rns_ret, _n, getattr(RNS.Interfaces, _n))


# ============================================================================
# Protocol constants (must match tun_rns_linux.py)
# ============================================================================
APP_NAME    = "rnstunnel"
ASPECT      = "endpoint"
APP_DIRNAME = "ReticulumTUN"


# ============================================================================
# Isolated Reticulum config location
# ============================================================================
def _running_as_exe():
    return getattr(sys, "frozen", False)


def default_config_dir(portable=False):
    """
    Where to store config/storage/identity for Reticulum.

    - portable=True or running from .exe without --install -> <exe-dir>/config
    - otherwise -> standard Reticulum directory (%APPDATA%\\Reticulum or ~/.reticulum)
    """
    if portable or _running_as_exe():
        # next to .exe (or .py)
        base = Path(sys.executable).parent if _running_as_exe() else Path(__file__).resolve().parent
        return str(base / "config")
    # standard Reticulum directory
    if os.name != "nt":
        return str(Path.home() / ".reticulum")
    appdata = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
    return str(Path(appdata) / "Reticulum")


def ensure_default_config(config_dir):
    """
    If Reticulum config doesn't exist — generate a minimal one.
    This allows running .exe immediately after build without manual configuration.
    """
    config_dir = Path(config_dir)
    config_dir.mkdir(parents=True, exist_ok=True)
    cfg = config_dir / "config"
    if cfg.exists():
        return str(config_dir)
    cfg.write_text(f"""# Reticulum config for ReticulumTUN
# Config dir: {config_dir}

[reticulum]
  share_instance = False
  enable_transport = True
  instance_name = rnstunnel-win

[interfaces]
""", encoding="utf-8")
    (config_dir / "storage").mkdir(exist_ok=True)
    return str(config_dir)


# ============================================================================
# Searching for wintun.dll (multiple locations)
# ============================================================================
def find_wintun_dll():
    """
    Returns the full path to wintun.dll or None.
    Searches in typical locations (including official wintun-0.x.zip archive,
    where the structure is: wintun/bin/<arch>/wintun.dll).
    """
    candidates = []
    if _running_as_exe():
        exe_dir = Path(sys.executable).parent
        meipass  = Path(getattr(sys, "_MEIPASS", exe_dir))
    else:
        exe_dir = Path(__file__).resolve().parent
        meipass = exe_dir

    # 1) right next to the script/.exe
    candidates += [exe_dir / "wintun.dll", meipass / "wintun.dll"]
    # 2) subdirectory wintun/<arch>/ or wintun/bin/<arch>/
    for arch in ("amd64", "x86", "arm64", "arm"):
        candidates += [
            exe_dir / "wintun" / arch / "wintun.dll",
            meipass / "wintun" / arch / "wintun.dll",
            exe_dir / "wintun" / "bin" / arch / "wintun.dll",
            meipass / "wintun" / "bin" / arch / "wintun.dll",
        ]
    # 3) in AppData
    appdata = os.environ.get("APPDATA")
    if appdata:
        candidates.append(Path(appdata) / APP_DIRNAME / "wintun.dll")
    # 4) system Wintun
    candidates += [Path(r"C:\Program Files\Wintun\bin\amd64\wintun.dll"),
                   Path(r"C:\Program Files\Wintun\bin\x86\wintun.dll")]

    for c in candidates:
        if c.is_file():
            return str(c)
    return None


# ============================================================================
# Optional TUN on Windows via wintun.dll
# ============================================================================
class WinTunInterface:
    """
    Creates a TUN interface on Windows via wintun.dll.
    Works only if wintun.dll is available (see find_wintun_dll()).
    """

    def __init__(self, name="tun0", local_ip="10.244.0.2", peer_ip="10.244.0.1",
                 netmask="255.255.255.0", mtu=1500, log=None):
        self.name      = name
        self.local_ip  = local_ip
        self.peer_ip   = peer_ip
        self.netmask   = netmask
        self.mtu       = mtu
        self.log       = log or (lambda *a, **kw: None)
        self._wintun   = None
        self._adapter  = None
        self._session  = None
        self._rx_event = None
        self._has_event= False
        self._stop_evt = threading.Event()
        self._thread   = None
        self.tx_lock   = threading.Lock()
        self.on_packet = None
        self.rx_bytes  = 0
        self.tx_bytes  = 0
        self.opened    = False
        self._dll_arch = "?"
        self._py_arch  = "?"
        import struct as _st
        self._py_arch = "x64" if _st.calcsize("P") == 8 else "x86"

    def open(self):
        import ctypes
        from ctypes import wintypes

        # search for wintun.dll in several locations
        dll_path = find_wintun_dll()
        if not dll_path:
            raise RuntimeError(
                "wintun.dll not found. Download from https://www.wintun.net/ and place:\n"
                "  - next to .exe (or .py) as wintun.dll, or\n"
                "  - in %APPDATA%\\ReticulumTUN\\wintun.dll, or\n"
                "  - install Wintun in C:\\Program Files\\Wintun\\."
            )
        try:
            self._wintun = ctypes.WinDLL(dll_path)
        except OSError as e:
            raise RuntimeError(f"Failed to load wintun.dll ({dll_path}): {e}")

        # detect DLL architecture by PE header (Machine: 0x8664=x64, 0x14c=x86, 0xaa64=arm64)
        try:
            with open(dll_path, "rb") as _f:
                _pe = _f.read(1024)
            if len(_pe) > 0x3c + 4 and _pe[:2] == b"MZ":
                _e_lfanew = int.from_bytes(_pe[0x3c:0x40], "little")
                if _pe[_e_lfanew:_e_lfanew+4] == b"PE\x00\x00":
                    _machine = int.from_bytes(_pe[_e_lfanew+4:_e_lfanew+6], "little")
                    self._dll_arch = {0x8664: "x64", 0x14c: "x86", 0xaa64: "arm64"}.get(_machine, f"0x{_machine:x}")
        except Exception:
            pass
        self.log(f"TUN: wintun.dll = {dll_path} ({self._dll_arch}); Python = {self._py_arch}")

        W = self._wintun
        # WINTUN_PACKET = { ULONG DataSize; BYTE Data[]; }  — variable length.
        # Actual function names — WintunReceivePacket / WintunAllocateSendPacket
        # (NOT WintunGetReceivePacket, no such function exists).
        # WintunCreateAdapter: Name, TunnelType, RequestedGUID-or-NULL
        # RequestedGUID — pointer to 16-byte GUID, NULL = auto-generation.
        W.WintunCreateAdapter.restype  = wintypes.HANDLE
        W.WintunCreateAdapter.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR,
                                          ctypes.c_void_p]
        W.WintunOpenAdapter.restype    = wintypes.HANDLE
        W.WintunOpenAdapter.argtypes   = [wintypes.LPCWSTR]
        W.WintunCloseAdapter.argtypes  = [wintypes.HANDLE]
        W.WintunStartSession.restype   = wintypes.HANDLE
        W.WintunStartSession.argtypes  = [wintypes.HANDLE, wintypes.DWORD]
        W.WintunEndSession.argtypes    = [wintypes.HANDLE]
        # Receive: returns pointer to WINTUN_PACKET (c_void_p),
        # data length written via *PacketSize.
        W.WintunReceivePacket.restype  = ctypes.c_void_p
        W.WintunReceivePacket.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        W.WintunReleaseReceivePacket.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
        # Send: returns pointer to WINTUN_PACKET, where data must be
        # copied at offset 4 (immediately after DataSize).
        W.WintunAllocateSendPacket.restype  = ctypes.c_void_p
        W.WintunAllocateSendPacket.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        W.WintunSendPacket.argtypes         = [wintypes.HANDLE, ctypes.c_void_p]
        # event for efficient waiting (not in all wintun.dll versions)
        self._has_event = hasattr(W, "WintunGetReceiveWaitEvent")
        if self._has_event:
            W.WintunGetReceiveWaitEvent.restype  = wintypes.HANDLE
            W.WintunGetReceiveWaitEvent.argtypes = [wintypes.HANDLE]

        # --- create adapter (if exists — reuse) -----------------
        # Third argument of WintunCreateAdapter — pointer to GUID (16 bytes)
        # or NULL for auto-generation. ctypes.c_void_p(None) = NULL.
        last_err = ctypes.get_last_error()
        try:
            adapter = W.WintunCreateAdapter(ctypes.c_wchar_p(self.name),
                                            ctypes.c_wchar_p("Reticulum TUN"),
                                            ctypes.c_void_p(None))
        except Exception as e:
            raise RuntimeError(f"WintunCreateAdapter crashed: {e}")

        if not adapter:
            # adapter might already exist — try to open
            try:
                adapter = W.WintunOpenAdapter(ctypes.c_wchar_p(self.name))
            except Exception as e:
                raise RuntimeError(f"WintunOpenAdapter crashed: {e}")
            if not adapter:
                # clarify the reason: admin? architecture? busy name?
                win_err = ctypes.get_last_error()
                try:
                    is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
                except Exception:
                    is_admin = False
                if not is_admin:
                    raise RuntimeError(
                        "TUN: administrator rights required. "
                        "Run ReticulumTUN.exe as administrator "
                        "(right-click -> Run as administrator)."
                    )
                hint = f" (Win32 error {win_err})"
                raise RuntimeError(
                    f"WintunCreateAdapter/OpenAdapter returned FALSE{hint}. "
                    f"Check: wintun.dll architecture = {self._dll_arch}, "
                    f"Python = {self._py_arch}; adapter name \"{self.name}\" "
                    f"is not busy/not locked."
                )
        self._adapter = adapter

        # Capacity — ring buffer size in bytes.
        # WINTUN_MAX_RING_CAPACITY = 0x4000000 (64 MB). Standard in wintun examples: 4 MB.
        RING_CAPACITY = 0x400000
        try:
            session = W.WintunStartSession(self._adapter, RING_CAPACITY)
        except Exception as e:
            raise RuntimeError(f"WintunStartSession crashed: {e}")
        if not session:
            win_err = ctypes.get_last_error()
            raise RuntimeError(
                f"WintunStartSession returned NULL (Win32 error {win_err}). "
                f"Ring capacity = {RING_CAPACITY} (0x{RING_CAPACITY:x})."
            )
        self._session = session
        self._rx_event = None
        if self._has_event:
            try:
                self._rx_event = W.WintunGetReceiveWaitEvent(self._session)
            except Exception:
                self._rx_event = None
                self._has_event = False

        self._configure_ip_windows()
        self._stop_evt.clear()
        self._thread = threading.Thread(target=self._reader, daemon=True, name="wintun-rx")
        self._thread.start()
        self.opened = True
        self.log(f"[TUN] wintun adapter '{self.name}' started ({self.local_ip}/{self.netmask})", "ok")

    def _configure_ip_windows(self):
        ps_cmd = (
            f"$a = Get-NetAdapter -IncludeHidden | Where-Object {{ $_.Name -eq '{self.name}' }}; "
            f"if ($a) {{ "
            f"  New-NetIPAddress -InterfaceAlias '{self.name}' -IPAddress {self.local_ip} "
            f"    -PrefixLength {self._cidr()} -ErrorAction SilentlyContinue; "
            f"  Set-NetIPInterface -InterfaceAlias '{self.name}' -NlMtu {self.mtu} -ErrorAction SilentlyContinue; "
            f"  Set-NetIPInterface -InterfaceAlias '{self.name}' -InterfaceMetric 5 -ErrorAction SilentlyContinue "
            f"}} else {{ Write-Error 'adapter not found' }}"
        )
        rc = os.system(f'powershell -NoProfile -Command "{ps_cmd}"')
        if rc != 0:
            self.log(f"[TUN] IP configuration returned code {rc} (admin rights needed?)", "warn")

    def _cidr(self):
        return sum(bin(int(x)).count("1") for x in self.netmask.split("."))

    def _reader(self):
        """Reads IP packets from wintun and calls on_packet."""
        import ctypes
        from ctypes import wintypes
        W = self._wintun
        kernel32 = None
        if self._has_event and self._rx_event:
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
            kernel32.WaitForSingleObject.restype  = wintypes.DWORD
        WAIT_TIMEOUT = 0x00000102

        size = wintypes.DWORD(0)
        while not self._stop_evt.is_set():
            # wait for readiness (event or just sleep)
            if kernel32 and self._rx_event:
                rc = kernel32.WaitForSingleObject(self._rx_event, 50)
                if self._stop_evt.is_set():
                    break
                if rc == WAIT_TIMEOUT:
                    continue
            else:
                # polling — for old wintun versions without WintunGetReceiveWaitEvent
                time.sleep(0.002)
                if self._stop_evt.is_set():
                    break

            # read all available packets
            while not self._stop_evt.is_set():
                pkt = W.WintunReceivePacket(self._session, ctypes.byref(size))
                if not pkt:
                    break
                try:
                    data = ctypes.string_at(pkt, size.value)
                finally:
                    W.WintunReleaseReceivePacket(self._session, pkt)

                self.rx_bytes += size.value
                if self.on_packet:
                    try:
                        self.on_packet(data)
                    except Exception as e:
                        self.log(f"[TUN] on_packet error: {e}", "err")

    def write(self, data):
        if not self.opened or not self._session:
            return False
        import ctypes
        W = self._wintun
        with self.tx_lock:
            try:
                size = len(data)
                pkt = W.WintunAllocateSendPacket(self._session, ctypes.c_uint32(size))
                if not pkt:
                    return False
                try:
                    ctypes.memmove(pkt, data, size)
                    W.WintunSendPacket(self._session, pkt)
                except Exception:
                    pass
                self.tx_bytes += size
                return True
            except Exception as e:
                self.log(f"[TUN] write error: {e}", "err")
                return False

    def close(self):
        self._stop_evt.set()
        if self._wintun and self._session:
            try: self._wintun.WintunEndSession(self._session)
            except Exception: pass
            self._session = None
        if self._wintun and self._adapter:
            try: self._wintun.WintunCloseAdapter(self._adapter)
            except Exception: pass
            self._adapter = None
        self.opened = False


# ============================================================================
# Reticulum node core
# ============================================================================
class ReticulumNode:
    """
    Reticulum node with TUN <-> RNS.Resource bridge (via active link).
    """

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
        # Reticulum must be initialized in the main thread (signal handlers)
        self._bootstrap()
        # background thread only for future tasks (currently idle)
        self._thread    = threading.Thread(target=self._run, daemon=True, name="rns-core")
        self._thread.start()
        self._ready.wait(timeout=10)

    # ------------------------------------------------------------------
    def set_tun(self, tun):
        if self.tun:
            self.tun.on_packet = None
        self.tun = tun
        if tun:
            tun.on_packet = self._tun_to_link
            self._tun_active = True
        else:
            self._tun_active = False

    # ------------------------------------------------------------------
    def _run(self):
        # Reticulum already initialized in main thread (see bootstrap).
        # Here we only wait for the stop signal.
        while not self._stop_evt.is_set():
            time.sleep(0.1)

    def _bootstrap(self):
        log = self.log_fn

        # ── validate config BEFORE RNS.Reticulum() ──
        # RNS.panic() calls os._exit(255) — cannot be caught via except.
        cfg_path = os.path.join(self.config_dir, "config") if self.config_dir else None
        if cfg_path and os.path.isfile(cfg_path):
            try:
                parsed = parse_reticulum_config(cfg_path)
                errors = validate_interfaces(parsed["interfaces"])
                if errors:
                    for e in errors:
                        log(f"[CONFIG ERROR] {e}", "err")
                    log("[CONFIG] Auto-fixing config...", "warn")
                    fixed = False
                    for it in parsed["interfaces"]:
                        p = it["params"]
                        if p.get("type") == "TCPInterface":
                            p["type"] = "TCPServerInterface"
                            log(f"  [[{it['name']}]] type=TCPInterface → TCPServerInterface", "ok")
                            fixed = True
                    if fixed:
                        update_config_interfaces(cfg_path, parsed["interfaces"])
                        log("[CONFIG] Config fixed. Re-reading...", "ok")
                        parsed = parse_reticulum_config(cfg_path)
                        errors = validate_interfaces(parsed["interfaces"])
                if errors:
                    for e in errors:
                        log(f"[CONFIG ERROR] {e}", "err")
                    log("[CONFIG] CANNOT start Reticulum — fix interfaces via GUI.", "err")
                    self._ready.set()
                    return
                log(f"[CONFIG] validation OK ({len(parsed['interfaces'])} interfaces)", "ok")
            except Exception as e:
                log(f"[CONFIG] config read error: {e}", "err")

        try:
            log("[RNS] initializing Reticulum...", "info")
            RNS.Reticulum(configdir=self.config_dir) if self.config_dir else RNS.Reticulum()
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
            id_path = os.path.join(storage, "windows_gui_identity")
        try:
            if id_path and os.path.isfile(id_path):
                self.identity = RNS.Identity.from_file(id_path)
            else:
                self.identity = RNS.Identity()
                if id_path: self.identity.to_file(id_path)
        except Exception:
            self.identity = RNS.Identity()
            if id_path: self.identity.to_file(id_path)

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

    # ------------------------------------------------------------------
    def re_announce(self):
        if self.destination:
            self.destination.announce()
            self.log_fn("[RNS] announce sent", "info")

    # ------------------------------------------------------------------
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
            try: link.teardown()
            except Exception: pass

    def shutdown(self):
        self._stop_evt.set()


# ============================================================================
# File logger with rotation
# ============================================================================
class FileLogger:
    """
    Thread-safe file logger. Rotation when exceeding MAX_BYTES.
    Fixed name: rnstunnel.log (with .1 archive).
    """
    MAX_BYTES = 2 * 1024 * 1024  # 2 MB

    def __init__(self, log_dir):
        from datetime import datetime
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.path = self.log_dir / "rnstunnel.log"
        self._lock = threading.Lock()
        # session header
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
# Reticulum uses its own format with nested sections:
#   [interfaces]
#     [[TCP Server]]
#       type = TCPInterface
#       enabled = True
#       listen_port = 4242
# Standard configparser can't handle this — we write a minimal parser.

def parse_reticulum_config(path):
    """
    Returns dict:
      {
        "interfaces": [ {"name": "TCP Server", "params": {"type": ..., ...}, "raw": "..."}, ... ],
        "lines": [all file lines]  # for rewriting
        "interfaces_block": (start_line, end_line)  # [interfaces] boundaries
      }
    """
    with open(path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    interfaces = []
    in_interfaces = False
    in_subsection = False
    cur = None
    iface_start = -1
    iface_end = -1
    interfaces_start = -1
    interfaces_end   = -1
    depth = 0  # 0=normal, 1=inside [interfaces], 2=inside [[subsection]]

    for i, line in enumerate(lines):
        stripped = line.strip()
        if not in_interfaces and stripped.startswith("[interfaces]"):
            in_interfaces = True
            interfaces_start = i
            continue
        if in_interfaces and stripped.startswith("[") and not stripped.startswith("[["):
            # another top-level section — exit [interfaces]
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
    """
    Assembles [interfaces] block from interface list in Reticulum format.
    """
    out = ["[interfaces]\n"]
    for iface in interfaces:
        name = iface["name"]
        out.append(f"  [[{name}]]\n")
        params = iface.get("params", {})
        # type/enabled first — for readability
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
    """Returns list of errors (empty = all ok)."""
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
    """
    Validates, rewrites file, replacing [interfaces] content with new list.
    Returns (ok, errors).
    """
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
# Simplified interface settings window
# ============================================================================
class InterfaceSettingsDialog(tk.Toplevel):
    """
    Simple window: protocol (UDP/TCP), role (Client/Server), IP, port.
    """

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

        # --- current state from config ---
        self._load_current()

        # --- UI ---
        frm = ttk.Frame(self, padding=16)
        frm.pack(fill=tk.BOTH, expand=True)

        # Protocol
        ttk.Label(frm, text="Protocol:", font=("Segoe UI", 10, "bold")).grid(row=0, column=0, sticky=tk.W, pady=4)
        self.var_proto = tk.StringVar(value=self._current_proto)
        r0 = ttk.Frame(frm); r0.grid(row=0, column=1, sticky=tk.W, pady=4)
        ttk.Radiobutton(r0, text="UDP", variable=self.var_proto, value="udp").pack(side=tk.LEFT, padx=(0, 12))
        ttk.Radiobutton(r0, text="TCP", variable=self.var_proto, value="tcp").pack(side=tk.LEFT)

        # Role
        ttk.Label(frm, text="Mode:", font=("Segoe UI", 10, "bold")).grid(row=1, column=0, sticky=tk.W, pady=4)
        self.var_role = tk.StringVar(value=self._current_role)
        r1 = ttk.Frame(frm); r1.grid(row=1, column=1, sticky=tk.W, pady=4)
        ttk.Radiobutton(r1, text="Client", variable=self.var_role, value="client").pack(side=tk.LEFT, padx=(0, 12))
        ttk.Radiobutton(r1, text="Server", variable=self.var_role, value="server").pack(side=tk.LEFT)

        # IP address
        ttk.Label(frm, text="IP address:", font=("Segoe UI", 10, "bold")).grid(row=2, column=0, sticky=tk.W, pady=4)
        self.var_ip = tk.StringVar(value=self._current_ip)
        ent_ip = ttk.Entry(frm, textvariable=self.var_ip, width=24, font=("Consolas", 11))
        ent_ip.grid(row=2, column=1, sticky=tk.W, pady=4, padx=(0, 0))

        # Port
        ttk.Label(frm, text="Port:", font=("Segoe UI", 10, "bold")).grid(row=3, column=0, sticky=tk.W, pady=4)
        self.var_port = tk.StringVar(value=self._current_port)
        ent_port = ttk.Entry(frm, textvariable=self.var_port, width=10, font=("Consolas", 11))
        ent_port.grid(row=3, column=1, sticky=tk.W, pady=4)

        # Hint
        self.lbl_hint = ttk.Label(frm, text="", foreground="#888", wraplength=380)
        self.lbl_hint.grid(row=4, column=0, columnspan=2, sticky=tk.W, pady=(8, 4))
        self._update_hint()

        self.var_proto.trace_add("write", lambda *_: self._update_hint())
        self.var_role.trace_add("write", lambda *_: self._update_hint())

        # Buttons
        btn_row = ttk.Frame(frm)
        btn_row.grid(row=5, column=0, columnspan=2, pady=(16, 0))
        ttk.Button(btn_row, text="Save", command=self._on_save).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(btn_row, text="Cancel", command=self.destroy).pack(side=tk.LEFT)

        frm.columnconfigure(1, weight=1)

    def _load_current(self):
        """Reads current interface from config, determines proto/role/ip/port."""
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

                # determine IP and port
                if self._current_proto == "udp":
                    if self._current_role == "client":
                        self._current_ip = p.get("forward_ip", "")
                        self._current_port = p.get("forward_port", p.get("listen_port", "4242"))
                    else:
                        self._current_ip = p.get("listen_ip", "0.0.0.0")
                        self._current_port = p.get("listen_port", "4242")
                else:  # tcp
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

        # Generate interface
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
        else:  # tcp
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
        mode = "portable" if args.portable else "isolated"
        self.title(f"Reticulum TUN Tunnel — Windows [{mode}]")
        self.geometry("820x600")
        self.minsize(720, 520)
        self.configure(bg=self.BG)

        self._configure_style()
        self._build_ui()
        self._log_queue = queue.Queue()

        cfg_dir = Path(os.path.expanduser(args.config_dir)) if args.config_dir else None
        if cfg_dir is None:
            cfg_dir = Path(default_config_dir(portable=args.portable))
        self.file_logger = FileLogger(cfg_dir / "logs")
        self._file_log("APP START", f"exe={sys.executable if hasattr(sys, 'frozen') else __file__}")
        self._file_log("APP START", f"config_dir={cfg_dir}")
        self._file_log("APP START", f"python={sys.version}")
        self._file_log("APP START", f"platform={sys.platform}")

        # log config file contents
        cfg_path = cfg_dir / "config"
        if cfg_path.exists():
            try:
                content = cfg_path.read_text(encoding="utf-8")
                self._file_log("CONFIG", f"=== {cfg_path} ===")
                for line in content.splitlines():
                    self._file_log("CONFIG", line)
            except Exception as e:
                self._file_log("CONFIG", f"read error: {e}")
        else:
            self._file_log("CONFIG", f"config file not found: {cfg_path}")

        self.after(50, self._drain_log_queue)

        self.node = ReticulumNode(
            log_fn=self._qlog,
            config_dir=str(cfg_dir),
        )
        self.node.on_link_state = self._on_link_state

        self.after(800, lambda: self._qlog(f"Config dir: {cfg_dir}", "info"))
        self.after(820, lambda: self._qlog(f"Log file : {self.file_logger.path_str()}", "info"))
        if find_wintun_dll():
            self.after(850, lambda: self._qlog(f"wintun.dll: {find_wintun_dll()}", "ok"))
        else:
            self.after(850, lambda: self._qlog("wintun.dll: NOT FOUND (TUN will be unavailable)", "warn"))

        self.after(500, self._refresh_identity)
        self.after(500, self._refresh_stats)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        if args.pidfile:
            _write_pidfile(args.pidfile)
            atexit.register(_remove_pidfile, args.pidfile)
            self._file_log("PIDFILE", f"wrote pid={os.getpid()} to {args.pidfile}")

        self._load_tunnel_settings()

    # -----------------------------------------------------------------
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

    # -----------------------------------------------------------------
    def _build_ui(self):
        # --- top: identity --------------------------------------------------
        top = ttk.Frame(self, style="Panel.TFrame", padding=10)
        top.pack(side=tk.TOP, fill=tk.X)
        ttk.Label(top, text="My destination hash:", style="Panel.TLabel").pack(side=tk.LEFT)
        self.lbl_hash = ttk.Label(top, text="(initializing...)", style="Stat.TLabel")
        self.lbl_hash.pack(side=tk.LEFT, padx=8)
        ttk.Button(top, text="Logs",   command=self._open_logs).pack(side=tk.RIGHT, padx=(0, 6))
        ttk.Button(top, text="Interfaces", command=self._open_settings).pack(side=tk.RIGHT, padx=(0, 6))
        ttk.Button(top, text="Copy", command=self._copy_hash).pack(side=tk.RIGHT)

        # === log (fill remaining space) =====================================
        box_log = ttk.LabelFrame(self, text="Log")
        box_log.pack(side=tk.BOTTOM, fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        self.txt_log = scrolledtext.ScrolledText(box_log, height=8, bg="#101010", fg=self.FG, insertbackground=self.FG, font=("Consolas", 9))
        self.txt_log.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        self.txt_log.tag_config("info", foreground=self.FG)
        self.txt_log.tag_config("ok",   foreground=self.OK)
        self.txt_log.tag_config("warn", foreground=self.WARN)
        self.txt_log.tag_config("err",  foreground=self.ERR)

        # === middle area (fills between top and log) ========================
        mid = ttk.Frame(self, padding=10)
        mid.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        left  = ttk.Frame(mid)
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        right = ttk.Frame(mid)
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(5, 0))

        # === left column ====================================================
        # — connect box
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

        # — TUN config box
        box_tun = ttk.LabelFrame(left, text="TUN (Windows, optional via wintun.dll)")
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

        # === right column ===================================================
        # — stats
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


    # -----------------------------------------------------------------
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
            try: self.node.set_tun(None)
            except Exception: pass
        if self.node is not None:
            try: self.node.disconnect()
            except Exception: pass
            try: self.node.shutdown()
            except Exception: pass
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
        """Open log folder in file explorer."""
        log_dir = Path(self.file_logger.log_dir)
        log_dir.mkdir(parents=True, exist_ok=True)
        try:
            if sys.platform.startswith("win"):
                os.startfile(str(log_dir))   # open in explorer
            elif sys.platform == "darwin":
                os.system(f'open "{log_dir}"')
            else:
                os.system(f'xdg-open "{log_dir}"')
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
        if not self._is_admin():
            messagebox.showwarning(
                "Administrator required",
                "Creating TUN on Windows requires administrator privileges.\n"
                "Run the program as administrator."
            )
            return
        try:
            tun = WinTunInterface(
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

    def _get_default_gateway(self):
        """Get current default gateway via physical interface."""
        try:
            r = subprocess.run(
                ["route", "print", "0.0.0.0", "mask", "0.0.0.0"],
                capture_output=True, text=True, timeout=5,
            )
            for line in r.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 4 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                    gw = parts[2]
                    if gw != "10.244.0.1" and gw != "0.0.0.0":
                        return gw
        except Exception:
            pass
        return "192.168.0.1"

    def _get_rns_server(self):
        """Read RNS server IP from Reticulum config."""
        try:
            cfg_path = Path(self.node.config_dir) / "config"
            parsed = parse_reticulum_config(str(cfg_path))
            for it in parsed["interfaces"]:
                p = it["params"]
                if "target_host" in p:
                    return p["target_host"]
        except Exception:
            pass
        return None

    def _setup_routes(self, peer_ip):
        """Add VPN routes: RNS server via physical gateway, default via TUN."""
        gw = self._get_default_gateway()
        rns_server = self._get_rns_server()
        if not rns_server:
            self._qlog("[ROUTES] RNS server not found in config, skipping RNS route", "warn")
        else:
            self._qlog(f"[ROUTES] gateway={gw}, peer={peer_ip}", "info")
            try:
                subprocess.run(
                    ["route", "add", rns_server, "mask", "255.255.255.255", gw, "metric", "5"],
                    capture_output=True, timeout=5,
                )
                self._qlog(f"[ROUTES] {rns_server} -> {gw} metric 5", "ok")
            except Exception as e:
                self._qlog(f"[ROUTES] failed to add RNS route: {e}", "warn")
        try:
            ps_cmd = (
                f"New-NetRoute -DestinationPrefix '0.0.0.0/0' -InterfaceAlias 'tun0' "
                f"-NextHop '{peer_ip}' -RouteMetric 0 -ErrorAction SilentlyContinue"
            )
            rc = os.system(f'powershell -NoProfile -Command "{ps_cmd}"')
            if rc != 0:
                subprocess.run(
                    ["route", "add", "0.0.0.0", "mask", "0.0.0.0", peer_ip, "metric", "15"],
                    capture_output=True, timeout=5,
                )
            self._qlog(f"[ROUTES] default 0.0.0.0 -> {peer_ip} via tun0 metric 0", "ok")
        except Exception as e:
            self._qlog(f"[ROUTES] failed to add default route: {e}", "warn")

    def _teardown_routes(self):
        """Remove VPN routes on shutdown."""
        rns_server = self._get_rns_server()
        peer_ip = "10.244.0.1"
        self._qlog("[ROUTES] removing VPN routes...", "info")
        try:
            subprocess.run(
                ["route", "delete", "0.0.0.0", "mask", "0.0.0.0", peer_ip],
                capture_output=True, timeout=5,
            )
        except Exception:
            pass
        if rns_server:
            try:
                subprocess.run(
                    ["route", "delete", rns_server, "mask", "255.255.255.255"],
                    capture_output=True, timeout=5,
                )
            except Exception:
                pass
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
        """Direct write to file (without queue)."""
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

    def _is_admin(self):
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

    # -----------------------------------------------------------------
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
# Management helpers (pidfile, status, stop, dry-run, daemon-detach)
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
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        STILL_ACTIVE = 259
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        OpenProcess = kernel32.OpenProcess
        OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        OpenProcess.restype  = wintypes.HANDLE
        GetExitCodeProcess = kernel32.GetExitCodeProcess
        GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        GetExitCodeProcess.restype  = wintypes.BOOL
        CloseHandle = kernel32.CloseHandle
        CloseHandle.argtypes = [wintypes.HANDLE]
        CloseHandle.restype  = wintypes.BOOL
        h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
        if not h:
            return False
        code = wintypes.DWORD()
        ok = GetExitCodeProcess(h, ctypes.byref(code))
        CloseHandle(h)
        return bool(ok) and code.value == STILL_ACTIVE
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


def _default_pidfile_path(portable, config_dir_override):
    if config_dir_override:
        return os.path.join(os.path.expanduser(config_dir_override), "tun_rns_win.pid")
    return os.path.join(default_config_dir(portable=portable), "tun_rns_win.pid")


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
    if sys.platform == "win32":
        cmd = ["taskkill", "/F", "/PID", str(pid)] if force else ["taskkill", "/PID", str(pid)]
    else:
        sig = signal.SIGKILL if force else signal.SIGTERM
        try:
            os.kill(pid, sig)
            cmd = None
        except OSError as e:
            print(f"[X] kill failed: {e}", file=sys.stderr)
            return 1
    if cmd is not None:
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            print(f"[X] {' '.join(cmd)} failed: {r.stderr.strip()}", file=sys.stderr)
            return 1
    for _ in range(30):
        time.sleep(0.5)
        if not _pid_alive(pid):
            print("[+] stopped")
            _remove_pidfile(pidfile)
            return 0
    print("[!] not stopped in 15s")
    return 1


def _do_dry_run(args):
    cfg_dir = args.config_dir if args.config_dir else default_config_dir(portable=args.portable)
    cfg_dir = ensure_default_config(cfg_dir)
    cfg_path = Path(cfg_dir) / "config"
    if not cfg_path.is_file():
        print(f"[X] no config at {cfg_path}", file=sys.stderr)
        return 1
    try:
        parsed = parse_reticulum_config(str(cfg_path))
    except Exception as e:
        print(f"[X] parse error: {e}", file=sys.stderr)
        return 1
    print(f"[*] config: {cfg_path}")
    print(f"[*] {len(parsed['interfaces'])} interface(s):")
    for it in parsed["interfaces"]:
        p = it["params"]
        short = ", ".join(f"{k}={v}" for k, v in p.items())
        print(f"    [[{it['name']}]] {short}")
    errors = validate_interfaces(parsed["interfaces"])
    if errors:
        print(f"[X] {len(errors)} validation error(s):", file=sys.stderr)
        for e in errors:
            print(f"    {e}", file=sys.stderr)
        return 1
    print(f"[+] validation OK")
    print(f"[*] would start GUI (pidfile={args.pidfile})")
    print(f"[*] log file: {Path(cfg_dir) / 'logs' / 'rnstunnel.log'}")
    return 0


def _spawn_detached_child(args):
    if sys.platform != "win32":
        print("[!] --daemon is ignored on this platform (Windows only)", file=sys.stderr)
        return None
    DETACHED_PROCESS       = 0x00000008
    CREATE_NEW_PROCESS_GROUP = 0x00000200
    child_argv = [a for a in sys.argv[1:] if a != "--daemon"] + ["--__child"]
    cmd = [sys.executable, os.path.abspath(__file__)] + child_argv
    p = subprocess.Popen(
        cmd,
        creationflags=DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
    )
    print(f"[i] daemon started, pid={p.pid}, pidfile={args.pidfile}")
    return 0


# ============================================================================
def _run_cli(args):
    """CLI mode: headless, connection + TUN, no GUI."""
    def log(msg, level="info"):
        prefix = {"info": "[*] ", "ok": "[+] ", "warn": "[!] ", "err": "[X] "}.get(level, "")
        try:
            print(f"{prefix}{msg}", flush=True)
        except OSError:
            pass

    if not args.dest:
        print("[X] --cli requires --dest <hash>", file=sys.stderr)
        return 1

    if args.config_dir:
        config_dir = os.path.expanduser(args.config_dir)
    else:
        config_dir = default_config_dir(portable=args.portable)
    config_dir = ensure_default_config(config_dir)
    args.config_dir = config_dir

    log(f"Config: {config_dir}")
    log(f"Dest: {args.dest}")

    node = ReticulumNode(log_fn=log, config_dir=config_dir)

    log(f"Identity: {RNS.prettyhexrep(node.identity.hash)}")

    log(f"TUN: name={args.tun_name} ip={args.tun_ip} peer={args.tun_peer} mask={args.tun_mask} mtu={args.tun_mtu}")

    tun = WinTunInterface(
        name=args.tun_name, local_ip=args.tun_ip, peer_ip=args.tun_peer,
        netmask=args.tun_mask, mtu=args.tun_mtu, log=log,
    )
    try:
        tun.open()
    except Exception as e:
        log(f"TUN open failed: {e}", "err")
        return 1

    node.set_tun(tun)

    log(f"Connecting to {args.dest} ...")
    ok = node.connect_to(args.dest, timeout=30)
    if not ok:
        log("Connect failed", "err")
        tun.close()
        return 1

    log("Connected! TUN + link active.", "ok")

    def _get_rns_server_from_config():
        try:
            parsed = parse_reticulum_config(os.path.join(config_dir, "config"))
            for it in parsed["interfaces"]:
                p = it["params"]
                if "target_host" in p:
                    return p["target_host"]
        except Exception:
            pass
        return None

    def _setup_routes(peer_ip):
        gw = "192.168.0.1"
        try:
            r = subprocess.run(
                ["route", "print", "0.0.0.0", "mask", "0.0.0.0"],
                capture_output=True, text=True, timeout=5,
            )
            for line in r.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 4 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                    if parts[2] != "10.244.0.1" and parts[2] != "0.0.0.0":
                        gw = parts[2]
                        break
        except Exception:
            pass
        rns_server = _get_rns_server_from_config()
        if rns_server:
            subprocess.run(["route", "add", rns_server, "mask", "255.255.255.255", gw, "metric", "5"], capture_output=True, timeout=5)
            log(f"[ROUTES] {rns_server} -> {gw} metric 5", "ok")
        ps_cmd = (
            f"New-NetRoute -DestinationPrefix '0.0.0.0/0' -InterfaceAlias 'tun0' "
            f"-NextHop '{peer_ip}' -RouteMetric 0 -ErrorAction SilentlyContinue"
        )
        rc = os.system(f'powershell -NoProfile -Command "{ps_cmd}"')
        if rc != 0:
            subprocess.run(["route", "add", "0.0.0.0", "mask", "0.0.0.0", peer_ip, "metric", "15"], capture_output=True, timeout=5)
        log(f"[ROUTES] default -> {peer_ip} via tun0 metric 0", "ok")

    def _teardown_routes(peer_ip):
        rns_server = _get_rns_server_from_config()
        log("[ROUTES] removing VPN routes...", "info")
        ps_cmd = (
            f"Remove-NetRoute -DestinationPrefix '0.0.0.0/0' -InterfaceAlias 'tun0' "
            f"-NextHop '{peer_ip}' -Confirm:$false -ErrorAction SilentlyContinue"
        )
        os.system(f'powershell -NoProfile -Command "{ps_cmd}"')
        subprocess.run(["route", "delete", "0.0.0.0", "mask", "0.0.0.0", peer_ip], capture_output=True, timeout=5)
        if rns_server:
            subprocess.run(["route", "delete", rns_server, "mask", "255.255.255.255"], capture_output=True, timeout=5)
        log("[ROUTES] VPN routes removed", "ok")

    _setup_routes(args.tun_peer)

    stop = threading.Event()
    def _sig(s, f):
        log("Signal received, stopping...", "warn")
        stop.set()
    signal.signal(signal.SIGINT, _sig)
    signal.signal(signal.SIGTERM, _sig)

    t0 = time.time()
    while not stop.is_set():
        time.sleep(1)
        elapsed = int(time.time() - t0)
        with node._link_lock:
            nlinks = 1 if node.link and node.link.status == RNS.Link.ACTIVE else 0
        try:
            sys.stdout.write(
                f"\r[TUN:{tun.name} {tun.local_ip}] "
                f"links={nlinks}  "
                f"rx={tun.rx_bytes:>10} B  tx={tun.tx_bytes:>10} B  "
                f"rns_rx={node.rx_bytes:>10} B  rns_tx={node.tx_bytes:>10} B  "
                f"up={elapsed}s"
            )
            sys.stdout.flush()
        except OSError:
            pass

    log("\nShutting down...")
    _teardown_routes(args.tun_peer)
    node.disconnect()
    node.shutdown()
    tun.close()
    log("Done.", "ok")
    return 0


def main():
    ap = argparse.ArgumentParser(
        description="Reticulum TUN tunnel — Windows GUI (isolated Reticulum)",
        # argparse uses %-formatting in help, so escape %
        formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=40),
    )
    ap.add_argument("--config-dir", default=None,
                    help="Reticulum config directory "
                         "(default: %%APPDATA%%\\Reticulum or .\\config with --portable)")
    ap.add_argument("--portable",   action="store_true",
                    help="store config/identity next to .exe (in ./config subfolder)")
    ap.add_argument("--dest",       default=None,
                    help="endpoint destination hash for auto-connect on startup")
    ap.add_argument("--pidfile",    default=None,
                    help="PID file (default: <config-dir>/tun_rns_win.pid)")
    ap.add_argument("--status",     action="store_true",
                    help="check if instance is running and exit")
    ap.add_argument("--stop",       action="store_true",
                    help="send graceful shutdown (taskkill / WM_CLOSE) and exit")
    ap.add_argument("--force-stop", action="store_true",
                    help="force kill process (taskkill /F / SIGKILL)")
    ap.add_argument("--dry-run",    action="store_true",
                    help="check config/interfaces and exit without launching GUI")
    ap.add_argument("--cli",        action="store_true",
                    help="CLI mode: no GUI, connects to --dest, starts TUN")
    ap.add_argument("--tun-name",   default="tun0",
                    help="TUN adapter name (default: tun0)")
    ap.add_argument("--tun-ip",     default="10.244.0.2",
                    help="TUN adapter IP (default: 10.244.0.2)")
    ap.add_argument("--tun-peer",   default="10.244.0.1",
                    help="peer IP (default: 10.244.0.1)")
    ap.add_argument("--tun-mask",   default="255.255.255.0",
                    help="TUN mask (default: 255.255.255.0)")
    ap.add_argument("--tun-mtu",    type=int, default=1500,
                    help="TUN MTU (default: 1500)")
    ap.add_argument("--daemon",     action="store_true",
                    help="(Windows) restart in background (DETACHED_PROCESS)")
    ap.add_argument("--mss-clamp",  action="store_true",
                    help="(Linux only) iptables TCPMSS; ignored on Windows")
    ap.add_argument("--__child",    action="store_true",
                    help=argparse.SUPPRESS)
    args = ap.parse_args()

    if args.pidfile is None:
        args.pidfile = _default_pidfile_path(args.portable, args.config_dir)

    if args.status:
        return _do_status(args.pidfile)
    if args.stop or args.force_stop:
        return _do_stop(args.pidfile, force=args.force_stop)
    if args.dry_run:
        return _do_dry_run(args)
    if args.cli:
        return _run_cli(args)

    if args.daemon and not args.__child:
        rc = _spawn_detached_child(args)
        if rc is not None:
            return rc

    if args.mss_clamp and sys.platform == "win32":
        print("[!] --mss-clamp: not implemented on Windows, ignored", file=sys.stderr)

    if not args.dry_run and args.pidfile:
        existing = _read_pidfile(args.pidfile)
        if existing and _pid_alive(existing) and not args.__child:
            print(f"[X] already running, pid={existing}, pidfile={args.pidfile}", file=sys.stderr)
            return 1

    if args.config_dir:
        config_dir = os.path.expanduser(args.config_dir)
    else:
        config_dir = default_config_dir(portable=args.portable)
    config_dir = ensure_default_config(config_dir)

    args.config_dir = config_dir
    print(f"[i] Reticulum config: {config_dir}", file=sys.stderr)
    print(f"[i] Mode: {'portable' if args.portable else 'isolated (%APPDATA%)'}", file=sys.stderr)
    print(f"[i] Pidfile: {args.pidfile}", file=sys.stderr)

    app = App(args)
    app.mainloop()


if __name__ == "__main__":
    sys.exit(main() or 0)
