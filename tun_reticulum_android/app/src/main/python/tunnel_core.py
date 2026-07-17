import os
import sys
import socket as _socket_mod
import threading
import time
import zlib
from pathlib import Path

import RNS

APP_NAME = "rnstunnel"
ASPECT   = "endpoint"

_identity    = None
_destination = None
_link        = None
_link_lock   = threading.Lock()
_link_active = threading.Event()

_tun_fd     = None
_tun_stop   = threading.Event()
_tun_thread = None
android_tun = None
_tun_tx_bytes   = 0
_tun_tx_packets = 0
_tun_rx_bytes   = 0
_tun_rx_packets = 0
_tun_tx_dropped = 0
_tun_rx_dropped = 0

_use_compression = False
COMPRESS_MARKER = b'\x01'
RAW_MARKER      = b'\x00'

_assigned_client_ip = None

_server_ips = set()

_verbose = False

_config_dir = None
_log_lines  = []
_log_lock   = threading.Lock()
_my_hash    = ""

_PROTO_NAMES = {
    1: "ICMP", 2: "IGMP", 4: "IPIP", 6: "TCP", 8: "EGP",
    9: "IGP", 17: "UDP", 41: "IPv6", 47: "GRE", 50: "ESP",
    51: "AH", 89: "OSPF", 103: "PIM", 112: "VRRP", 115: "L2TP",
}


def compress_packet(data):
    c = zlib.compress(data, 1)
    return (COMPRESS_MARKER + c) if len(c) < len(data) else (RAW_MARKER + data)


def decompress_packet(data):
    if not data:
        return data
    if data[0] == 0x01:
        try:
            return zlib.decompress(data[1:])
        except Exception:
            return data
    elif data[0] == 0x00:
        return data[1:]
    return data


def _log(msg, level="info"):
    ts = time.strftime("%H:%M:%S")
    line = f"{ts} [{level.upper():5}] {msg}"
    with _log_lock:
        _log_lines.append(line)
        if len(_log_lines) > 500:
            _log_lines[:] = _log_lines[-500:]
    print(line, file=sys.stderr, flush=True)


def get_log():
    with _log_lock:
        return "\n".join(_log_lines)


def get_my_hash():
    return _my_hash


def set_verbose(v):
    global _verbose
    _verbose = v
    _log(f"[VERBOSE] {'on' if v else 'off'}")


def _pkt_info(data):
    if len(data) < 20:
        return "?", "?", "?", 0
    version = (data[0] >> 4) & 0xF
    if version == 4:
        proto = data[9]
        src = f"{data[12]}.{data[13]}.{data[14]}.{data[15]}"
        dst = f"{data[16]}.{data[17]}.{data[18]}.{data[19]}"
    elif version == 6 and len(data) >= 40:
        proto = data[6]
        src = "::".join(f"{data[i]:02x}{data[i+1]:02x}" for i in range(8, 24, 2))
        dst = "::".join(f"{data[i]:02x}{data[i+1]:02x}" for i in range(24, 40, 2))
    else:
        return "?", "?", "?", 0
    pname = _PROTO_NAMES.get(proto, str(proto))
    return src, dst, pname, version


def _log_pkt(dir_label, data, extra=""):
    if len(data) < 20:
        return
    src, dst, proto, ver = _pkt_info(data)
    _log(f"{dir_label} {len(data)}B v{ver} {proto} {src}→{dst}{extra}")


class AndroidTunInterface:
    def __init__(self, fd, mtu=1500):
        self.fd     = fd
        self.mtu    = mtu
        self._stop  = threading.Event()
        self._thread= None
        self.on_packet = None
        self.tx_lock   = threading.Lock()
        self.rx_bytes  = 0
        self.tx_bytes  = 0
        self.opened    = False

    def start(self):
        self._stop.clear()
        self._thread = threading.Thread(target=self._reader, daemon=True)
        self._thread.start()
        self.opened = True
        _log("[TUN] reader started")

    def _reader(self):
        import select
        while not self._stop.is_set():
            try:
                r, _, _ = select.select([self.fd], [], [], 0.5)
                if not r:
                    continue
                data = os.read(self.fd, self.mtu + 32)
                if not data:
                    _log("[TUN] EOF on fd", "warn")
                    break
                sz = len(data)
                self.rx_bytes += sz
                if self.on_packet:
                    try:
                        self.on_packet(data)
                    except Exception as e:
                        _log(f"[TUN] on_packet: {e}", "err")
            except OSError as e:
                if not self._stop.is_set():
                    _log(f"[TUN] read error: {e}", "err")
                break

    def write(self, data):
        if not self.opened:
            return False
        with self.tx_lock:
            try:
                os.write(self.fd, data)
                self.tx_bytes += len(data)
                return True
            except OSError as e:
                _log(f"[TUN] write error: {e}", "err")
                return False

    def close(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)
        self.opened = False


def _ensure_config(config_dir):
    p = Path(config_dir)
    p.mkdir(parents=True, exist_ok=True)
    (p / "storage").mkdir(exist_ok=True)
    cfg = p / "config"
    if not cfg.exists():
        cfg.write_text("""[reticulum]
  share_instance = False
  enable_transport = True
  instance_name = rnstunnel-android

[interfaces]
""", encoding="utf-8")


def setup(config_dir, server_host, server_port, dest_hash, use_compression=False):
    global _config_dir, _server_host, _server_port, _use_compression
    _config_dir = config_dir
    _server_host = server_host
    _server_port = server_port
    _use_compression = use_compression
    _log(f"[SETUP] config={config_dir} server={server_host}:{server_port} dest={dest_hash} compress={use_compression}")

    _ensure_config(config_dir)
    _add_tcp_interface_to_config(server_host, server_port)
    _install_socket_hook()
    _init_rns()
    _connect(dest_hash)


def setup_rns(config_dir, server_host, server_port, use_compression=False):
    global _config_dir, _server_host, _server_port, _use_compression
    _config_dir = config_dir
    _server_host = server_host
    _server_port = server_port
    _use_compression = use_compression
    _log(f"[SETUP] config={config_dir} server={server_host}:{server_port} compress={use_compression}")

    _ensure_config(config_dir)
    _add_tcp_interface_to_config(server_host, server_port)
    _install_socket_hook()
    _init_rns()


_server_host = None
_server_port = None
_socket_fd = -1

_orig_connect = None

def _install_socket_hook():
    global _socket_fd, _orig_connect, _server_ips
    _socket_fd = -1
    _server_ips = set()
    if _server_host:
        try:
            for res in _socket_mod.getaddrinfo(_server_host, None):
                _server_ips.add(res[4][0])
        except Exception:
            pass
    if _orig_connect is None:
        _orig_connect = _socket_mod.socket.connect

    def _hooked_connect(self, addr):
        global _socket_fd
        try:
            host, port = addr
            is_target = False
            if port == _server_port or _server_port is None:
                if host == _server_host or host in _server_ips:
                    is_target = True
                else:
                    try:
                        resolved = {res[4][0] for res in _socket_mod.getaddrinfo(host, None)}
                        if resolved & _server_ips or _server_host in resolved:
                            is_target = True
                    except Exception:
                        pass
            if is_target:
                _socket_fd = self.fileno()
                _log(f"[SOCKET] captured fd={_socket_fd} for {host}:{port}", "ok")
                try:
                    from java import jclass
                    RnsBridge = jclass("com.reticulum.tun.RnsBridge")
                    protected = RnsBridge.protectFd(_socket_fd)
                    _log(f"[SOCKET] java protect result={protected} for fd={_socket_fd}", "ok" if protected else "warn")
                except Exception as ex:
                    _log(f"[SOCKET] failed java protect for fd={_socket_fd}: {ex}", "warn")
            elif _server_host is not None:
                _log(f"[SOCKET] mismatch: connect({host}:{port}) vs target({_server_host}:{_server_port})", "info")
        except Exception as ex:
            _log(f"[SOCKET] hook error: {ex} for addr={addr}", "warn")
        return _orig_connect(self, addr)

    _socket_mod.socket.connect = _hooked_connect
    _log(f"[SOCKET] connect hook installed, target={_server_host}:{_server_port} ({len(_server_ips)} IPs)", "info")

def get_tcp_socket_fd():
    if _socket_fd >= 0:
        _log(f"[SOCKET] returning captured fd={_socket_fd}", "ok")
        return _socket_fd
    _log(f"[SOCKET] no captured socket fd (hook may have missed it)", "warn")
    return -1


def connect_link(dest_hash):
    _connect(dest_hash)


def _add_tcp_interface_to_config(host, port):
    cfg_path = os.path.join(_config_dir, "config")
    config_content = f"""[reticulum]
  share_instance = False
  enable_transport = True
  instance_name = rnstunnel-android

[interfaces]
  [[RNS Server]]
    type = TCPClientInterface
    enabled = True
    target_host = {host}
    target_port = {port}
"""
    with open(cfg_path, "w", encoding="utf-8") as f:
        f.write(config_content)
    _log(f"[CONFIG] wrote interface configuration: {host}:{port}")


def _init_rns():
    global _identity, _destination, _my_hash

    if RNS.Reticulum._Reticulum__instance is not None:
        _log("[RNS] Reticulum already initialized, reusing instance", "ok")
    else:
        import signal as _signal
        _original_signal = _signal.signal
        _signal.signal = lambda *a, **kw: None
        try:
            RNS.Reticulum(configdir=_config_dir)
        except SystemExit:
            _log("[RNS] init failed (SystemExit)", "err")
            return
        finally:
            _signal.signal = _original_signal
        _log("[RNS] initialized", "ok")

    storage = os.path.join(_config_dir, "storage")
    id_path = os.path.join(storage, "android_identity")

    if os.path.isfile(id_path):
        _identity = RNS.Identity.from_file(id_path)
        _log("[RNS] identity loaded", "ok")
    else:
        _identity = RNS.Identity()
        _identity.to_file(id_path)
        _log("[RNS] identity created", "ok")

    _destination = RNS.Destination(
        _identity,
        RNS.Destination.IN,
        RNS.Destination.SINGLE,
        APP_NAME,
        ASPECT,
    )
    _destination.set_proof_strategy(RNS.Destination.PROVE_ALL)
    _destination.set_packet_callback(_on_direct_packet)
    _destination.set_link_established_callback(_on_link_established)
    _destination.announce()

    _my_hash = RNS.prettyhexrep(_destination.hash)
    _log(f"[RNS] my hash: {_my_hash}", "ok")


def _connect(dest_hash):
    _log(f"[RNS] connecting to {dest_hash}...")
    try:
        dest_bytes = bytes.fromhex(dest_hash)
    except ValueError:
        _log(f"[RNS] invalid hash: {dest_hash}", "err")
        _link_active.set()
        return

    if not RNS.Transport.has_path(dest_bytes):
        _log("[RNS] requesting path...")
        RNS.Transport.request_path(dest_bytes)
        t0 = time.time()
        while not RNS.Transport.has_path(dest_bytes) and time.time() - t0 < 30:
            if _tun_stop.is_set():
                _log("[RNS] path request aborted by stop", "info")
                _link_active.set()
                return
            time.sleep(0.2)
        if not RNS.Transport.has_path(dest_bytes):
            _log("[RNS] path not found (timeout)", "err")
            _link_active.set()
            return
        _log("[RNS] path found", "ok")

    try:
        server_identity = RNS.Identity.recall(dest_bytes)
        _log("[RNS] server identity recalled", "ok")
    except Exception as e:
        _log(f"[RNS] identity recall: {e}", "err")
        _link_active.set()
        return

    server_dest = RNS.Destination(
        server_identity,
        RNS.Destination.OUT,
        RNS.Destination.SINGLE,
        APP_NAME,
        ASPECT,
    )

    _log("[RNS] establishing link...")
    link = RNS.Link(server_dest)
    t0 = time.time()
    while link.status not in (RNS.Link.ACTIVE, RNS.Link.CLOSED) and time.time() - t0 < 30:
        if _tun_stop.is_set():
            _log("[RNS] link establishment aborted by stop", "info")
            try:
                link.teardown()
            except Exception:
                pass
            _link_active.set()
            return
        time.sleep(0.1)

    if link.status != RNS.Link.ACTIVE:
        _log(f"[RNS] link status={link.status}, not active", "err")
        _link_active.set()
        return

    _attach_link(link)


def _attach_link(link):
    global _link
    with _link_lock:
        _link = link
    link.set_link_closed_callback(_on_link_closed)
    link.set_resource_callback(_on_resource_advertised)
    link.set_packet_callback(_on_link_packet)
    _link_active.set()
    _log("[RNS] link active", "ok")


def _on_link_established(link):
    _log("[RNS] inbound link established")
    _attach_link(link)


def _on_link_closed(link):
    with _link_lock:
        if _link is link:
            _link = None
    _link_active.clear()
    _log("[RNS] link closed", "warn")


def _on_link_packet(message, packet):
    global _tun_rx_bytes, _tun_rx_packets
    _tun_rx_bytes += len(message)
    _tun_rx_packets += 1
    _tun_write(decompress_packet(message))


def _on_resource_advertised(resource):
    _log(f"[RNS] resource advertised: {resource.getSize()}B from {resource.sender}")
    resource.set_callback(_on_resource_complete)
    return True


def _on_resource_complete(resource):
    global _tun_rx_bytes, _tun_rx_packets
    try:
        data = bytes(resource.data)
    except Exception:
        _log("[RNS] resource data error", "err")
        return
    if not data:
        return
    _tun_rx_bytes += len(data)
    _tun_rx_packets += 1
    _log(f"[RES→TUN] {len(data)}B resource complete")
    _tun_write(decompress_packet(data))


def _on_direct_packet(data, packet):
    global _tun_rx_bytes, _tun_rx_packets
    _tun_rx_bytes += len(data)
    _tun_rx_packets += 1
    _tun_write(decompress_packet(data))


def _tun_to_link(data):
    if len(data) < 20:
        return
    version = (data[0] >> 4) & 0xF
    if version == 4:
        dst = data[16:20]
        if dst[0] >= 224 or dst == b'\xff\xff\xff\xff':
            return
        protocol = data[9]
        if protocol == 17 and len(data) >= 24:
            dst_port = int.from_bytes(data[22:24], 'big')
            if dst_port in (5353, 5355, 137, 138, 1900):
                return
    elif version == 6:
        if data[24] == 0xff:
            return
    global _tun_tx_bytes, _tun_tx_packets, _tun_tx_dropped
    with _link_lock:
        link = _link
    if not link or link.status != RNS.Link.ACTIVE:
        _tun_tx_dropped += 1
        return
    if _use_compression:
        data = compress_packet(data)
    try:
        pkt = RNS.Packet(link, data)
        pkt.send()
        _tun_tx_bytes += len(data)
        _tun_tx_packets += 1
    except Exception as e:
        _log(f"[TUN→RNS] send error: {e}", "err")
        _tun_tx_dropped += 1


def _tun_write(data):
    global _tun_rx_bytes, _tun_rx_packets
    if android_tun and android_tun.opened:
        try:
            android_tun.write(data)
        except Exception:
            pass


def start_tun(tun_fd, mtu=1500):
    global android_tun, _tun_thread, _tun_stop

    _log(f"[TUN] starting fd={tun_fd} mtu={mtu}")
    _tun_stop.clear()

    android_tun = AndroidTunInterface(tun_fd, mtu)
    android_tun.on_packet = _tun_to_link
    android_tun.start()

    _tun_thread = threading.Thread(target=_tun_stats_loop, daemon=True)
    _tun_thread.start()
    _log("[TUN] bridge active", "ok")


def _tun_stats_loop():
    last_rx = 0
    last_tx = 0
    last_t = time.time()
    while not _tun_stop.is_set():
        time.sleep(5)
        now = time.time()
        dt = now - last_t
        drx = _tun_rx_bytes - last_rx
        dtx = _tun_tx_bytes - last_tx
        last_rx = _tun_rx_bytes
        last_tx = _tun_tx_bytes
        last_t = now
        rxs = drx / dt if dt > 0 else 0
        txs = dtx / dt if dt > 0 else 0
        _log(
            f"[STATS] {dt:.0f}s  "
            f"RX {_tun_rx_bytes}B ({rxs:.0f} B/s)  "
            f"TX {_tun_tx_bytes}B ({txs:.0f} B/s)  "
            f"dropped_tx={_tun_tx_dropped}"
        )


def wait_for_link(timeout=45):
    t0 = time.time()
    while time.time() - t0 < timeout:
        if _tun_stop.is_set():
            _log("[RNS] wait for link aborted by user stop", "info")
            return False
        if _link_active.is_set():
            _log("[RNS] link ready, requesting IP from host...", "info")
            if _request_ip_from_host():
                _log(f"[RNS] assigned IP from host: {_assigned_client_ip}", "ok")
            else:
                _log("[RNS] failed to get IP from host, using fallback", "warn")
            return True
        time.sleep(0.2)
    _log("[RNS] link not ready within timeout", "err")
    return False


def _request_ip_from_host():
    global _assigned_client_ip
    with _link_lock:
        link = _link
    if not link or link.status != RNS.Link.ACTIVE:
        return False
        
    evt = threading.Event()
    success = False
    
    def _response_cb(receipt):
        global _assigned_client_ip
        nonlocal success
        try:
            res_data = receipt.response
            if res_data:
                _assigned_client_ip = res_data.decode("utf-8").strip()
                success = True
        except Exception as e:
            _log(f"Error parsing IP assignment response: {e}", "err")
        evt.set()
        
    def _failed_cb(receipt):
        evt.set()
        
    try:
        link.request(
            "/ip_assign",
            b"",
            response_callback=_response_cb,
            failed_callback=_failed_cb,
            timeout=10
        )
    except Exception as e:
        _log(f"Failed to send IP request: {e}", "err")
        return False
        
    evt.wait(timeout=10)
    return success


def get_client_ip():
    if _assigned_client_ip:
        return _assigned_client_ip
    if _destination and _destination.hash:
        val = _destination.hash[-1]
        ip_last = 2 + (val % 253)
        return f"10.244.0.{ip_last}"
    return "10.244.0.2"


def stop_all():
    global _link
    _log("[STOP] shutting down...")
    _tun_stop.set()
    if android_tun:
        android_tun.close()
    global _tun_thread
    if _tun_thread:
        _tun_thread.join(timeout=2)
        _tun_thread = None
    with _link_lock:
        if _link:
            try:
                _link.teardown()
            except Exception:
                pass
            _link = None
    _link_active.clear()
    try:
        RNS.Transport.detach_interfaces()
    except Exception:
        pass
    try:
        RNS.Reticulum._Reticulum__instance.teardown()
    except Exception:
        pass
    RNS.Reticulum._Reticulum__instance = None
    _log(f"[STOP] done  rx={_tun_rx_bytes} tx={_tun_tx_bytes} dropped_tx={_tun_tx_dropped}", "ok")
