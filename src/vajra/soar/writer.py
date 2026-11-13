#!/usr/bin/env python3
"""Firewall writer - the only process that changes the host firewall, behind a unix socket"""

import argparse
import ctypes
import grp
import ipaddress
import json
import logging
import os
import signal
import socket
import socketserver
import stat
import struct
import sys
import threading
import time
from collections import deque
from typing import Any, Callable, Dict, List, Optional, Tuple

from vajra.common.logging import setup_logging
from vajra.soar.firewall import FirewallManager
from vajra.soar.writer_client import DEFAULT_SOCKET, MAX_REASON, MAX_TTL, PROTOCOL_VERSION, parse_address

MAX_REQUEST_BYTES = 4096
CAP_NET_ADMIN = 12
CAP_NET_RAW = 13

# Same logger as firewall.py; main() points it at logs/writer.log
logger = logging.getLogger("soar_engine.firewall")


def error_response(code: str, message: str) -> Dict[str, Any]:
    """Build an error response"""
    return {"v": PROTOCOL_VERSION, "ok": False, "error": code, "message": message}


def ok_response(**fields: Any) -> Dict[str, Any]:
    """Build a success response"""
    return dict({"v": PROTOCOL_VERSION, "ok": True}, **fields)


def clean_text(text: str) -> str:
    """Replace control characters so a reason cannot forge log lines"""
    return "".join(c if c.isprintable() else "?" for c in text)


class FirewallWriter:
    """Validates requests and applies them through a FirewallManager"""

    def __init__(self, fw: FirewallManager, group_gid: int, max_per_minute: int = 60,
                 clock: Callable[[], float] = time.monotonic):
        self.fw = fw
        self.group_gid = group_gid
        self.max_per_minute = max_per_minute
        self.clock = clock
        self._block_times: deque = deque()
        self._lock = threading.Lock()

    def check_address(self, text: Any) -> Tuple[Optional[str], Optional[str]]:
        """Return (canonical, None) for a blockable address or (None, error_code)"""
        ip = parse_address(text)
        if ip is None:
            return None, "invalid_address"
        address = ipaddress.ip_address(ip)
        if (address.is_unspecified or address.is_loopback or address.is_link_local or address.is_multicast
                or address.is_reserved or self.fw.is_allowlisted(ip)):
            return None, "protected"
        return ip, None

    def _rate_limited(self) -> bool:
        """Drop block times older than a minute and report whether the cap is reached"""
        now = self.clock()
        while self._block_times and now - self._block_times[0] >= 60:
            self._block_times.popleft()
        return len(self._block_times) >= self.max_per_minute

    def handle(self, request: Any, uid: int = 0) -> Dict[str, Any]:
        """Validate one request and return its response"""
        if not isinstance(request, dict):
            return error_response("bad_request", "request must be a JSON object")
        if "v" not in request:
            return error_response("bad_request", "missing key: v")
        version = request["v"]
        if isinstance(version, bool) or version != PROTOCOL_VERSION:
            return error_response("unsupported_version", f"only version {PROTOCOL_VERSION} is supported")
        op = request.get("op")
        required = {"block": {"v", "op", "ip", "ttl"}, "unblock": {"v", "op", "ip"}, "list": {"v", "op"}}
        if not isinstance(op, str) or op not in required:
            return error_response("unknown_op", "op must be block, unblock or list")
        optional = {"reason"} if op == "block" else set()
        keys = set(request)
        if not required[op] <= keys or keys - required[op] - optional:
            return error_response("bad_request", f"wrong keys for {op}")
        if op == "list":
            return self._list()
        if op == "unblock":
            return self._unblock(request["ip"], uid)
        return self._block(request, uid)

    def _list(self) -> Dict[str, Any]:
        """Answer the list operation"""
        with self.fw._lock:
            blocks = [{"ip": ip, "expires_at": self.fw.block_expiry.get(ip)} for ip in sorted(self.fw.blocked_ips) if ip]
        return ok_response(enforcing=self.fw.enforcing, backend=self.fw.backend, blocks=blocks)

    def _unblock(self, text: Any, uid: int) -> Dict[str, Any]:
        """Answer the unblock operation"""
        ip = parse_address(text)
        if ip is None:
            return error_response("invalid_address", "not an IP address")
        if not self.fw.unblock_ip(ip):
            return error_response("failed", f"could not unblock {ip}")
        logger.info(f"Unblock {ip} for uid {uid}")
        return ok_response()

    def _block(self, request: Dict[str, Any], uid: int) -> Dict[str, Any]:
        """Answer the block operation"""
        ttl = request["ttl"]
        reason = request.get("reason", "")
        if isinstance(ttl, bool) or not isinstance(ttl, int) or not 0 <= ttl <= MAX_TTL:
            return error_response("bad_request", f"ttl must be an integer from 0 to {MAX_TTL}")
        if not isinstance(reason, str) or len(reason) > MAX_REASON:
            return error_response("bad_request", f"reason must be a string of at most {MAX_REASON} characters")
        ip, error = self.check_address(request["ip"])
        if error:
            logger.warning(f"Refused block {clean_text(str(request['ip']))[:64]} for uid {uid}: {error}")
            return error_response(error, "address cannot be blocked")
        if not self.fw.enforcing:
            return error_response("not_enforced", "the writer is in dry run or has no firewall backend")
        with self._lock:
            if ip in self.fw.blocked_ips:
                return ok_response(expires_at=self.fw.block_expiry.get(ip))
            if self._rate_limited():
                logger.warning(f"Refused block {ip} for uid {uid}: rate_limited")
                return error_response("rate_limited", f"more than {self.max_per_minute} new blocks in a minute")
            self._block_times.append(self.clock())
            expires_at = time.time() + ttl if ttl else None
            logger.info(f"Block {ip} ttl={ttl}s for uid {uid}: {clean_text(reason)}")
            if not self.fw.block_ip(ip, clean_text(reason), expires_at=expires_at):
                return error_response("failed", f"could not block {ip}")
            return ok_response(expires_at=self.fw.block_expiry.get(ip))

    def _peer_groups(self, pid: int) -> List[int]:
        """Read the supplementary groups of a process"""
        try:
            with open(f"/proc/{pid}/status") as f:
                for line in f:
                    if line.startswith("Groups:"):
                        return [int(g) for g in line.split()[1:]]
        except (OSError, ValueError):
            pass
        return []

    def peer_allowed(self, pid: int, uid: int, gid: int) -> bool:
        """Allow root, the writer's own user and members of the writer's group"""
        if uid == 0 or uid == os.geteuid() or gid == self.group_gid:
            return True
        return self.group_gid in self._peer_groups(pid)


def prepare_socket(path: str, gid: int) -> socket.socket:
    """Bind the listening socket with the right owner and mode"""
    parent = os.path.dirname(path) or "."
    if not os.path.isdir(parent):
        os.makedirs(parent)
        os.chown(parent, -1, gid)
        os.chmod(parent, 0o2750)
    if os.path.lexists(path):
        if not stat.S_ISSOCK(os.lstat(path).st_mode):
            raise SystemExit(f"{path} exists and is not a socket")
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            probe.connect(path)
        except OSError:
            os.unlink(path)
        else:
            raise SystemExit(f"Another writer is listening on {path}")
        finally:
            probe.close()
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    old_umask = os.umask(0o177)
    try:
        sock.bind(path)
    finally:
        os.umask(old_umask)
    os.chown(path, -1, gid)
    os.chmod(path, 0o660)
    sock.listen(16)
    return sock


def make_server(writer: FirewallWriter, sock: socket.socket) -> socketserver.ThreadingUnixStreamServer:
    """Build a server around a bound socket; the caller runs serve_forever"""

    class Handler(socketserver.StreamRequestHandler):
        timeout = 30

        def _send(self, response: Dict[str, Any]):
            self.wfile.write(json.dumps(response).encode("utf-8") + b"\n")
            self.wfile.flush()

        def handle(self):
            try:
                pid, uid, gid = struct.unpack("3i", self.request.getsockopt(
                    socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
                if not writer.peer_allowed(pid, uid, gid):
                    logger.warning(f"Refused connection from uid {uid} gid {gid} pid {pid}")
                    self._send(error_response("forbidden", "peer is not allowed to use the writer"))
                    return
                while True:
                    line = self.rfile.readline(MAX_REQUEST_BYTES + 1)
                    if not line:
                        return
                    if not line.endswith(b"\n"):
                        if len(line) > MAX_REQUEST_BYTES:
                            self._send(error_response("bad_request", "request line too long"))
                        return
                    try:
                        request = json.loads(line)
                    except (ValueError, RecursionError):
                        self._send(error_response("bad_request", "request is not valid JSON"))
                        continue
                    try:
                        response = writer.handle(request, uid=uid)
                    except Exception as e:
                        logger.error(f"Request from uid {uid} failed: {e!r}")
                        response = error_response("failed", "internal error")
                    self._send(response)
            except OSError:
                return

    server = socketserver.ThreadingUnixStreamServer(sock.getsockname(), Handler, bind_and_activate=False)
    server.socket.close()
    server.socket = sock
    server.daemon_threads = True
    return server


def drop_capabilities(keep: List[int]):
    """Drop every capability except those in keep, failing closed"""
    if os.geteuid() != 0 or sys.platform != "linux":
        logger.info("Not root on Linux, skipping capability drop")
        return
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        with open("/proc/sys/kernel/cap_last_cap") as f:
            last_cap = int(f.read())
        for cap in range(last_cap + 1):
            if cap not in keep and libc.prctl(24, cap, 0, 0, 0) != 0:
                raise OSError(ctypes.get_errno(), f"PR_CAPBSET_DROP {cap} failed")

        class Header(ctypes.Structure):
            _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]

        class Data(ctypes.Structure):
            _fields_ = [("effective", ctypes.c_uint32), ("permitted", ctypes.c_uint32),
                        ("inheritable", ctypes.c_uint32)]

        mask = sum(1 << cap for cap in keep)
        data = (Data * 2)()
        data[0].effective = data[0].permitted = mask & 0xFFFFFFFF
        data[1].effective = data[1].permitted = mask >> 32
        header = Header(0x20080522, 0)
        if libc.capset(ctypes.byref(header), data) != 0:
            raise OSError(ctypes.get_errno(), "capset failed")
    except (OSError, ValueError) as e:
        raise SystemExit(f"Could not drop capabilities: {e}")
    logger.info(f"Dropped capabilities, keeping {keep}")


def main():
    """Run the firewall writer"""
    parser = argparse.ArgumentParser(description="Vajra firewall writer")
    parser.add_argument("--socket", default=os.environ.get("VAJRA_WRITER_SOCKET", DEFAULT_SOCKET),
                        help="Path of the unix socket to listen on")
    parser.add_argument("--group", default="vajra", help="Group allowed to use the writer")
    parser.add_argument("--allow", action="append", default=[], metavar="CIDR",
                        help="Address or network that must never be blocked (repeatable)")
    parser.add_argument("--dry-run", action="store_true", help="Answer requests without changing the firewall")
    parser.add_argument("--max-blocks-per-minute", type=int,
                        default=int(os.environ.get("VAJRA_WRITER_MAX_BLOCKS_PER_MINUTE", 60)), metavar="N",
                        help="Refuse new blocks past this many a minute (default: 60 or "
                             "VAJRA_WRITER_MAX_BLOCKS_PER_MINUTE)")
    args = parser.parse_args()
    setup_logging("soar_engine.firewall", "logs/writer.log")
    if args.max_blocks_per_minute < 1:
        parser.error("--max-blocks-per-minute must be 1 or more")
    try:
        group_gid = grp.getgrnam(args.group).gr_gid
    except KeyError:
        parser.error(f"group {args.group} does not exist; create it with: sudo groupadd --system {args.group}")

    fw = FirewallManager(dry_run=args.dry_run, allowlist=args.allow, block_ttl=0)
    writer = FirewallWriter(fw, group_gid, max_per_minute=args.max_blocks_per_minute)
    sock = prepare_socket(args.socket, group_gid)
    # iptables-legacy needs CAP_NET_RAW to open its table
    drop_capabilities([CAP_NET_ADMIN, CAP_NET_RAW] if fw.backend == "iptables" else [CAP_NET_ADMIN])

    if fw.enforcing:
        def expire_loop():
            while True:
                try:
                    fw.expire_blocks()
                except Exception as e:
                    logger.error(f"Block expiry sweep failed: {e}")
                time.sleep(FirewallManager.EXPIRY_INTERVAL)

        threading.Thread(target=expire_loop, daemon=True, name="BlockExpiry").start()

    def stop(signum, frame):
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, stop)
    server = make_server(writer, sock)
    logger.info(f"Firewall writer listening on {args.socket}")
    try:
        server.serve_forever()
    finally:
        server.server_close()
        try:
            os.unlink(args.socket)
        except OSError:
            pass


if __name__ == "__main__":
    main()
