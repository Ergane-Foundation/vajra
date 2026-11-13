"""Engine-side client for the firewall writer, with the same interface as FirewallManager"""

import ipaddress
import json
import logging
import math
import socket
import time
from typing import Any, Dict, List, Optional

from vajra.common.network import build_allowlist
from vajra.soar.firewall import FirewallManager

# Shared with writer.py; kept here so importing the client never sets up the writer's log file
PROTOCOL_VERSION = 1
DEFAULT_SOCKET = "/run/vajra/writer.sock"
MAX_TTL = 31536000
MAX_REASON = 200

MAX_RESPONSE_BYTES = 16 * 1024 * 1024
CONNECT_ATTEMPTS = 10

logger = logging.getLogger("soar_engine.firewall")


def parse_address(text: Any) -> Optional[str]:
    """Return the canonical form of an IP address, folding IPv4-mapped IPv6, or None"""
    if not isinstance(text, str) or "%" in text:
        return None
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return None
    if address.version == 6 and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return str(address)


class WriterClient:
    """Sends block requests to the firewall writer over its unix socket"""

    EXPIRY_INTERVAL = FirewallManager.EXPIRY_INTERVAL

    def __init__(self, socket_path: str, allowlist: Optional[List[str]] = None, block_ttl: int = 0):
        self.socket_path = socket_path
        self.block_ttl = block_ttl
        # Used for policy decisions only; the writer enforces the real protected set
        self.allowlist = build_allowlist(allowlist, logger)
        self.protected = set()
        self.block_expiry: Dict[str, float] = {}
        self._enforcing = True
        self.backend = "writer (unreachable)"
        resp = None
        for attempt in range(CONNECT_ATTEMPTS):
            resp = self._request({"op": "list"})
            if resp and resp.get("ok"):
                break
            if attempt < CONNECT_ATTEMPTS - 1:
                time.sleep(1)
        if resp and resp.get("ok"):
            self._enforcing = bool(resp.get("enforcing"))
            self.backend = f"writer ({resp.get('backend')})"
        else:
            logger.error(f"Firewall writer not reachable at {socket_path}; blocks will fail until it starts")
        logger.info(f"Firewall backend: {self.backend}")
        logger.info(f"Block TTL: {block_ttl}s" if block_ttl else "Block TTL: permanent")
        logger.info(f"Allowlist: {', '.join(str(n) for n in self.allowlist)}")

    @property
    def enforcing(self) -> bool:
        """True when the writer applies blocks to the host firewall"""
        return self._enforcing

    def _request(self, payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Send one request on a new connection and return the parsed response"""
        message = dict(payload, v=PROTOCOL_VERSION)
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(5)
                sock.connect(self.socket_path)
                sock.sendall(json.dumps(message).encode("utf-8") + b"\n")
                data = b""
                while not data.endswith(b"\n") and len(data) < MAX_RESPONSE_BYTES:
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    data += chunk
            return json.loads(data.decode("utf-8"))
        except (OSError, ValueError) as e:
            logger.error(f"Firewall writer request failed: {e}")
            return None

    def is_allowlisted(self, ip: str) -> bool:
        """Check whether an IP falls inside the allowlist or was refused as protected"""
        if ip in self.protected:
            return True
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(address.version == n.version and address in n for n in self.allowlist)

    def block_ip(self, ip: str, reason: str = "", expires_at: Optional[float] = None) -> bool:
        """Ask the writer to block an IP address"""
        if not ip:
            return False
        if self.is_allowlisted(ip):
            logger.warning(f"Not blocking allowlisted IP {ip} | Reason: {reason}")
            return False
        ttl = max(1, math.ceil(expires_at - time.time())) if expires_at else self.block_ttl
        ttl = min(ttl, MAX_TTL)
        resp = self._request({"op": "block", "ip": ip, "ttl": ttl, "reason": reason[:MAX_REASON]})
        if resp is None:
            return False
        if resp.get("ok"):
            key = parse_address(ip) or ip
            expiry = resp.get("expires_at")
            if expiry is not None:
                self.block_expiry[key] = float(expiry)
            else:
                self.block_expiry.pop(key, None)
            logger.info(f"BLOCKED IP: {ip} | Reason: {reason}")
            return True
        error = resp.get("error")
        if error == "protected":
            self.protected.add(ip)
            logger.warning(f"Not blocking protected IP {ip} | Reason: {reason}")
        elif error == "not_enforced":
            logger.warning(f"Would block {ip} (not enforced: writer in dry run or without a firewall backend) | Reason: {reason}")
        else:
            logger.error(f"Writer refused to block {ip}: {error}")
        return False

    def expire_blocks(self, now: Optional[float] = None) -> List[str]:
        """Return the IPs whose blocks the writer has removed"""
        if not self.block_expiry:
            return []
        tracked = list(self.block_expiry)
        resp = self._request({"op": "list"})
        if not resp or not resp.get("ok"):
            return []
        active = {entry.get("ip") for entry in resp.get("blocks", [])}
        expired = [ip for ip in tracked if ip not in active]
        for ip in expired:
            self.block_expiry.pop(ip, None)
            logger.info(f"Block expired for {ip}")
        return expired
