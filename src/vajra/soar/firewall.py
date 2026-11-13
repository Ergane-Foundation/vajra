"""Applies and removes IP blocks with nftables or iptables"""

import ipaddress
import json
import logging
import math
import shutil
import subprocess
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional

from vajra.common.network import build_allowlist

logger = logging.getLogger("soar_engine.firewall")


class FirewallManager:
    """Manages iptables/nftables for blocking IPs"""

    NFT_RULESET = """table inet vajra
delete table inet vajra
table inet vajra {
    set blocked_ips {
        type ipv4_addr
        flags timeout
    }
    set blocked_ips6 {
        type ipv6_addr
        flags timeout
    }
    chain input {
        type filter hook input priority filter - 1; policy accept;
        ip saddr @blocked_ips drop
        ip6 saddr @blocked_ips6 drop
    }
    chain output {
        type filter hook output priority filter - 1; policy accept;
        ip daddr @blocked_ips drop
        ip6 daddr @blocked_ips6 drop
    }
}
"""
    IPTABLES_CHAIN = "VAJRA-BLOCK"
    EXPIRY_INTERVAL = 5
    ALREADY_GONE_ERRORS = (
        "No such file or directory",
        "does a matching rule exist",
        "No chain/target/match by that name",
    )
    
    def __init__(self, dry_run: bool = False, allowlist: Optional[List[str]] = None, block_ttl: int = 0):
        self.dry_run = dry_run
        self.backend = self._detect_backend()
        self.allowlist = build_allowlist(allowlist, logger)
        self.blocked_ips_file = Path("logs/blocked_ips.txt")
        self.blocked_ips = self._load_blocked_ips()
        self.unrestored_ips = set()
        self.block_ttl = block_ttl
        self.block_expiry_file = Path("logs/block_expiry.json")
        self.block_expiry = self._load_block_expiry()
        self._lock = threading.RLock()
        if self.enforcing and self.backend == "nftables":
            self._setup_nftables()
        elif self.enforcing and self.backend == "iptables":
            self._setup_iptables()
        logger.info(f"Firewall backend: {self.backend}" + (" (dry run)" if dry_run else ""))
        logger.info(f"Block TTL: {block_ttl}s" if block_ttl else "Block TTL: permanent")
        logger.info(f"Allowlist: {', '.join(str(n) for n in self.allowlist)}")

    @property
    def enforcing(self) -> bool:
        """True when blocks are actually applied to the host firewall"""
        return not self.dry_run and self.backend != "none"

    def _nft_set(self, ip: str) -> str:
        """Choose the nftables set for an IP address"""
        return "blocked_ips6" if ipaddress.ip_address(ip).version == 6 else "blocked_ips"

    def _iptables(self, ip: str) -> str:
        """Choose iptables or ip6tables for an IP address"""
        return "ip6tables" if ipaddress.ip_address(ip).version == 6 else "iptables"

    def _setup_nftables(self):
        """Create the nftables rules and restore saved blocks"""
        error = None
        try:
            result = subprocess.run(["nft", "-f", "-"], input=self.NFT_RULESET, capture_output=True, text=True, timeout=5)
            if result.returncode != 0:
                error = result.stderr.strip()
        except (OSError, subprocess.SubprocessError) as e:
            error = str(e)
        if error is not None:
            # Without the table no block can be applied, so saved blocks must not count as active
            logger.error(f"Could not set up nftables, blocks will not be enforced: {error}")
            self.backend = "none"
            self.blocked_ips = set()
            return

        # Recreating the table empties the sets, so re-apply saved blocks
        self._restore_saved_blocks()

    def _setup_iptables(self):
        """Create the VAJRA-BLOCK chain ahead of the NFQUEUE rules and restore saved blocks"""
        chain = self.IPTABLES_CHAIN
        for tool in ("iptables", "ip6tables"):
            error = None
            try:
                # -N fails if the chain exists and -D if there is no jump yet; both are fine
                for args in (["-N", chain], ["-D", "INPUT", "-j", chain], ["-D", "OUTPUT", "-j", chain]):
                    subprocess.run([tool, *args], capture_output=True, timeout=5)
                # start.sh inserts NFQUEUE at the top, so the jump goes back above it on every start
                for args in (["-F", chain], ["-I", "INPUT", "1", "-j", chain], ["-I", "OUTPUT", "1", "-j", chain]):
                    result = subprocess.run([tool, *args], capture_output=True, text=True, timeout=5)
                    if result.returncode != 0:
                        error = result.stderr.strip()
                        break
            except (OSError, subprocess.SubprocessError) as e:
                error = str(e)
            if error is None:
                continue
            if tool == "ip6tables":
                logger.warning(f"Could not set up the ip6tables {chain} chain, IPv6 blocks will fail: {error}")
                continue
            logger.error(f"Could not set up the iptables {chain} chain, blocks will not be enforced: {error}")
            self.backend = "none"
            self.blocked_ips = set()
            return
        # Flushing the chain removed the old blocks, so re-apply saved ones
        self._restore_saved_blocks()

    def _restore_saved_blocks(self):
        """Re-apply saved blocks after the firewall rules were recreated"""
        saved_ips = self.blocked_ips
        saved_expiry = self.block_expiry
        self.blocked_ips = set()
        self.block_expiry = {}
        for ip in saved_ips:
            exp = saved_expiry.get(ip)
            if exp is not None and exp <= time.time():
                # Already expired while stopped; the first sweep unblocks and records it
                self.blocked_ips.add(ip)
                self.block_expiry[ip] = exp
                continue
            self.block_ip(ip, "Restored saved block", expires_at=exp)
        # Keep blocks that could not be re-applied so the next start retries them
        self.unrestored_ips = {ip for ip in saved_ips - self.blocked_ips if ip and not self.is_allowlisted(ip)}
        self.block_expiry.update({ip: saved_expiry[ip] for ip in self.unrestored_ips if ip in saved_expiry})
        if self.unrestored_ips:
            logger.warning(f"Could not restore {len(self.unrestored_ips)} saved blocks, keeping them in {self.blocked_ips_file}")
        self._save_blocked_ips()
        logger.info(f"Restored {len(self.blocked_ips)} {self.backend} blocks")

    def is_allowlisted(self, ip: str) -> bool:
        """Check whether an IP falls inside the allowlist"""
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(address.version == n.version and address in n for n in self.allowlist)
    
    def _detect_backend(self) -> str:
        """Detect available firewall backend"""
        if shutil.which("nft"):
            return "nftables"
        elif shutil.which("iptables"):
            return "iptables"
        else:
            return "none"
    
    def _load_blocked_ips(self) -> set:
        """Load previously blocked IPs"""
        if self.blocked_ips_file.exists():
            return set(self.blocked_ips_file.read_text().strip().split('\n'))
        return set()

    def _load_block_expiry(self) -> Dict[str, float]:
        """Load the expiry time of each timed block"""
        if not self.block_expiry_file.exists():
            return {}
        try:
            return {ip: float(t) for ip, t in json.loads(self.block_expiry_file.read_text()).items()}
        except (ValueError, TypeError, AttributeError, OSError) as e:
            logger.warning(f"Could not read {self.block_expiry_file}, saved blocks get a new expiry: {e}")
            return {}
    
    def _save_blocked_ips(self):
        """Save blocked IPs to file"""
        # Serialize firewall changes, expiry state and persistence across alert and sweep threads
        with self._lock:
            self.blocked_ips_file.parent.mkdir(parents=True, exist_ok=True)
            self.blocked_ips_file.write_text('\n'.join(self.blocked_ips | self.unrestored_ips))
            self.block_expiry_file.write_text(json.dumps(dict(self.block_expiry)))
    
    def block_ip(self, ip: str, reason: str = "", expires_at: Optional[float] = None) -> bool:
        """Block an IP address"""
        if not ip:
            return False

        if self.is_allowlisted(ip):
            logger.warning(f"Not blocking allowlisted IP {ip} | Reason: {reason}")
            return False
        
        with self._lock:
            if ip in self.blocked_ips:
                logger.debug(f"IP {ip} already blocked")
                return True

            if not self.enforcing:
                logger.warning(f"Would block {ip} (not enforced: {'dry run' if self.dry_run else 'no firewall backend'}) | Reason: {reason}")
                return False

            if expires_at is None and self.block_ttl > 0:
                expires_at = time.time() + self.block_ttl
            
            success = False
            
            try:
                if self.backend == "nftables":
                    # nftables
                    element = ip
                    if expires_at is not None:
                        # The sweep removes it on time; the kernel timeout is a backstop while the engine is stopped
                        element += f" timeout {max(1, math.ceil(expires_at - time.time())) + self.EXPIRY_INTERVAL + 1}s"
                    cmd = ["nft", "add", "element", "inet", "vajra", self._nft_set(ip), f"{{ {element} }}"]
                    result = subprocess.run(cmd, capture_output=True, timeout=5)
                    success = result.returncode == 0
                    
                elif self.backend == "iptables":
                    # VAJRA-BLOCK is jumped to from INPUT and OUTPUT ahead of the NFQUEUE rules
                    tool = self._iptables(ip)
                    cmd1 = [tool, "-A", self.IPTABLES_CHAIN, "-s", ip, "-j", "DROP"]
                    cmd2 = [tool, "-A", self.IPTABLES_CHAIN, "-d", ip, "-j", "DROP"]
                    
                    r1 = subprocess.run(cmd1, capture_output=True, timeout=5)
                    r2 = subprocess.run(cmd2, capture_output=True, timeout=5)
                    success = r1.returncode == 0 or r2.returncode == 0

                if success:
                    self.blocked_ips.add(ip)
                    if expires_at is not None:
                        self.block_expiry[ip] = expires_at
                    else:
                        self.block_expiry.pop(ip, None)
                    self.unrestored_ips.discard(ip)
                    self._save_blocked_ips()
                    logger.info(f"BLOCKED IP: {ip} | Reason: {reason}")
                else:
                    logger.error(f"Failed to block IP: {ip}")
                    
            except Exception as e:
                logger.error(f"Error blocking IP {ip}: {e}")
                success = False
            
            return success
    
    def unblock_ip(self, ip: str) -> bool:
        """Unblock an IP address"""
        with self._lock:
            if ip not in self.blocked_ips:
                return True
            
            try:
                results = []
                if self.backend == "nftables":
                    cmd = ["nft", "delete", "element", "inet", "vajra", self._nft_set(ip), f"{{ {ip} }}"]
                    results.append(subprocess.run(cmd, capture_output=True, text=True, timeout=5))
                elif self.backend == "iptables":
                    tool = self._iptables(ip)
                    results.append(subprocess.run([tool, "-D", self.IPTABLES_CHAIN, "-s", ip, "-j", "DROP"], capture_output=True, text=True, timeout=5))
                    results.append(subprocess.run([tool, "-D", self.IPTABLES_CHAIN, "-d", ip, "-j", "DROP"], capture_output=True, text=True, timeout=5))
                # Only a missing rule, element or table counts as already gone, e.g. a block that expired while stopped
                if any(
                    r.returncode != 0 and not any(text in r.stderr for text in self.ALREADY_GONE_ERRORS)
                    for r in results
                ):
                    logger.error(f"Failed to unblock IP: {ip}")
                    return False
                
                self.blocked_ips.discard(ip)
                self.block_expiry.pop(ip, None)
                self._save_blocked_ips()
                logger.info(f"Unblocked IP: {ip}")
                return True
                
            except Exception as e:
                logger.error(f"Error unblocking IP {ip}: {e}")
                return False

    def expire_blocks(self, now: Optional[float] = None) -> List[str]:
        """Remove blocks whose expiry has passed and return their IPs"""
        with self._lock:
            now = time.time() if now is None else now
            expired = []
            for ip, exp in list(self.block_expiry.items()):
                if exp > now:
                    continue
                if ip in self.unrestored_ips:
                    self.unrestored_ips.discard(ip)
                    self.block_expiry.pop(ip, None)
                    expired.append(ip)
                elif self.unblock_ip(ip):
                    expired.append(ip)
            if expired:
                self._save_blocked_ips()
                for ip in expired:
                    logger.info(f"Block expired for {ip}")
            return expired
