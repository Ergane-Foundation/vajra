#!/usr/bin/env python3
"""
SOAR Engine - Security Orchestration and Automated Response

Handles automated response to security threats including:
- IP blocking via iptables/nftables
- Alert processing and severity evaluation
- Report generation
- Action logging
"""

import json
import logging
import subprocess
import shutil
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger("soar_engine")


class FirewallManager:
    """Manages firewall rules for blocking IPs"""
    
    def __init__(self):
        self.backend = self._detect_backend()
        self.blocked_ips_file = Path("logs/blocked_ips.txt")
        self.blocked_ips = self._load_blocked_ips()
        logger.info(f"Firewall backend: {self.backend}")
    
    def _detect_backend(self) -> str:
        """Detect available firewall backend"""
        if shutil.which("nft"):
            return "nftables"
        elif shutil.which("iptables"):
            return "iptables"
        else:
            logger.warning("No firewall backend detected (nftables/iptables)")
            return "none"
    
    def _load_blocked_ips(self) -> set:
        """Load previously blocked IPs from file"""
        if self.blocked_ips_file.exists():
            content = self.blocked_ips_file.read_text().strip()
            return set(line for line in content.split('\n') if line)
        return set()
    
    def _save_blocked_ips(self):
        """Save blocked IPs to file"""
        self.blocked_ips_file.parent.mkdir(parents=True, exist_ok=True)
        self.blocked_ips_file.write_text('\n'.join(sorted(self.blocked_ips)))
    
    def block_ip(self, ip: str, reason: str = "Security threat") -> bool:
        """Block an IP address using firewall rules"""
        # Validate IP
        if not ip or ip in ("", "127.0.0.1", "::1", "localhost"):
            logger.warning(f"Invalid or localhost IP, skipping: {ip}")
            return False
        
        if ip in self.blocked_ips:
            logger.debug(f"IP {ip} already blocked")
            return True
        
        success = False
        
        try:
            if self.backend == "nftables":
                # nftables command
                cmd = ["nft", "add", "element", "inet", "filter", "blocked_ips", f"{{ {ip} }}"]
                result = subprocess.run(cmd, capture_output=True, timeout=5)
                success = result.returncode == 0
                
                if not success:
                    logger.error(f"nftables error: {result.stderr.decode()}")
                
            elif self.backend == "iptables":
                # iptables commands - block both INPUT and OUTPUT
                cmd_input = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP", 
                           "-m", "comment", "--comment", f"SOAR: {reason[:50]}"]
                cmd_output = ["iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"]
                
                r1 = subprocess.run(cmd_input, capture_output=True, timeout=5)
                r2 = subprocess.run(cmd_output, capture_output=True, timeout=5)
                success = r1.returncode == 0 and r2.returncode == 0
                
                if not success:
                    logger.error(f"iptables error: {r1.stderr.decode()}")
            
            else:
                # No firewall backend - simulation mode
                logger.warning(f"[SIMULATION] Would block {ip} - no firewall available")
                success = True
            
            if success:
                self.blocked_ips.add(ip)
                self._save_blocked_ips()
                logger.info(f"🛡️  BLOCKED IP: {ip} | Reason: {reason}")
            
        except Exception as e:
            logger.error(f"Error blocking IP {ip}: {e}")
            success = False
        
        return success
    
    def unblock_ip(self, ip: str) -> bool:
        """Unblock a previously blocked IP"""
        if ip not in self.blocked_ips:
            logger.warning(f"IP {ip} is not blocked")
            return True
        
        try:
            if self.backend == "nftables":
                cmd = ["nft", "delete", "element", "inet", "filter", "blocked_ips", f"{{ {ip} }}"]
                subprocess.run(cmd, capture_output=True, timeout=5)
            
            elif self.backend == "iptables":
                subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], 
                             capture_output=True, timeout=5)
                subprocess.run(["iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"], 
                             capture_output=True, timeout=5)
            
            self.blocked_ips.discard(ip)
            self._save_blocked_ips()
            logger.info(f"✅ Unblocked IP: {ip}")
            return True
            
        except Exception as e:
            logger.error(f"Error unblocking IP {ip}: {e}")
            return False
    
    def list_blocked_ips(self) -> List[str]:
        """Get list of all blocked IPs"""
        return sorted(self.blocked_ips)


class ReportGenerator:
    """Generates security reports for alerts and actions"""
    
    def __init__(self, reports_dir: str = "logs/reports"):
        self.reports_dir = Path(reports_dir)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.actions_log = Path("logs/soar_actions.json")
    
    def log_action(self, alert: Dict[str, Any], action: str, result: str):
        """Log a SOAR action"""
        action_record = {
            'timestamp': datetime.now().isoformat(),
            'alert_signature': alert.get('signature', 'Unknown'),
            'source_ip': alert.get('src_ip', 'Unknown'),
            'action': action,
            'result': result,
            'severity': alert.get('severity', 'MEDIUM')
        }
        
        # Append to actions log
        with open(self.actions_log, 'a') as f:
            f.write(json.dumps(action_record) + '\n')
        
        logger.info(f"📝 Action logged: {action} on {alert.get('src_ip')}")
    
    def generate_report(self, alert: Dict[str, Any], blocked: bool):
        """Generate detailed security report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        src_ip = alert.get('src_ip', 'unknown')
        report_file = self.reports_dir / f"report_{timestamp}_{src_ip.replace('.', '_')}.json"
        
        report = {
            'report_id': f"RPT-{timestamp}",
            'generated_at': datetime.now().isoformat(),
            'alert': alert,
            'action_taken': 'IP_BLOCKED' if blocked else 'NO_ACTION',
            'blocked': blocked,
            'analysis': {
                'attack_type': self._classify_attack(alert.get('signature', '')),
                'severity': alert.get('severity', 'MEDIUM'),
                'source_ip': src_ip,
                'destination': alert.get('dest_ip', 'Unknown'),
                'protocol': alert.get('proto', 'Unknown')
            },
            'recommendations': self._get_recommendations(alert)
        }
        
        report_file.write_text(json.dumps(report, indent=2))
        logger.info(f"📄 Report generated: {report_file.name}")
        
        return report
    
    def _classify_attack(self, signature: str) -> str:
        """Classify attack type from signature"""
        sig_lower = signature.lower()
        
        if "sql" in sig_lower or "injection" in sig_lower:
            return "SQL Injection"
        elif "xss" in sig_lower or "script" in sig_lower:
            return "Cross-Site Scripting (XSS)"
        elif "traversal" in sig_lower or "path" in sig_lower:
            return "Path Traversal"
        elif "scan" in sig_lower or "recon" in sig_lower:
            return "Port Scan / Reconnaissance"
        elif "ddos" in sig_lower or "flood" in sig_lower:
            return "DDoS Attack"
        elif "brute" in sig_lower:
            return "Brute Force Attack"
        else:
            return "General Threat"
    
    def _get_recommendations(self, alert: Dict[str, Any]) -> List[str]:
        """Get security recommendations based on attack type"""
        attack_type = self._classify_attack(alert.get('signature', ''))
        
        recommendations_map = {
            "SQL Injection": [
                "Review and sanitize all user inputs",
                "Use parameterized queries/prepared statements",
                "Implement Web Application Firewall (WAF)"
            ],
            "Cross-Site Scripting (XSS)": [
                "Encode all user-generated output",
                "Implement Content Security Policy (CSP)",
                "Use HTTPOnly and Secure flags on cookies"
            ],
            "Path Traversal": [
                "Validate and sanitize file paths",
                "Use whitelisting for allowed paths",
                "Implement proper access controls"
            ],
            "Port Scan / Reconnaissance": [
                "Review exposed services",
                "Implement rate limiting",
                "Monitor for follow-up attacks"
            ],
            "DDoS Attack": [
                "Enable rate limiting and traffic shaping",
                "Use DDoS protection service",
                "Scale infrastructure if needed"
            ],
            "Brute Force Attack": [
                "Implement account lockout policies",
                "Enable multi-factor authentication (MFA)",
                "Use CAPTCHA on login forms"
            ]
        }
        
        return recommendations_map.get(attack_type, [
            "Review security posture",
            "Monitor for additional suspicious activity",
            "Update security rules and signatures"
        ])


class SOAREngine:
    """Security Orchestration and Automated Response Engine
    
    Main engine for processing security alerts and executing automated responses.
    """
    
    def __init__(self, auto_block: bool = True, severity_threshold: str = "MEDIUM"):
        self.firewall = FirewallManager()
        self.reporter = ReportGenerator()
        self.auto_block = auto_block
        self.severity_threshold = severity_threshold
        self.alert_count = 0
        
        logger.info("SOAR Engine initialized")
        logger.info(f"  Auto-block: {auto_block}")
        logger.info(f"  Severity threshold: {severity_threshold}")
    
    def process_alert(self, alert: Dict[str, Any]) -> bool:
        """Process a security alert and take appropriate action"""
        self.alert_count += 1
        
        src_ip = alert.get('src_ip', 'Unknown')
        signature = alert.get('signature', 'Unknown threat')
        severity = alert.get('severity', 'MEDIUM')
        
        logger.info(f"🚨 Alert #{self.alert_count}: {signature}")
        logger.info(f"   Source: {src_ip} | Severity: {severity}")
        
        # Decide action based on severity
        should_block = self._should_block(severity)
        blocked = False
        
        if should_block and self.auto_block:
            blocked = self.firewall.block_ip(src_ip, reason=signature)
            action = "IP_BLOCKED" if blocked else "BLOCK_FAILED"
        else:
            action = "LOGGED_ONLY"
            logger.info(f"   Action: Alert logged (severity below threshold)")
        
        # Log action
        result = "success" if blocked or not should_block else "failed"
        self.reporter.log_action(alert, action, result)
        
        # Generate report for high severity
        if severity in ["HIGH", "CRITICAL"] or blocked:
            self.reporter.generate_report(alert, blocked)
        
        return blocked
    
    def _should_block(self, severity: str) -> bool:
        """Determine if an IP should be blocked based on severity"""
        severity_levels = {
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3,
            "CRITICAL": 4
        }
        
        threshold_level = severity_levels.get(self.severity_threshold, 2)
        alert_level = severity_levels.get(severity, 1)
        
        return alert_level >= threshold_level
    
    def block_ip(self, ip: str, reason: str = "Manual block") -> bool:
        """Manually block an IP address"""
        return self.firewall.block_ip(ip, reason)
    
    def unblock_ip(self, ip: str) -> bool:
        """Manually unblock an IP address"""
        return self.firewall.unblock_ip(ip)
    
    def get_blocked_ips(self) -> List[str]:
        """Get list of all blocked IPs"""
        return self.firewall.list_blocked_ips()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get SOAR engine statistics"""
        return {
            'alerts_processed': self.alert_count,
            'blocked_ips_count': len(self.firewall.blocked_ips),
            'auto_block_enabled': self.auto_block,
            'severity_threshold': self.severity_threshold
        }


def main():
    """Main entry point for testing"""
    # Create SOAR engine
    soar = SOAREngine(auto_block=True, severity_threshold="MEDIUM")
    
    # Test with sample alerts
    test_alerts = [
        {
            'src_ip': '192.168.1.100',
            'dest_ip': '10.0.0.1',
            'signature': 'Potential SQL Injection attempt',
            'severity': 'HIGH',
            'proto': 'TCP'
        },
        {
            'src_ip': '192.168.1.101',
            'dest_ip': '10.0.0.1',
            'signature': 'Port scan detected',
            'severity': 'MEDIUM',
            'proto': 'TCP'
        },
        {
            'src_ip': '192.168.1.102',
            'dest_ip': '10.0.0.1',
            'signature': 'Suspicious DNS query',
            'severity': 'LOW',
            'proto': 'UDP'
        }
    ]
    
    logger.info("Processing test alerts...")
    for alert in test_alerts:
        soar.process_alert(alert)
        print()
    
    # Print stats
    stats = soar.get_stats()
    logger.info(f"\n📊 SOAR Statistics:")
    logger.info(f"   Alerts processed: {stats['alerts_processed']}")
    logger.info(f"   IPs blocked: {stats['blocked_ips_count']}")
    logger.info(f"   Blocked IPs: {', '.join(soar.get_blocked_ips())}")


if __name__ == "__main__":
    main()
