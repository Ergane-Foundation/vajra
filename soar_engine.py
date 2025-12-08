#!/usr/bin/env python3
"""
SOAR Engine - Security Orchestration and Automated Response

Handles automated response to security threats including:
- IP blocking via iptables/nftables
- Alert processing and severity evaluation
- Report generation
- Action logging
- AI-powered dynamic rule generation using Google Gemini

Features:
- Automated IP blocking
- Threat severity evaluation
- Security report generation
- Gemini AI-based Suricata rule generation
- Rule validation and deployment
- Comprehensive audit logging
"""

import json
import logging
import subprocess
import shutil
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum

try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger("soar_engine")


# ============================================================================
# Configuration
# ============================================================================

# Suricata paths
SURICATA_RULES_PATH = Path("rules/local.rules")
SURICATA_BINARY = Path("/usr/bin/suricata")

# Gemini configuration
GEMINI_MODEL_NAME = "gemini-2.0-flash-exp"
RULE_SID_START = 1000001

# Audit paths
RULES_AUDIT_LOG = Path("logs/rules_audit.json")
RULES_STATE_FILE = Path("logs/rules_state.json")


# ============================================================================
# Data Classes & Enums
# ============================================================================

class ThreatSeverity(Enum):
    """Threat severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class RuleAction(Enum):
    """Suricata rule actions"""
    DROP = "drop"
    REJECT = "reject"
    ALERT = "alert"
    PASS = "pass"


@dataclass
class ThreatContext:
    """Input context for AI rule generation"""
    severity: ThreatSeverity
    threat_type: str  # e.g., "SQL_INJECTION", "XSS", "DDoS"
    payload: str  # Raw threat payload or description
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None
    protocol: str = "tcp"
    additional_context: Optional[str] = None

    def to_prompt(self) -> str:
        """Convert threat context to AI prompt"""
        return f"""
Generate a Suricata 6.0+ IDS rule for defensive network security purposes.

THREAT INFORMATION:
Type: {self.threat_type}
Severity: {self.severity.value.upper()}
Protocol: {self.protocol.upper()}

NETWORK ACTIVITY DETAILS:
{self.payload}

{f'Source IP: {self.source_ip}' if self.source_ip else ''}
{f'Destination IP: {self.dest_ip}' if self.dest_ip else ''}
{f'Destination Port: {self.dest_port}' if self.dest_port else ''}
{f'Additional Context: {self.additional_context}' if self.additional_context else ''}

RULE REQUIREMENTS:
1. Action: 'drop' or 'alert'
2. SID >= {RULE_SID_START}
3. Fields: msg, classtype, rev, metadata
4. Match patterns specific to this threat
5. Use appropriate content matching and flow analysis

OUTPUT INSTRUCTIONS:
Provide only the Suricata rule, no explanations or code blocks.
"""


@dataclass
class GeneratedRule:
    """Generated Suricata rule metadata"""
    rule_text: str
    sid: int
    msg: str
    classtype: str
    action: str
    threat_severity: ThreatSeverity
    timestamp: str
    generated_by_ai: bool = True
    validated: bool = False
    deployed: bool = False


@dataclass
class AuditEntry:
    """Rule deployment audit trail"""
    timestamp: str
    action: str  # "generated", "validated", "deployed"
    rule_sid: int
    rule_msg: str
    status: str  # "success", "failed"
    error_message: Optional[str] = None
    operator: str = "ai_system"


# ============================================================================
# AI Rule Generator
# ============================================================================

class AIRuleGenerator:
    """Generates Suricata rules using Google Gemini AI"""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("GOOGLE_API_KEY")

        if not self.api_key:
            logger.warning(
                "GOOGLE_API_KEY not found. AI rule generation will be disabled. "
                "Set it via: export GOOGLE_API_KEY='your-api-key'"
            )
            self.model = None
            self.next_sid = RULE_SID_START
            return

        if not GEMINI_AVAILABLE:
            logger.warning(
                "google-generativeai not installed. "
                "Install with: pip install google-generativeai"
            )
            self.model = None
            self.next_sid = RULE_SID_START
            return

        try:
            genai.configure(api_key=self.api_key)
            self.model = genai.GenerativeModel(GEMINI_MODEL_NAME)
            logger.info(f"✓ Gemini AI configured: {GEMINI_MODEL_NAME}")
        except Exception as e:
            logger.error(f"Gemini initialization failed: {e}")
            self.model = None

        self.next_sid = self._get_next_sid()

    def generate(self, threat: ThreatContext) -> Optional[GeneratedRule]:
        """
        Generate a Suricata rule from threat context

        Args:
            threat: ThreatContext with threat details

        Returns:
            GeneratedRule object or None if generation failed
        """
        if not self.model:
            logger.warning("Gemini AI not available, using fallback rule generation")
            return self._generate_fallback_rule(threat)

        prompt = threat.to_prompt()

        logger.info(f"Generating AI rule for threat: {threat.threat_type}")

        try:
            response = self.model.generate_content(
                prompt,
                generation_config={
                    "temperature": 0.2,  # Low randomness for security-critical output
                    "top_p": 0.9,
                    "top_k": 40,
                    "max_output_tokens": 500,
                }
            )

            # Check if response was blocked or empty
            if not response.text or response.text.strip() == "":
                logger.warning(f"AI response empty, using fallback rule for {threat.threat_type}")
                return self._generate_fallback_rule(threat)

            rule_text = response.text.strip()

            # Clean up markdown if present
            rule_text = rule_text.replace("```suricata", "").replace("```", "").strip()

            if not rule_text:
                logger.error("AI returned empty rule")
                return self._generate_fallback_rule(threat)

            # Parse rule to extract metadata
            rule_obj = self._parse_rule(rule_text, threat.severity)

            if not rule_obj:
                logger.error("Failed to parse generated rule")
                return self._generate_fallback_rule(threat)

            logger.info(f"✓ AI rule generated: SID {rule_obj.sid} - {rule_obj.msg}")
            return rule_obj

        except Exception as e:
            logger.error(f"AI rule generation failed: {e}")
            return self._generate_fallback_rule(threat)

    def _generate_fallback_rule(self, threat: ThreatContext) -> GeneratedRule:
        """Generate a basic fallback rule when AI fails"""
        sid = self.next_sid
        self.next_sid += 1

        # Create a basic rule based on threat type
        threat_type_to_pattern = {
            "SQL_INJECTION": "content:\"'\"; http_uri; content:\"OR\"; http_uri;",
            "XSS": "content:\"<script\"; http_uri;",
            "PATH_TRAVERSAL": "content:\"../\"; http_uri;",
            "DDOS": "flags:S; threshold:type both,track by_src,count 100,seconds 10;",
            "PORT_SCAN": "flags:S; threshold:type both,track by_src,count 50,seconds 5;",
        }

        pattern = threat_type_to_pattern.get(threat.threat_type, "content:\"suspicious\";")
        action = "drop" if threat.severity in [ThreatSeverity.CRITICAL, ThreatSeverity.HIGH] else "alert"

        rule_text = f'{action} tcp any any -> any any (msg:"{threat.threat_type} Detected (Fallback)"; {pattern} classtype:attempted-admin; sid:{sid}; rev:1;)'

        return GeneratedRule(
            rule_text=rule_text,
            sid=sid,
            msg=f"{threat.threat_type} Detected (Fallback)",
            classtype="attempted-admin",
            action=action,
            threat_severity=threat.severity,
            timestamp=datetime.now().isoformat(),
            generated_by_ai=False,
            validated=False
        )

    def _parse_rule(self, rule_text: str, severity: ThreatSeverity) -> Optional[GeneratedRule]:
        """Parse rule text and extract metadata"""
        try:
            # Extract action
            action = None
            for act in [act.value for act in RuleAction]:
                if rule_text.startswith(act):
                    action = act
                    break

            if not action:
                logger.error("Rule does not start with a valid action")
                return None

            # Extract SID
            sid = None
            for token in rule_text.split():
                if token.startswith("sid:"):
                    try:
                        sid = int(token.split(":")[1].rstrip(";"))
                        break
                    except (ValueError, IndexError):
                        pass

            if not sid:
                sid = self.next_sid
                self.next_sid += 1

            # Extract msg
            msg = ""
            if 'msg:"' in rule_text:
                start = rule_text.find('msg:"') + 5
                end = rule_text.find('"', start)
                msg = rule_text[start:end] if end > start else "AI Generated Rule"

            # Extract classtype
            classtype = "unknown"
            if "classtype:" in rule_text:
                start = rule_text.find("classtype:") + 10
                end = rule_text.find(";", start)
                classtype = rule_text[start:end].strip() if end > start else "unknown"

            return GeneratedRule(
                rule_text=rule_text,
                sid=sid,
                msg=msg,
                classtype=classtype,
                action=action,
                threat_severity=severity,
                timestamp=datetime.now().isoformat(),
                generated_by_ai=True,
                validated=False
            )

        except Exception as e:
            logger.error(f"Rule parsing failed: {e}")
            return None

    @staticmethod
    def _get_next_sid() -> int:
        """Get next available SID"""
        try:
            if RULES_STATE_FILE.exists():
                state = json.loads(RULES_STATE_FILE.read_text())
                return state.get("next_sid", RULE_SID_START)
        except Exception:
            pass
        return RULE_SID_START

    def _save_state(self):
        """Save current state (next_sid) to file"""
        try:
            RULES_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
            state = {"next_sid": self.next_sid, "last_update": datetime.now().isoformat()}
            RULES_STATE_FILE.write_text(json.dumps(state, indent=2))
        except Exception as e:
            logger.error(f"Failed to save state: {e}")


# ============================================================================
# Firewall Manager
# ============================================================================

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
    
    Features:
    - Automated IP blocking based on severity
    - AI-powered Suricata rule generation using Gemini
    - Security report generation
    - Comprehensive audit logging
    """
    
    def __init__(self, auto_block: bool = True, severity_threshold: str = "MEDIUM", 
                 enable_ai_rules: bool = False):
        self.firewall = FirewallManager()
        self.reporter = ReportGenerator()
        self.auto_block = auto_block
        self.severity_threshold = severity_threshold
        self.enable_ai_rules = enable_ai_rules
        self.alert_count = 0
        
        # Initialize AI rule generator if enabled
        self.ai_generator = None
        if enable_ai_rules:
            try:
                self.ai_generator = AIRuleGenerator()
                logger.info("✓ AI rule generation enabled")
            except Exception as e:
                logger.warning(f"AI rule generation disabled: {e}")
        
        logger.info("SOAR Engine initialized")
        logger.info(f"  Auto-block: {auto_block}")
        logger.info(f"  Severity threshold: {severity_threshold}")
        logger.info(f"  AI rule generation: {enable_ai_rules}")
    
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
        
        # Generate AI rule for HIGH/CRITICAL threats
        if self.enable_ai_rules and severity in ["HIGH", "CRITICAL"]:
            self._generate_dynamic_rule(alert)
        
        # Log action
        result = "success" if blocked or not should_block else "failed"
        self.reporter.log_action(alert, action, result)
        
        # Generate report for high severity
        if severity in ["HIGH", "CRITICAL"] or blocked:
            self.reporter.generate_report(alert, blocked)
        
        return blocked
    
    def _generate_dynamic_rule(self, alert: Dict[str, Any]):
        """Generate dynamic Suricata rule using AI"""
        if not self.ai_generator:
            logger.debug("AI generator not available")
            return
        
        try:
            # Extract threat information
            signature = alert.get('signature', 'Unknown threat')
            severity_str = alert.get('severity', 'MEDIUM')
            
            # Map string severity to enum
            severity_map = {
                'CRITICAL': ThreatSeverity.CRITICAL,
                'HIGH': ThreatSeverity.HIGH,
                'MEDIUM': ThreatSeverity.MEDIUM,
                'LOW': ThreatSeverity.LOW
            }
            severity = severity_map.get(severity_str, ThreatSeverity.MEDIUM)
            
            # Classify attack type from signature
            threat_type = self._classify_threat_type(signature)
            
            # Create threat context
            threat = ThreatContext(
                severity=severity,
                threat_type=threat_type,
                payload=signature,
                source_ip=alert.get('src_ip'),
                dest_ip=alert.get('dest_ip'),
                dest_port=alert.get('dest_port'),
                protocol=alert.get('proto', 'tcp').lower(),
                additional_context=f"Detected by Suricata at {datetime.now().isoformat()}"
            )
            
            # Generate rule
            logger.info(f"🤖 Generating AI rule for: {threat_type}")
            rule = self.ai_generator.generate(threat)
            
            if rule:
                # Deploy rule
                success = self._deploy_rule(rule)
                if success:
                    logger.info(f"✓ AI rule deployed: SID {rule.sid}")
                    self._log_rule_audit("deployed", rule, "success")
                else:
                    logger.warning(f"Failed to deploy AI rule: SID {rule.sid}")
                    self._log_rule_audit("deployed", rule, "failed", "Deployment failed")
            
        except Exception as e:
            logger.error(f"Error generating AI rule: {e}")
    
    def _classify_threat_type(self, signature: str) -> str:
        """Classify threat type from signature"""
        sig_lower = signature.lower()
        
        if "sql" in sig_lower or "injection" in sig_lower:
            return "SQL_INJECTION"
        elif "xss" in sig_lower or "script" in sig_lower:
            return "XSS"
        elif "traversal" in sig_lower or "path" in sig_lower:
            return "PATH_TRAVERSAL"
        elif "ddos" in sig_lower or "flood" in sig_lower:
            return "DDOS"
        elif "scan" in sig_lower or "recon" in sig_lower:
            return "PORT_SCAN"
        elif "brute" in sig_lower:
            return "BRUTE_FORCE"
        else:
            return "GENERAL_THREAT"
    
    def _deploy_rule(self, rule: GeneratedRule) -> bool:
        """Deploy generated rule to Suricata rules file"""
        try:
            # Check if rules file exists
            if not SURICATA_RULES_PATH.exists():
                logger.warning(f"Rules file not found: {SURICATA_RULES_PATH}")
                logger.info("Creating rules file...")
                SURICATA_RULES_PATH.parent.mkdir(parents=True, exist_ok=True)
                SURICATA_RULES_PATH.touch()
            
            # Append rule to local.rules
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            rule_entry = f"\n# AI-generated rule on {timestamp}\n# Threat Severity: {rule.threat_severity.value}\n{rule.rule_text}\n"
            
            with open(SURICATA_RULES_PATH, "a") as f:
                f.write(rule_entry)
            
            logger.info(f"Rule appended to {SURICATA_RULES_PATH}")
            
            # Try to reload Suricata rules (non-blocking)
            self._reload_suricata_rules()
            
            return True
            
        except Exception as e:
            logger.error(f"Rule deployment failed: {e}")
            return False
    
    @staticmethod
    def _reload_suricata_rules() -> bool:
        """Reload Suricata rules (best effort, non-blocking)"""
        if not SURICATA_BINARY.exists():
            logger.debug("Suricata binary not found - skipping reload (development mode)")
            return True
        
        try:
            # Try suricatasc first (zero-downtime reload)
            result = subprocess.run(
                ["suricatasc", "-c", "reload-rules"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                logger.info("✓ Suricata rules reloaded")
                return True
            else:
                logger.debug("suricatasc reload failed (may not be running)")
                
        except Exception as e:
            logger.debug(f"Could not reload Suricata rules: {e}")
        
        return False
    
    def _log_rule_audit(self, action: str, rule: GeneratedRule, status: str, 
                       error_message: Optional[str] = None):
        """Log rule action to audit trail"""
        try:
            RULES_AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
            
            entry = AuditEntry(
                timestamp=datetime.now().isoformat(),
                action=action,
                rule_sid=rule.sid,
                rule_msg=rule.msg,
                status=status,
                error_message=error_message
            )
            
            # Read existing audit log
            audit_entries = []
            if RULES_AUDIT_LOG.exists():
                try:
                    audit_entries = json.loads(RULES_AUDIT_LOG.read_text())
                except Exception:
                    pass
            
            # Append new entry
            audit_entries.append(asdict(entry))
            
            # Write back
            RULES_AUDIT_LOG.write_text(json.dumps(audit_entries, indent=2))
            
        except Exception as e:
            logger.error(f"Failed to log audit entry: {e}")
    
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
        stats = {
            'alerts_processed': self.alert_count,
            'blocked_ips_count': len(self.firewall.blocked_ips),
            'auto_block_enabled': self.auto_block,
            'severity_threshold': self.severity_threshold,
            'ai_rules_enabled': self.enable_ai_rules
        }
        
        # Add AI rule stats if enabled
        if self.ai_generator:
            stats['ai_generator_available'] = True
        
        return stats


def main():
    """Main entry point for testing"""
    # Create SOAR engine with AI rule generation
    soar = SOAREngine(
        auto_block=True, 
        severity_threshold="MEDIUM",
        enable_ai_rules=True  # Enable AI rule generation
    )
    
    # Test with sample alerts
    test_alerts = [
        {
            'src_ip': '192.168.1.100',
            'dest_ip': '10.0.0.1',
            'signature': 'Potential SQL Injection attempt',
            'severity': 'HIGH',
            'proto': 'TCP',
            'dest_port': 80
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
            'signature': 'XSS attack attempt detected',
            'severity': 'CRITICAL',
            'proto': 'TCP',
            'dest_port': 443
        }
    ]
    
    logger.info("="*60)
    logger.info("VAJRA SOAR Engine - Testing with AI Rule Generation")
    logger.info("="*60)
    logger.info("Processing test alerts...")
    
    for alert in test_alerts:
        soar.process_alert(alert)
        print()
        time.sleep(1)  # Small delay between alerts
    
    # Print stats
    stats = soar.get_stats()
    logger.info(f"\n📊 SOAR Statistics:")
    logger.info(f"   Alerts processed: {stats['alerts_processed']}")
    logger.info(f"   IPs blocked: {stats['blocked_ips_count']}")
    logger.info(f"   AI rules enabled: {stats['ai_rules_enabled']}")
    logger.info(f"   Blocked IPs: {', '.join(soar.get_blocked_ips()) if soar.get_blocked_ips() else 'None'}")


if __name__ == "__main__":
    main()

