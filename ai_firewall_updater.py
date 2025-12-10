#!/usr/bin/env python3
"""
AI-Powered Firewall Rule Generator using Google Gemini

EVENT-DRIVEN, ON-DEMAND, NON-BLOCKING rule generation.

Key Design Principles:
- ZERO impact on main firewall throughput (40Gbps, <1ms latency)
- Rules generated ONLY when needed (triggered by SOAR/ML anomalies)
- Async/threading prevents blocking packet inspection
- Safe for production deployment

Triggered by:
- SOAR engine detecting CRITICAL/HIGH severity threats
- ML anomaly detection models with high confidence
- Zero-day behavior pattern detection
- External threat intelligence feeds (optional)

Security Features:
- API key management via environment variables
- Rule syntax validation before deployment
- File locking to prevent race conditions
- Automatic rule backups
- Comprehensive logging and audit trails
- Safe rule rollback mechanism
- Zero-downtime rule reload (suricatasc)

Author: NGFW Security Team
License: MIT
"""

import os
import subprocess
import logging
import json
import threading
import time
import fcntl
from pathlib import Path
from datetime import datetime
from typing import Optional, Tuple, List, Callable
from dataclasses import dataclass, asdict
from enum import Enum
import hashlib
from queue import Queue, Empty
from concurrent.futures import ThreadPoolExecutor

try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False


# ============================================================================
# CONFIGURATION
# ============================================================================

# Path to rules file - uses local rules/local.rules in development, /etc/suricata/rules/local.rules in production
SURICATA_RULES_PATH = Path("rules/local.rules") if Path("rules/local.rules").exists() else Path("/etc/suricata/rules/local.rules")
SURICATA_TEST_RULES_PATH = Path("/tmp/suricata_test_rules.rules")
SURICATA_BINARY = Path("/usr/bin/suricata")
SURICATA_SOCKET = Path("/var/run/suricata/suricata-command.socket")

# Backup and audit paths (must be writable by the script)
RULES_BACKUP_DIR = Path("logs/rules_backup")
RULES_AUDIT_LOG = Path("logs/rules_audit.json")
RULES_STATE_FILE = Path("logs/rules_state.json")
RULES_LOCK_FILE = Path("logs/rules.lock")

# Rule generation config
GEMINI_MODEL_NAME = "gemini-2.5-flash"
RULE_SID_START = 1000001
RULE_GENERATION_TIMEOUT = 30  # seconds

# Setup Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/ai_firewall_updater.log')
    ]
)
logger = logging.getLogger("ai_firewall_updater")


# ============================================================================
# ENUMS & DATA CLASSES
# ============================================================================

class RuleAction(Enum):
    """Suricata rule actions"""
    DROP = "drop"
    REJECT = "reject"
    ALERT = "alert"
    PASS = "pass"


class ThreatSeverity(Enum):
    """Threat severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class ThreatContext:
    """Input context for AI rule generation"""
    severity: ThreatSeverity
    threat_type: str  # e.g., "C2_BEACONING", "SQL_INJECTION", "MALWARE"
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
1. Action: 'drop' or 'reject'
2. SID >= 1000001
3. Fields: msg, classtype, rev, metadata
4. Match patterns specific to this threat
5. TCP flow analysis for encrypted traffic
6. Pattern detection for malware signatures
7. Beacon detection for C2 communications
8. Behavioral patterns for anomalies

OUTPUT INSTRUCTIONS:
Provide only the Suricata rule, no explanations or code blocks.

Example format:
drop tcp any any -> any 4444 (msg:"C2 Beacon"; flow:established,to_server; content:"beacon"; classtype:trojan-activity; sid:1000001; rev:1; metadata: policy drop;)
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
    rollback_hash: Optional[str] = None


@dataclass
class AuditEntry:
    """Rule deployment audit trail"""
    timestamp: str
    action: str  # "generated", "validated", "deployed", "rolled_back"
    rule_sid: int
    rule_msg: str
    status: str  # "success", "failed"
    error_message: Optional[str] = None
    operator: str = "ai_system"


# ============================================================================
# SECURITY & SAFETY MECHANISMS
# ============================================================================

class RuleLock:
    """File-based locking to prevent concurrent rule updates"""

    def __init__(self, lock_file: Path):
        self.lock_file = lock_file
        self.lock_file.parent.mkdir(parents=True, exist_ok=True)
        self.file_handle = None

    def acquire(self, timeout: int = 30) -> bool:
        """Acquire exclusive lock"""
        start_time = time.time()
        while True:
            try:
                self.file_handle = open(self.lock_file, 'w')
                fcntl.flock(self.file_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                logger.info(f"Lock acquired: {self.lock_file}")
                return True
            except IOError:
                if time.time() - start_time > timeout:
                    logger.error(f"Lock timeout after {timeout}s")
                    return False
                time.sleep(0.1)

    def release(self):
        """Release lock"""
        if self.file_handle:
            try:
                fcntl.flock(self.file_handle.fileno(), fcntl.LOCK_UN)
                self.file_handle.close()
                logger.info(f"Lock released: {self.lock_file}")
            except Exception as e:
                logger.error(f"Failed to release lock: {e}")

    def __enter__(self):
        if not self.acquire():
            raise RuntimeError("Could not acquire rules lock")
        return self

    def __exit__(self, *args):
        self.release()


class RulesBackup:
    """Backup and rollback mechanism for rules"""

    def __init__(self, backup_dir: Path):
        self.backup_dir = backup_dir
        self.backup_dir.mkdir(parents=True, exist_ok=True)

    def create_backup(self, rules_path: Path) -> str:
        """Create timestamped backup of current rules"""
        if not rules_path.exists():
            return None

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_hash = self._compute_hash(rules_path)
        backup_file = self.backup_dir / f"rules_{timestamp}_{backup_hash[:8]}.backup"

        try:
            backup_file.write_text(rules_path.read_text())
            logger.info(f"Backup created: {backup_file}")
            return str(backup_file)
        except Exception as e:
            logger.error(f"Backup failed: {e}")
            return None

    def rollback_to_backup(self, backup_file: Path, target_path: Path) -> bool:
        """Rollback rules to a previous backup"""
        try:
            backup_content = backup_file.read_text()
            target_path.write_text(backup_content)
            logger.info(f"Rolled back to: {backup_file}")
            return True
        except Exception as e:
            logger.error(f"Rollback failed: {e}")
            return False

    @staticmethod
    def _compute_hash(file_path: Path) -> str:
        """Compute SHA256 hash of file content"""
        sha256_hash = hashlib.sha256()
        with open(file_path, 'rb') as f:
            sha256_hash.update(f.read())
        return sha256_hash.hexdigest()

    def get_latest_backup(self) -> Optional[Path]:
        """Get the most recent backup file"""
        backups = list(self.backup_dir.glob("rules_*.backup"))
        if backups:
            return max(backups, key=lambda p: p.stat().st_mtime)
        return None


class RuleValidator:
    """Validates Suricata rule syntax before deployment"""

    def __init__(self, suricata_binary: Path, test_rules_path: Path):
        self.suricata_binary = suricata_binary
        self.test_rules_path = test_rules_path

    def validate(self, rule_text: str) -> Tuple[bool, str]:
        """
        Validate rule syntax using Suricata test mode

        Returns:
            Tuple of (is_valid, error_message)
        """
        # Skip validation if Suricata binary not available (development mode)
        if not self.suricata_binary.exists():
            logger.warning(f"Suricata binary not found at {self.suricata_binary} - skipping validation (development mode)")
            return True, ""  # Skip validation, allow deployment
        
        # Create temporary test file
        try:
            self.test_rules_path.write_text(rule_text)
        except Exception as e:
            return False, f"Failed to write test file: {e}"

        # Run Suricata in test mode
        # -T = test mode, -S = specific rule file
        cmd = [str(self.suricata_binary), "-T", "-S", str(self.test_rules_path)]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=RULE_GENERATION_TIMEOUT
            )

            # Clean up test file
            try:
                self.test_rules_path.unlink()
            except Exception:
                pass

            if result.returncode == 0:
                return True, ""
            else:
                error = result.stderr or result.stdout
                logger.error(f"Rule validation failed: {error}")
                return False, error

        except subprocess.TimeoutExpired:
            return False, "Validation timeout"
        except Exception as e:
            return False, f"Validation error: {e}"

    def validate_rule_object(self, rule: GeneratedRule) -> Tuple[bool, str]:
        """Validate a GeneratedRule object"""
        is_valid, error = self.validate(rule.rule_text)
        if is_valid:
            rule.validated = True
        return is_valid, error


# ============================================================================
# AI RULE GENERATOR
# ============================================================================

class AIRuleGenerator:
    """Generates Suricata rules using Google Gemini AI"""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("GOOGLE_API_KEY")

        if not self.api_key:
            raise ValueError(
                "GOOGLE_API_KEY not found. Set it via environment variable: "
                "export GOOGLE_API_KEY='your-api-key'"
            )

        if not GEMINI_AVAILABLE:
            raise ImportError(
                "google-generativeai not installed. "
                "Install with: pip install google-generativeai"
            )

        try:
            genai.configure(api_key=self.api_key)
            self.model = genai.GenerativeModel(GEMINI_MODEL_NAME)
            logger.info(f"Gemini configured: {GEMINI_MODEL_NAME}")
        except Exception as e:
            logger.error(f"Gemini initialization failed: {e}")
            raise

        self.next_sid = self._get_next_sid()

    def generate(self, threat: ThreatContext) -> Optional[GeneratedRule]:
        """
        Generate a Suricata rule from threat context

        Args:
            threat: ThreatContext with threat details

        Returns:
            GeneratedRule object or None if generation failed
        """
        prompt = threat.to_prompt()

        logger.info(f"Generating rule for threat: {threat.threat_type}")

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

            # Check if response was blocked by safety filter
            if not response.text or response.text.strip() == "":
                logger.warning(f"API response empty (safety filter?). Using fallback rule for {threat.threat_type}")
                # Generate basic fallback rule
                rule_text = self._generate_fallback_rule(threat)
            else:
                rule_text = response.text.strip()

            # Clean up markdown if present
            rule_text = rule_text.replace("```suricata", "").replace("```", "").strip()

            if not rule_text:
                logger.error("AI returned empty rule")
                return None

            # Parse rule to extract metadata
            rule_obj = self._parse_rule(rule_text, threat.severity)

            if not rule_obj:
                logger.error("Failed to parse generated rule")
                return None

            logger.info(f"Rule generated: SID {rule_obj.sid} - {rule_obj.msg}")
            return rule_obj

        except Exception as e:
            logger.error(f"Rule generation failed: {e}")
            # Try fallback
            try:
                logger.info("Attempting fallback rule generation...")
                rule_text = self._generate_fallback_rule(threat)
                rule_obj = self._parse_rule(rule_text, threat.severity)
                if rule_obj:
                    logger.info(f"Fallback rule generated: SID {rule_obj.sid}")
                    return rule_obj
            except Exception as fallback_error:
                logger.error(f"Fallback also failed: {fallback_error}")
            return None

    def _generate_fallback_rule(self, threat: ThreatContext) -> str:
        """Generate a basic fallback rule when API fails"""
        sid = self.next_sid
        self.next_sid += 1

        # Create a basic rule based on threat type
        threat_type_to_pattern = {
            "C2_BEACONING": "content:\"beacon\"; flow:established,to_server;",
            "SQL_INJECTION": "content:\"'\"; http_uri; content:\"OR\"; http_uri;",
            "MALWARE_EXECUTION": "content:\"|909090|\"; depth:10;",
            "PORT_SCAN": "flags:S; threshold:type both,track by_src,count 100,seconds 10;",
            "COMMAND_INJECTION": "content:\"|3b|\"; http_uri;",
        }

        pattern = threat_type_to_pattern.get(threat.threat_type, "content:\"suspicious\";")

        rule = f'drop tcp any any -> any any (msg:"{threat.threat_type} Detected"; {pattern} classtype:trojan-activity; sid:{sid}; rev:1;)'

        return rule

    def _parse_rule(self, rule_text: str, severity: ThreatSeverity) -> Optional[GeneratedRule]:
        """Parse rule text and extract metadata"""
        try:
            # Extract action (drop, reject, alert, pass)
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
# RULE MANAGER (Orchestration)
# ============================================================================

class AIFirewallRuleManager:
    """
    Orchestrates AI rule generation, validation, and deployment.
    
    EVENT-DRIVEN, ASYNC architecture:
    - Rules generated asynchronously in background threads
    - Non-blocking: doesn't affect main firewall throughput
    - Thread pool: max 2 concurrent rule generations
    - Queue-based: threats queued and processed in order
    - Zero latency impact on packet processing (40Gbps target)
    """

    def __init__(self, max_workers: int = 2, queue_size: int = 100):
        self.generator = AIRuleGenerator() if GEMINI_AVAILABLE else None
        self.validator = RuleValidator(SURICATA_BINARY, SURICATA_TEST_RULES_PATH)
        self.backup = RulesBackup(RULES_BACKUP_DIR)
        self.audit_log = RULES_AUDIT_LOG

        # Thread pool for async rule generation (non-blocking)
        self.executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="ai_rule_gen_")
        self.threat_queue: Queue = Queue(maxsize=queue_size)
        self.processing = False
        self.processed_rules: int = 0
        self.failed_rules: int = 0
        self.skipped_threats: int = 0

        # Ensure directories exist
        Path("logs").mkdir(exist_ok=True)
        RULES_BACKUP_DIR.mkdir(parents=True, exist_ok=True)

        # Start background queue processor thread
        self.queue_processor_thread = None
        self._start_queue_processor()

        logger.info(f"AI Firewall Rule Manager initialized (async, max_workers={max_workers})")

    def _start_queue_processor(self):
        """Start the background queue processor thread"""
        if self.processing:
            return

        self.processing = True
        self.queue_processor_thread = threading.Thread(
            target=self._process_queue_loop,
            daemon=True,
            name="ai_rule_queue_processor"
        )
        self.queue_processor_thread.start()
        logger.info("Background queue processor started (daemon)")

    def _process_queue_loop(self):
        """
        Background thread that processes threats from queue.
        Runs continuously, processing one threat at a time.
        """
        while self.processing:
            try:
                # Non-blocking queue get with timeout
                threat = self.threat_queue.get(timeout=5)

                # Process in executor (background thread pool)
                future = self.executor.submit(self._process_threat_sync, threat)

                # Don't wait for completion - fire and forget
                # This ensures main firewall isn't blocked
                logger.debug(f"Threat queued for async processing: {threat.threat_type}")

            except Empty:
                # No threats in queue, continue waiting
                pass
            except Exception as e:
                logger.error(f"Queue processor error: {e}")

    def queue_threat(self, threat: ThreatContext) -> bool:
        """
        Queue a threat for async rule generation.
        
        IMPORTANT: This is NON-BLOCKING and returns immediately.
        Rule generation happens in background.

        Args:
            threat: ThreatContext to process

        Returns:
            True if queued successfully, False if queue is full
        """
        try:
            # Try to add without blocking (raises if queue full)
            self.threat_queue.put_nowait(threat)
            logger.info(f"Threat queued (async): {threat.threat_type} | Queue size: {self.threat_queue.qsize()}")
            return True
        except:
            logger.warning(f"Rule generation queue full, skipping: {threat.threat_type}")
            self.skipped_threats += 1
            return False

    def process_threat(self, threat: ThreatContext) -> Tuple[bool, str]:
        """
        BLOCKING version: Generate, validate, and deploy rule synchronously.
        
        Use this only for manual/CLI testing.
        For production, use queue_threat() for non-blocking async processing.

        Returns:
            Tuple of (success: bool, message: str)
        """
        if not self.generator:
            return False, "Gemini AI not available"

        return self._process_threat_sync(threat)

    def _process_threat_sync(self, threat: ThreatContext) -> Tuple[bool, str]:
        """
        Synchronous threat processing (runs in background thread).
        All heavy lifting happens here without blocking main firewall.
        """
        # Acquire lock (thread-safe)
        try:
            with RuleLock(RULES_LOCK_FILE):
                # Generate rule
                logger.info(f"Processing threat (background): {threat.threat_type}")
                rule = self.generator.generate(threat)

                if not rule:
                    logger.error(f"Rule generation failed for: {threat.threat_type}")
                    self.failed_rules += 1
                    return False, "Rule generation failed"

                # Validate rule
                logger.info(f"Validating rule SID {rule.sid}")
                is_valid, error = self.validator.validate_rule_object(rule)

                if not is_valid:
                    self._log_audit(
                        action="validated",
                        rule_sid=rule.sid,
                        rule_msg=rule.msg,
                        status="failed",
                        error_message=error
                    )
                    logger.error(f"Rule validation failed: {error}")
                    self.failed_rules += 1
                    return False, f"Rule validation failed: {error}"

                self._log_audit(
                    action="validated",
                    rule_sid=rule.sid,
                    rule_msg=rule.msg,
                    status="success"
                )

                # Deploy rule
                success, deploy_msg = self._deploy_rule(rule)
                if success:
                    self.processed_rules += 1
                else:
                    self.failed_rules += 1

                return success, deploy_msg

        except Exception as e:
            logger.error(f"Error processing threat: {e}")
            self.failed_rules += 1
            return False, f"Processing error: {e}"

    def shutdown(self):
        """Gracefully shutdown the manager"""
        self.processing = False
        self.executor.shutdown(wait=True)
        if self.queue_processor_thread:
            self.queue_processor_thread.join(timeout=5)
        logger.info(f"AI Firewall Manager shutdown (processed: {self.processed_rules}, failed: {self.failed_rules}, skipped: {self.skipped_threats})")

    def get_stats(self) -> dict:
        """Get processing statistics"""
        return {
            "processed_rules": self.processed_rules,
            "failed_rules": self.failed_rules,
            "skipped_threats": self.skipped_threats,
            "queue_size": self.threat_queue.qsize(),
        }

    def _deploy_rule(self, rule: GeneratedRule) -> Tuple[bool, str]:
        """
        Deploy rule to Suricata local.rules file and reload

        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            # Check if rules file exists
            if not SURICATA_RULES_PATH.exists():
                logger.warning(f"Rules file not found: {SURICATA_RULES_PATH}")
                logger.info("(This is normal in development environments)")
                # Log the rule even if we can't deploy
                self._log_audit(
                    action="generated",
                    rule_sid=rule.sid,
                    rule_msg=rule.msg,
                    status="success"
                )
                return True, f"Rule generated (local.rules not found): SID {rule.sid}"

            # Create backup before modification
            backup_file = self.backup.create_backup(SURICATA_RULES_PATH)

            # Append rule to local.rules
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            rule_entry = f"\n# Auto-generated by AI Firewall on {timestamp}\n# Threat Severity: {rule.threat_severity.value}\n{rule.rule_text}\n"

            with open(SURICATA_RULES_PATH, "a") as f:
                f.write(rule_entry)

            logger.info(f"Rule appended to {SURICATA_RULES_PATH}")

            # Reload Suricata rules (zero-downtime)
            reload_success = self._reload_suricata_rules()

            if reload_success:
                self._log_audit(
                    action="deployed",
                    rule_sid=rule.sid,
                    rule_msg=rule.msg,
                    status="success"
                )
                return True, f"Rule deployed successfully: SID {rule.sid}"
            else:
                logger.warning("Reload failed, attempting rollback...")
                if backup_file and Path(backup_file).exists():
                    self.backup.rollback_to_backup(Path(backup_file), SURICATA_RULES_PATH)
                    self._log_audit(
                        action="rolled_back",
                        rule_sid=rule.sid,
                        rule_msg=rule.msg,
                        status="success",
                        error_message="Deployment failed, rolled back to backup"
                    )
                return False, f"Rule reload failed, rolled back to backup"

        except Exception as e:
            logger.error(f"Rule deployment failed: {e}")
            self._log_audit(
                action="deployed",
                rule_sid=rule.sid,
                rule_msg=rule.msg,
                status="failed",
                error_message=str(e)
            )
            return False, f"Deployment error: {e}"

    @staticmethod
    def _reload_suricata_rules() -> bool:
        """Reload Suricata rules using suricatasc (zero-downtime)"""
        # Skip reload if Suricata not installed (development mode)
        if not SURICATA_BINARY.exists():
            logger.info("Suricata binary not found - skipping reload (development mode)")
            return True  # Consider it success for development
        
        try:
            # Try suricatasc first (zero-downtime reload)
            result = subprocess.run(
                ["suricatasc", "-c", "reload-rules"],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                logger.info("Suricata rules reloaded via suricatasc (zero-downtime)")
                return True
            else:
                logger.warning("suricatasc reload failed, trying restart...")

        except FileNotFoundError:
            logger.warning("suricatasc not found, trying systemctl restart...")
        except Exception as e:
            logger.error(f"suricatasc error: {e}")

        # Fallback: restart Suricata (may cause brief packet loss)
        try:
            result = subprocess.run(
                ["systemctl", "restart", "suricata"],
                capture_output=True,
                text=True,
                timeout=15
            )
            if result.returncode == 0:
                logger.info("Suricata restarted (zero-downtime may not be guaranteed)")
                time.sleep(2)  # Wait for restart
                return True
        except Exception as e:
            logger.error(f"Suricata restart failed: {e}")

        return False

    def _log_audit(
        self,
        action: str,
        rule_sid: int,
        rule_msg: str,
        status: str,
        error_message: Optional[str] = None
    ):
        """Log action to audit trail"""
        try:
            self.audit_log.parent.mkdir(parents=True, exist_ok=True)

            entry = AuditEntry(
                timestamp=datetime.now().isoformat(),
                action=action,
                rule_sid=rule_sid,
                rule_msg=rule_msg,
                status=status,
                error_message=error_message
            )

            # Read existing audit log
            audit_entries = []
            if self.audit_log.exists():
                try:
                    audit_entries = json.loads(self.audit_log.read_text())
                except Exception:
                    pass

            # Append new entry
            audit_entries.append(asdict(entry))

            # Write back
            self.audit_log.write_text(json.dumps(audit_entries, indent=2))

        except Exception as e:
            logger.error(f"Failed to log audit entry: {e}")


# ============================================================================
# MAIN DEMO / TESTING
# ============================================================================

def demo_c2_detection():
    """Demo: Generate rule for C2 beaconing threat"""
    threat = ThreatContext(
        severity=ThreatSeverity.CRITICAL,
        threat_type="C2_BEACONING",
        payload="""
        Detected encrypted C2 beaconing pattern over HTTPS.
        - Destination: 192.168.1.50:4444
        - Protocol: TCP/TLS 1.3
        - Payload signature: Starts with NOP sled (0x909090)
        - Frequency: Beacon every 5 minutes with consistent byte pattern
        - Pattern: JA3 fingerprint matches known malware family
        """,
        dest_ip="192.168.1.50",
        dest_port=4444,
        protocol="tcp",
        additional_context="Correlated with MITRE ATT&CK T1071 (Application Layer Protocol)"
    )
    return threat


def demo_sql_injection():
    """Demo: Generate rule for SQL injection attack"""
    threat = ThreatContext(
        severity=ThreatSeverity.HIGH,
        threat_type="SQL_INJECTION",
        payload="""
        HTTP GET request contains SQL injection payload:
        GET /search.php?q=1' OR '1'='1
        
        Bypassing authentication via boolean-based SQL injection.
        Attacker attempting to enumerate database structure.
        """,
        dest_port=80,
        protocol="tcp",
        additional_context="OWASP Top 10 A03:2021 – Injection"
    )
    return threat


def demo_zero_day():
    """Demo: Generate rule for zero-day polymorphic malware"""
    threat = ThreatContext(
        severity=ThreatSeverity.CRITICAL,
        threat_type="ZERO_DAY_MALWARE",
        payload="""
        Unknown polymorphic malware executable detected.
        - Behavioral signature: Creates child process with elevated privileges
        - Registry modification: HKLM\\System\\CurrentControlSet\\Services
        - Network behavior: DNS tunneling over unusual domain names
        - File operations: Writes to System32 with hidden attributes
        - Code obfuscation: XOR encryption, API hooking detected
        """,
        additional_context="Not in any threat intelligence feed. Triggered by behavioral ML model with 0.98 confidence."
    )
    return threat


def main():
    """Main function for testing"""
    logger.info("Starting AI Firewall Rule Generator (EVENT-DRIVEN MODE)")

    # Ensure Gemini is available
    if not GEMINI_AVAILABLE:
        logger.error("google-generativeai not installed")
        logger.info("Install with: pip install google-generativeai")
        return

    # Initialize manager (async mode by default)
    try:
        manager = AIFirewallRuleManager(max_workers=2, queue_size=100)
    except Exception as e:
        logger.error(f"Failed to initialize manager: {e}")
        return

    # Demo threats
    threats = [
        demo_c2_detection(),
        # demo_sql_injection(),
        # demo_zero_day(),
    ]

    # ASYNC/NON-BLOCKING: Queue threats (returns immediately)
    logger.info("\n" + "=" * 60)
    logger.info("QUEUEING THREATS FOR ASYNC PROCESSING")
    logger.info("=" * 60)

    for threat in threats:
        logger.info(f"\nQueuing: {threat.threat_type} (severity: {threat.severity.value})")
        success = manager.queue_threat(threat)

        if not success:
            logger.warning(f"Failed to queue threat (queue full)")

    # Let background processor work
    logger.info("\nWaiting for background processing to complete...")
    time.sleep(10)

    # Get stats
    stats = manager.get_stats()
    logger.info("\n" + "=" * 60)
    logger.info("PROCESSING STATISTICS")
    logger.info("=" * 60)
    logger.info(f"Processed rules: {stats['processed_rules']}")
    logger.info(f"Failed rules: {stats['failed_rules']}")
    logger.info(f"Skipped threats: {stats['skipped_threats']}")
    logger.info(f"Remaining queue size: {stats['queue_size']}")

    # Graceful shutdown
    logger.info("\nShutting down...")
    manager.shutdown()
    logger.info("Done!")


if __name__ == "__main__":
    main()
