#!/usr/bin/env python3
"""
SOAR-AI Integration Module

Bridges SOAR engine with AI Firewall Rule Generator.
Automatically triggers dynamic rule generation when:
- Unknown attack signatures are detected
- Zero-day behavior patterns emerge
- Anomaly detection triggers at critical severity
- New threat types are identified

This module is imported by soar_engine.py and automatically available.
"""

import logging
import os
from pathlib import Path
from typing import Optional, Dict, Any
from dataclasses import dataclass

# Try to import AI rule generator
try:
    from ai_firewall_updater import (
        AIFirewallRuleManager,
        ThreatContext,
        ThreatSeverity,
        GEMINI_AVAILABLE,
    )
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False

logger = logging.getLogger("soar_ai_integration")


@dataclass
class AlertToThreatMapper:
    """Maps Suricata/ML alerts to threat contexts for AI rule generation"""

    @staticmethod
    def suricata_alert_to_threat(alert: Dict[str, Any]) -> Optional[ThreatContext]:
        """
        Convert a Suricata alert to ThreatContext for AI rule generation

        Args:
            alert: Suricata EVE JSON alert dict

        Returns:
            ThreatContext or None if not applicable
        """
        try:
            # Extract basic info
            src_ip = alert.get("src_ip")
            dest_ip = alert.get("dest_ip")
            dest_port = alert.get("dest_port")
            signature = alert.get("alert", {}).get("signature", "Unknown")
            severity_int = alert.get("alert", {}).get("severity", 3)

            # Map alert severity to our severity levels
            severity_map = {1: ThreatSeverity.CRITICAL, 2: ThreatSeverity.HIGH, 3: ThreatSeverity.MEDIUM, 4: ThreatSeverity.LOW}
            severity = severity_map.get(severity_int, ThreatSeverity.MEDIUM)

            # Determine threat type from signature
            threat_type = AlertToThreatMapper._classify_threat_type(signature)

            # Extract payload or relevant data
            payload = f"""
            Suricata IDS Alert:
            Signature: {signature}
            Source IP: {src_ip}
            Destination: {dest_ip}:{dest_port}
            Protocol: {alert.get('proto', 'unknown').upper()}
            """

            if "http" in alert:
                http_info = alert.get("http", {})
                payload += f"""
            HTTP Method: {http_info.get('http_method', 'unknown')}
            URI: {http_info.get('uri', 'unknown')}
            Host: {http_info.get('hostname', 'unknown')}
            """

            if "payload" in alert:
                payload += f"\n            Raw Payload: {alert['payload'][:200]}..."

            return ThreatContext(
                severity=severity,
                threat_type=threat_type,
                payload=payload.strip(),
                source_ip=src_ip,
                dest_ip=dest_ip,
                dest_port=dest_port,
                protocol=alert.get("proto", "tcp"),
                additional_context=f"Suricata SID: {alert.get('alert', {}).get('signature_id')}",
            )

        except Exception as e:
            logger.error(f"Failed to map Suricata alert: {e}")
            return None

    @staticmethod
    def ml_anomaly_to_threat(anomaly_data: Dict[str, Any]) -> Optional[ThreatContext]:
        """
        Convert ML anomaly detection to ThreatContext

        Args:
            anomaly_data: ML model output dict

        Returns:
            ThreatContext or None if not applicable
        """
        try:
            anomaly_score = anomaly_data.get("anomaly_score", 0.5)
            model_name = anomaly_data.get("model_name", "unknown_model")
            packet_data = anomaly_data.get("packet_data", {})

            # Map anomaly score to severity
            if anomaly_score > 0.9:
                severity = ThreatSeverity.CRITICAL
            elif anomaly_score > 0.75:
                severity = ThreatSeverity.HIGH
            elif anomaly_score > 0.6:
                severity = ThreatSeverity.MEDIUM
            else:
                severity = ThreatSeverity.LOW

            # Build payload description
            payload = f"""
            ML Anomaly Detection:
            Model: {model_name}
            Anomaly Score: {anomaly_score:.2%}
            Features Detected: {anomaly_data.get('feature_flags', [])}
            """

            if packet_data:
                payload += f"""
            Source IP: {packet_data.get('src_ip')}
            Destination: {packet_data.get('dest_ip')}:{packet_data.get('dest_port')}
            Protocol: {packet_data.get('protocol', 'unknown')}
            """

            threat_type = anomaly_data.get("threat_type", "ANOMALOUS_BEHAVIOR")

            return ThreatContext(
                severity=severity,
                threat_type=threat_type,
                payload=payload.strip(),
                source_ip=packet_data.get("src_ip"),
                dest_ip=packet_data.get("dest_ip"),
                dest_port=packet_data.get("dest_port"),
                protocol=packet_data.get("protocol", "tcp"),
                additional_context=f"ML Model: {model_name}, Score: {anomaly_score:.2%}",
            )

        except Exception as e:
            logger.error(f"Failed to map ML anomaly: {e}")
            return None

    @staticmethod
    def zero_day_to_threat(zero_day_data: Dict[str, Any]) -> Optional[ThreatContext]:
        """
        Convert zero-day detection to ThreatContext

        Args:
            zero_day_data: Zero-day threat detection data

        Returns:
            ThreatContext or None
        """
        try:
            return ThreatContext(
                severity=ThreatSeverity.CRITICAL,
                threat_type=zero_day_data.get("threat_type", "UNKNOWN_ZERO_DAY"),
                payload=zero_day_data.get("behavioral_signature", "Behavioral anomaly detected"),
                source_ip=zero_day_data.get("src_ip"),
                dest_ip=zero_day_data.get("dest_ip"),
                dest_port=zero_day_data.get("dest_port"),
                protocol=zero_day_data.get("protocol", "tcp"),
                additional_context=zero_day_data.get("context", "Zero-day threat detected"),
            )

        except Exception as e:
            logger.error(f"Failed to map zero-day threat: {e}")
            return None

    @staticmethod
    def _classify_threat_type(signature: str) -> str:
        """Classify threat type based on signature"""
        signature_lower = signature.lower()

        classifications = {
            "c2": "C2_BEACONING",
            "command": "COMMAND_INJECTION",
            "sql": "SQL_INJECTION",
            "xss": "CROSS_SITE_SCRIPTING",
            "malware": "MALWARE_DETECTED",
            "ransomware": "RANSOMWARE",
            "backdoor": "BACKDOOR",
            "exploit": "EXPLOIT",
            "shellcode": "SHELLCODE_EXECUTION",
            "buffer": "BUFFER_OVERFLOW",
            "dos": "DENIAL_OF_SERVICE",
            "ddos": "DISTRIBUTED_DOS",
            "port": "PORT_SCAN",
            "nmap": "NETWORK_RECONNAISSANCE",
            "ssl": "SSL_ANOMALY",
            "tls": "TLS_ANOMALY",
            "beacon": "C2_BEACONING",
            "lateral": "LATERAL_MOVEMENT",
        }

        for key, threat_type in classifications.items():
            if key in signature_lower:
                return threat_type

        return "UNKNOWN_THREAT"


class SOARtoAIBridge:
    """
    Bridge between SOAR engine and AI rule generator.
    
    Uses EVENT-DRIVEN, NON-BLOCKING architecture:
    - Threats queued asynchronously
    - Returns immediately (doesn't block SOAR processing)
    - Background threads handle rule generation
    - Zero latency impact on main firewall
    """

    def __init__(self):
        self.manager = None
        self.enabled = AI_AVAILABLE and bool(os.getenv("GOOGLE_API_KEY"))

        if self.enabled:
            try:
                self.manager = AIFirewallRuleManager(max_workers=2, queue_size=100)
                logger.info("SOAR-AI Bridge initialized (async, event-driven)")
            except Exception as e:
                logger.warning(f"Failed to initialize AI rule manager: {e}")
                self.enabled = False
        else:
            logger.info("SOAR-AI Bridge disabled (Gemini AI not available or API key not set)")

    def process_alert(self, alert: Dict[str, Any]) -> bool:
        """
        Process a Suricata alert and queue for dynamic rule generation.
        
        NON-BLOCKING: Returns immediately after queuing.
        Actual rule generation happens asynchronously in background.

        Args:
            alert: Suricata EVE JSON alert

        Returns:
            True if threat was queued, False if queue full or disabled
        """
        if not self.enabled or not self.manager:
            return False

        threat = AlertToThreatMapper.suricata_alert_to_threat(alert)

        if not threat:
            return False

        # Only queue for CRITICAL/HIGH severity threats
        if threat.severity not in [ThreatSeverity.CRITICAL, ThreatSeverity.HIGH]:
            return False

        logger.info(f"Queueing AI rule generation for: {threat.threat_type} (async, non-blocking)")

        # Queue asynchronously (returns immediately)
        success = self.manager.queue_threat(threat)
        return success

    def process_ml_anomaly(self, anomaly_data: Dict[str, Any]) -> bool:
        """Process ML anomaly detection - queue for async rule generation"""
        if not self.enabled or not self.manager:
            return False

        threat = AlertToThreatMapper.ml_anomaly_to_threat(anomaly_data)

        if not threat:
            return False

        # Only queue for high-confidence anomalies
        anomaly_score = anomaly_data.get("anomaly_score", 0)
        if anomaly_score < 0.85:
            return False

        logger.info(f"Queueing AI rule for ML anomaly: {threat.threat_type} (score: {anomaly_score:.2%})")

        # Queue asynchronously
        success = self.manager.queue_threat(threat)
        return success

    def process_zero_day(self, zero_day_data: Dict[str, Any]) -> bool:
        """Process zero-day threat - CRITICAL priority"""
        if not self.enabled or not self.manager:
            return False

        threat = AlertToThreatMapper.zero_day_to_threat(zero_day_data)

        if not threat:
            return False

        logger.info(f"CRITICAL: Zero-day threat queued: {threat.threat_type}")

        # Queue asynchronously (high-severity will be processed first by thread pool)
        success = self.manager.queue_threat(threat)
        return success

    def get_stats(self) -> dict:
        """Get rule generation statistics"""
        if self.manager:
            return self.manager.get_stats()
        return {}


# Global bridge instance
_soar_ai_bridge: Optional[SOARtoAIBridge] = None


def get_soar_ai_bridge() -> Optional[SOARtoAIBridge]:
    """Get or create the SOAR-AI bridge"""
    global _soar_ai_bridge
    if _soar_ai_bridge is None:
        _soar_ai_bridge = SOARtoAIBridge()
    return _soar_ai_bridge


def trigger_rule_generation_from_alert(alert: Dict[str, Any]) -> bool:
    """Convenience function to trigger rule generation from alert"""
    bridge = get_soar_ai_bridge()
    if bridge:
        return bridge.process_alert(alert)
    return False


def trigger_rule_generation_from_anomaly(anomaly_data: Dict[str, Any]) -> bool:
    """Convenience function to trigger rule generation from ML anomaly"""
    bridge = get_soar_ai_bridge()
    if bridge:
        return bridge.process_ml_anomaly(anomaly_data)
    return False


def trigger_rule_generation_from_zero_day(zero_day_data: Dict[str, Any]) -> bool:
    """Convenience function to trigger rule generation from zero-day detection"""
    bridge = get_soar_ai_bridge()
    if bridge:
        return bridge.process_zero_day(zero_day_data)
    return False


if __name__ == "__main__":
    # Test the integration
    logging.basicConfig(level=logging.INFO)

    test_alert = {
        "src_ip": "192.168.1.100",
        "dest_ip": "192.168.1.50",
        "dest_port": 4444,
        "proto": "tcp",
        "alert": {"signature": "Malicious C2 Beacon Pattern", "signature_id": 100001, "severity": 1},
        "http": {"http_method": "GET", "uri": "/cmd", "hostname": "attacker.com"},
    }

    test_anomaly = {
        "model_name": "isolation_forest_v2",
        "anomaly_score": 0.95,
        "threat_type": "ANOMALOUS_TRAFFIC_PATTERN",
        "feature_flags": ["port_scan", "syn_flood", "unexpected_protocol"],
        "packet_data": {"src_ip": "203.0.113.1", "dest_ip": "192.168.1.5", "dest_port": 22, "protocol": "tcp"},
    }

    bridge = get_soar_ai_bridge()
    if bridge and bridge.enabled:
        print("Testing alert to threat mapping...")
        result = bridge.process_alert(test_alert)
        print(f"Alert processing result: {result}")

        print("\nTesting anomaly to threat mapping...")
        result = bridge.process_ml_anomaly(test_anomaly)
        print(f"Anomaly processing result: {result}")
    else:
        print("SOAR-AI Bridge not enabled (AI not available or API key missing)")
