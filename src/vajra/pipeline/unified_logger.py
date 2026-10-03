#!/usr/bin/env python3
"""
Unified Logger - Combines Suricata alerts and ML predictions into a single log stream

Creates a unified event format that includes:
- Suricata IDS alerts
- ML model predictions  
- Packet inspection results
- SOAR actions

All events are logged to a single unified JSON file for easy analysis.
"""

import json
import time
import logging
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional, List, Callable
from dataclasses import dataclass, asdict
from enum import Enum
import queue

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger("unified_logger")


class EventType(Enum):
    """Types of security events"""
    SURICATA_ALERT = "suricata_alert"
    ML_PREDICTION = "ml_prediction"
    PACKET_INSPECTION = "packet_inspection"
    SOAR_ACTION = "soar_action"
    SYSTEM_EVENT = "system_event"


class ThreatLevel(Enum):
    """Threat severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class UnifiedEvent:
    """Unified security event format"""
    event_id: str
    event_type: str
    timestamp: str
    threat_level: str
    
    # Source information
    source_component: str
    
    # Network context
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    
    # Threat details
    threat_type: str
    signature: str
    description: str
    confidence: float
    
    # ML specific
    ml_model: Optional[str]
    ml_prediction: Optional[int]
    ml_probabilities: Optional[List[float]]
    
    # Suricata specific
    suricata_sid: Optional[int]
    suricata_category: Optional[str]
    
    # Action taken
    action: str
    blocked: bool
    
    # Additional data
    metadata: Dict[str, Any]


class UnifiedLogger:
    """
    Unified logging system for all security events
    
    Combines:
    - Suricata eve.json alerts
    - ML model predictions
    - Packet inspection results
    - SOAR engine actions
    
    Into a single, searchable log format.
    """
    
    def __init__(
        self,
        unified_log_path: str = "logs/unified_events.json",
        eve_json_path: str = "logs/eve.json",
        ml_log_path: str = "logs/ml_predictions.json",
        watch_eve: bool = True,
        watch_ml: bool = True
    ):
        self.unified_log_path = Path(unified_log_path)
        self.eve_json_path = Path(eve_json_path)
        self.ml_log_path = Path(ml_log_path)
        
        # Create directories
        self.unified_log_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Event queue for async writing
        self.event_queue: queue.Queue = queue.Queue()
        
        # Statistics
        self.stats = {
            'total_events': 0,
            'suricata_alerts': 0,
            'ml_predictions': 0,
            'soar_actions': 0,
            'threats_by_level': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0
            }
        }
        
        # Control flags
        self._running = False
        self._stop_event = threading.Event()
        
        # File watchers
        self._eve_position = 0
        self._ml_position = 0
        
        # Event ID counter
        self._event_counter = 0
        self._counter_lock = threading.Lock()
        
        # Callbacks for real-time event processing
        self.event_callbacks: List[Callable[[UnifiedEvent], None]] = []
        
        logger.info(f"Unified Logger initialized")
        logger.info(f"  Unified log: {unified_log_path}")
    
    def _generate_event_id(self) -> str:
        """Generate unique event ID"""
        with self._counter_lock:
            self._event_counter += 1
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            return f"EVT-{timestamp}-{self._event_counter:06d}"
    
    def register_callback(self, callback: Callable[[UnifiedEvent], None]):
        """Register callback for real-time event processing"""
        self.event_callbacks.append(callback)
    
    def _map_suricata_severity(self, severity: int) -> str:
        """Map Suricata severity (1-4) to threat level"""
        mapping = {
            1: ThreatLevel.CRITICAL.value,
            2: ThreatLevel.HIGH.value,
            3: ThreatLevel.MEDIUM.value,
            4: ThreatLevel.LOW.value
        }
        return mapping.get(severity, ThreatLevel.MEDIUM.value)
    
    def log_suricata_event(self, eve_event: Dict[str, Any]) -> Optional[UnifiedEvent]:
        """Convert and log ANY Suricata eve.json event (alert, flow, dns, tls, http, etc.)"""
        # Validate input
        if not isinstance(eve_event, dict):
            return None
        
        event_type = eve_event.get('event_type')
        if not event_type:
            return None
        
        # Determine threat level and description based on event type
        if event_type == 'alert':
            alert_data = eve_event.get('alert', {})
            severity = self._map_suricata_severity(alert_data.get('severity', 3))
            threat_type = alert_data.get('category', 'Unknown')
            signature = alert_data.get('signature', 'Unknown')
            description = alert_data.get('signature', '')
            confidence = 1.0
            action = alert_data.get('action', 'allowed')
            blocked = alert_data.get('action') == 'blocked'
        elif event_type == 'flow':
            flow_data = eve_event.get('flow', {})
            severity = ThreatLevel.INFO.value
            threat_type = f"Network Flow ({eve_event.get('app_proto', 'unknown').upper()})"
            signature = f"Flow: {eve_event.get('proto', 'TCP')}"
            description = f"{flow_data.get('pkts_toserver', 0)} pkts sent, {flow_data.get('pkts_toclient', 0)} pkts recv"
            confidence = 1.0
            action = "allowed"
            blocked = False
        elif event_type == 'dns':
            dns_data = eve_event.get('dns', {})
            severity = ThreatLevel.INFO.value
            threat_type = f"DNS Query ({dns_data.get('type', 'query')})"
            signature = f"DNS: {dns_data.get('rrname', 'unknown')}"
            description = f"DNS lookup for {dns_data.get('rrname', 'unknown')}"
            confidence = 1.0
            action = "allowed"
            blocked = False
        elif event_type == 'tls':
            tls_data = eve_event.get('tls', {})
            severity = ThreatLevel.INFO.value
            threat_type = "TLS/SSL Connection"
            signature = f"TLS: {tls_data.get('sni', 'unknown')}"
            description = f"TLS connection to {tls_data.get('sni', 'unknown')} ({tls_data.get('version', 'unknown')})"
            confidence = 1.0
            action = "allowed"
            blocked = False
        elif event_type == 'http':
            http_data = eve_event.get('http', {})
            severity = ThreatLevel.INFO.value
            threat_type = "HTTP Request"
            signature = f"HTTP {http_data.get('http_method', 'GET')}"
            description = f"{http_data.get('http_method', 'GET')} {http_data.get('hostname', '')}{http_data.get('url', '/')}"
            confidence = 1.0
            action = "allowed"
            blocked = False
        else:
            # Other event types (fileinfo, stats, etc.)
            severity = ThreatLevel.INFO.value
            threat_type = event_type.upper()
            signature = f"{event_type}"
            description = f"Suricata {event_type} event"
            confidence = 1.0
            action = "logged"
            blocked = False
        
        event = UnifiedEvent(
            event_id=self._generate_event_id(),
            event_type=f"suricata_{event_type}",
            timestamp=eve_event.get('timestamp', datetime.now(timezone.utc).isoformat()),
            threat_level=severity,
            source_component="suricata",
            src_ip=eve_event.get('src_ip', ''),
            dst_ip=eve_event.get('dest_ip', ''),
            src_port=eve_event.get('src_port', 0),
            dst_port=eve_event.get('dest_port', 0),
            protocol=eve_event.get('proto', ''),
            threat_type=threat_type,
            signature=signature,
            description=description,
            confidence=confidence,
            ml_model=None,
            ml_prediction=None,
            ml_probabilities=None,
            suricata_sid=eve_event.get('alert', {}).get('signature_id') if event_type == 'alert' else None,
            suricata_category=eve_event.get('alert', {}).get('category') if event_type == 'alert' else None,
            action=action,
            blocked=blocked,
            metadata={
                'flow_id': eve_event.get('flow_id'),
                'app_proto': eve_event.get('app_proto'),
                'http': eve_event.get('http'),
                'dns': eve_event.get('dns'),
                'tls': eve_event.get('tls'),
                'flow': eve_event.get('flow'),
                'event_type': event_type,
            }
        )
        
        self._write_event(event)
        if event_type == 'alert':
            self.stats['suricata_alerts'] += 1
        
        return event
    
    def log_suricata_alert(self, eve_event: Dict[str, Any]) -> Optional[UnifiedEvent]:
        """Legacy method - redirects to log_suricata_event"""
        return self.log_suricata_event(eve_event)
    
    def log_ml_prediction(self, prediction: Dict[str, Any]) -> UnifiedEvent:
        """Log ML model prediction as unified event"""
        is_threat = prediction.get('is_threat', False)
        confidence = prediction.get('confidence', 0)
        
        # Determine threat level based on confidence
        if not is_threat:
            threat_level = ThreatLevel.INFO.value
        elif confidence >= 0.9:
            threat_level = ThreatLevel.CRITICAL.value
        elif confidence >= 0.75:
            threat_level = ThreatLevel.HIGH.value
        elif confidence >= 0.5:
            threat_level = ThreatLevel.MEDIUM.value
        else:
            threat_level = ThreatLevel.LOW.value
        
        features = prediction.get('features_used', {})
        
        event = UnifiedEvent(
            event_id=self._generate_event_id(),
            event_type=EventType.ML_PREDICTION.value,
            timestamp=prediction.get('timestamp', datetime.now(timezone.utc).isoformat()),
            threat_level=threat_level,
            source_component="ml_engine",
            src_ip=features.get('src_ip', ''),
            dst_ip=features.get('dst_ip', ''),
            src_port=features.get('src_port', 0),
            dst_port=features.get('dst_port', 0),
            protocol=features.get('protocol', ''),
            threat_type=prediction.get('threat_type', 'ml_detected'),
            signature=f"ML-{prediction.get('model_name', 'unknown')}",
            description=f"ML model {prediction.get('model_name')} detected {prediction.get('threat_type')}",
            confidence=confidence,
            ml_model=prediction.get('model_name'),
            ml_prediction=prediction.get('prediction'),
            ml_probabilities=prediction.get('probabilities'),
            suricata_sid=None,
            suricata_category=None,
            action="detected",
            blocked=False,  # ML doesn't block directly
            metadata={
                'inference_time_ms': prediction.get('inference_time_ms'),
                'features': features
            }
        )
        
        self._write_event(event)
        self.stats['ml_predictions'] += 1
        
        return event
    
    def log_soar_action(self, action: Dict[str, Any]) -> UnifiedEvent:
        """Log SOAR engine action as unified event"""
        blocked = action.get('blocked', False)
        
        threat_level = ThreatLevel.HIGH.value if blocked else ThreatLevel.MEDIUM.value
        
        event = UnifiedEvent(
            event_id=self._generate_event_id(),
            event_type=EventType.SOAR_ACTION.value,
            timestamp=action.get('timestamp', datetime.now(timezone.utc).isoformat()),
            threat_level=threat_level,
            source_component="soar_engine",
            src_ip=action.get('target_ip', ''),
            dst_ip='',
            src_port=0,
            dst_port=0,
            protocol='',
            threat_type=action.get('signature', 'Unknown'),
            signature=action.get('signature', ''),
            description=f"SOAR action: {action.get('action')} on {action.get('target_ip')}",
            confidence=1.0,
            ml_model=None,
            ml_prediction=None,
            ml_probabilities=None,
            suricata_sid=None,
            suricata_category=None,
            action=action.get('action', 'LOG_ONLY'),
            blocked=blocked,
            metadata={
                'alert_id': action.get('alert_id'),
                'result': action.get('result'),
                'severity': action.get('severity')
            }
        )
        
        self._write_event(event)
        self.stats['soar_actions'] += 1
        
        return event
    
    def log_custom_event(
        self,
        event_type: str,
        threat_level: str,
        description: str,
        src_ip: str = "",
        dst_ip: str = "",
        metadata: Dict = None
    ) -> UnifiedEvent:
        """Log a custom event"""
        event = UnifiedEvent(
            event_id=self._generate_event_id(),
            event_type=event_type,
            timestamp=datetime.now(timezone.utc).isoformat(),
            threat_level=threat_level,
            source_component="custom",
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=0,
            dst_port=0,
            protocol='',
            threat_type="custom",
            signature="",
            description=description,
            confidence=1.0,
            ml_model=None,
            ml_prediction=None,
            ml_probabilities=None,
            suricata_sid=None,
            suricata_category=None,
            action="logged",
            blocked=False,
            metadata=metadata or {}
        )
        
        self._write_event(event)
        
        return event
    
    def _write_event(self, event: UnifiedEvent):
        """Write event to unified log file"""
        try:
            self.stats['total_events'] += 1
            self.stats['threats_by_level'][event.threat_level] += 1
            
            # Write to file
            with open(self.unified_log_path, 'a') as f:
                f.write(json.dumps(asdict(event)) + '\n')
            
            # Call callbacks
            for callback in self.event_callbacks:
                try:
                    callback(event)
                except Exception as e:
                    logger.error(f"Event callback error: {e}")
            
            # Log high severity events
            if event.threat_level in ('critical', 'high'):
                logger.warning(
                    f"[ALERT] [{event.event_type}] {event.threat_level.upper()}: "
                    f"{event.signature} | {event.src_ip} -> {event.dst_ip}"
                )
                
        except Exception as e:
            logger.error(f"Failed to write event: {e}")
    
    def _watch_eve_json(self):
        """Watch Suricata eve.json for new alerts"""
        while not self._stop_event.is_set():
            try:
                if not self.eve_json_path.exists():
                    self._stop_event.wait(2)
                    continue
                
                current_size = self.eve_json_path.stat().st_size
                
                if current_size < self._eve_position:
                    # File rotated
                    self._eve_position = 0
                
                if current_size > self._eve_position:
                    with open(self.eve_json_path, 'r') as f:
                        f.seek(self._eve_position)
                        
                        for line in f:
                            try:
                                event = json.loads(line.strip())
                                # Skip if not a dict (malformed JSON)
                                if not isinstance(event, dict):
                                    continue
                                # Process ALL event types, not just alerts
                                self.log_suricata_event(event)
                            except (json.JSONDecodeError, AttributeError, TypeError):
                                pass
                        
                        self._eve_position = f.tell()
                
                self._stop_event.wait(0.1)
                
            except Exception as e:
                logger.error(f"Eve watcher error: {e}")
                self._stop_event.wait(1)
    
    def _watch_ml_log(self):
        """Watch ML predictions log for new predictions"""
        while not self._stop_event.is_set():
            try:
                if not self.ml_log_path.exists():
                    self._stop_event.wait(2)
                    continue
                
                current_size = self.ml_log_path.stat().st_size
                
                if current_size < self._ml_position:
                    self._ml_position = 0
                
                if current_size > self._ml_position:
                    with open(self.ml_log_path, 'r') as f:
                        f.seek(self._ml_position)
                        
                        for line in f:
                            try:
                                prediction = json.loads(line.strip())
                                if prediction.get('is_threat'):
                                    self.log_ml_prediction(prediction)
                            except json.JSONDecodeError:
                                pass
                        
                        self._ml_position = f.tell()
                
                self._stop_event.wait(0.1)
                
            except Exception as e:
                logger.error(f"ML watcher error: {e}")
                self._stop_event.wait(1)
    
    def start(self):
        """Start the unified logger and file watchers"""
        logger.info("Starting Unified Logger...")
        self._running = True
        self._stop_event.clear()
        
        # Start eve.json watcher
        eve_thread = threading.Thread(target=self._watch_eve_json, daemon=True)
        eve_thread.start()
        
        # Start ML log watcher
        ml_thread = threading.Thread(target=self._watch_ml_log, daemon=True)
        ml_thread.start()
        
        logger.info("Unified Logger started - watching for events")
    
    def stop(self):
        """Stop the unified logger"""
        logger.info("Stopping Unified Logger...")
        self._stop_event.set()
        self._running = False
    
    def get_stats(self) -> Dict[str, Any]:
        """Get logger statistics"""
        return self.stats.copy()
    
    def query_events(
        self,
        event_type: str = None,
        threat_level: str = None,
        src_ip: str = None,
        start_time: str = None,
        end_time: str = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Query unified events with filters"""
        events = []
        
        try:
            with open(self.unified_log_path, 'r') as f:
                for line in f:
                    try:
                        event = json.loads(line.strip())
                        
                        # Apply filters
                        if event_type and event.get('event_type') != event_type:
                            continue
                        if threat_level and event.get('threat_level') != threat_level:
                            continue
                        if src_ip and event.get('src_ip') != src_ip:
                            continue
                        if start_time and event.get('timestamp', '') < start_time:
                            continue
                        if end_time and event.get('timestamp', '') > end_time:
                            continue
                        
                        events.append(event)
                        
                        if len(events) >= limit:
                            break
                            
                    except json.JSONDecodeError:
                        pass
                        
        except FileNotFoundError:
            pass
        
        return events


# Singleton instance
_logger_instance: Optional[UnifiedLogger] = None


def get_unified_logger() -> UnifiedLogger:
    """Get or create the global UnifiedLogger instance"""
    global _logger_instance
    if _logger_instance is None:
        _logger_instance = UnifiedLogger()
    return _logger_instance


def main():
    """Run unified logger standalone"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Unified Security Logger")
    parser.add_argument("--stats", action="store_true", help="Show statistics")
    parser.add_argument("--query", action="store_true", help="Query events")
    parser.add_argument("--type", help="Filter by event type")
    parser.add_argument("--level", help="Filter by threat level")
    parser.add_argument("--limit", type=int, default=10, help="Max events to return")
    args = parser.parse_args()
    
    logger_instance = get_unified_logger()
    
    if args.stats:
        print("\nUnified Logger Statistics:")
        print(json.dumps(logger_instance.get_stats(), indent=2))
    
    elif args.query:
        events = logger_instance.query_events(
            event_type=args.type,
            threat_level=args.level,
            limit=args.limit
        )
        print(f"\nFound {len(events)} events:")
        for event in events:
            print(json.dumps(event, indent=2))
    
    else:
        # Run as service
        logger_instance.start()
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logger_instance.stop()
            print("\nStatistics:")
            print(json.dumps(logger_instance.get_stats(), indent=2))


if __name__ == "__main__":
    main()
