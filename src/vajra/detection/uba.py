#!/usr/bin/env python3
"""
UBA Engine - User Behavior Analytics Engine
Tracks user behavior patterns and detects insider threats

Integrates with SOAR engine to:
- Monitor user activity patterns (logons, file transfers, USB access)
- Detect anomalous behavior (after-hours access, unusual file transfers)
- Generate alerts for suspicious user behavior
- Enhance ML-based threat detection with behavioral analytics

Works alongside ML models to provide comprehensive insider threat detection.
"""

import json
import logging
import threading
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, asdict

# Create logs directory if it doesn't exist FIRST
try:
    Path("logs").mkdir(exist_ok=True)
    # Make sure it's writable
    Path("logs").chmod(0o777)
except Exception as e:
    print(f"Warning: Could not create/chmod logs directory: {e}")

# Configure logging with error handling
log_handlers = [logging.StreamHandler()]
try:
    log_file = Path("logs/uba_engine.log")
    # Try to create/open the log file
    log_file.touch(exist_ok=True)
    log_handlers.append(logging.FileHandler(str(log_file)))
except Exception as e:
    # Fallback to console-only logging if file logging fails
    print(f"Warning: Could not create log file: {e}")

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=log_handlers
)

logger = logging.getLogger("uba_engine")

# ML model integration
try:
    from vajra.ml.manager import get_model_manager, MLModelManager
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False


@dataclass
class UserProfile:
    """User behavior profile"""
    user_id: str
    logon_count: int = 0
    night_logons: int = 0
    usb_transfers: int = 0
    file_operations: int = 0
    external_emails: int = 0
    data_uploads: int = 0
    device_connections: int = 0
    last_update: float = 0.0
    total_events: int = 0
    risk_score: float = 0.0
    

@dataclass
class UBAAlert:
    """UBA-generated alert"""
    timestamp: str
    user_id: str
    alert_type: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    threat_indicator: str
    profile_snapshot: Dict[str, Any]
    confidence: float


class UBAEngine:
    """User Behavior Analytics Engine for insider threat detection"""
    
    def __init__(self):
        self.user_profiles = defaultdict(lambda: UserProfile(user_id=""))
        self.model_manager = None
        self.alerts_generated = 0
        self.users_monitored = 0
        self.running = False
        self.lock = threading.Lock()
        self.uba_alerts_file = Path("logs/uba_alerts.json")
        self.model_manager_enabled = False
        
        if ML_AVAILABLE:
            try:
                self.model_manager = get_model_manager()
                self.model_manager_enabled = True
                logger.info("ML Model Manager loaded for UBA")
            except Exception as e:
                logger.warning(f"Could not load ML Model Manager: {e}")
        
        logger.info("UBA Engine initialized")
    
    def update_user_state(self, log: Dict[str, Any]) -> Optional[UBAAlert]:
        """
        Updates the running tally for a user based on a new log event.
        Returns an alert if suspicious behavior is detected.
        """
        user_id = log.get('user_id') or log.get('user')
        if not user_id:
            return None
        
        with self.lock:
            # Initialize profile if needed
            if user_id not in self.user_profiles:
                self.user_profiles[user_id] = UserProfile(user_id=user_id)
                self.users_monitored += 1
            
            profile = self.user_profiles[user_id]
            event_type = log.get('event_type', '').lower()
            
            # Update features based on log content
            if event_type == 'logon':
                profile.logon_count += 1
                hour = self._get_hour_from_timestamp(log.get('timestamp'))
                
                # Mark after-hours logon (after 8 PM or before 6 AM)
                if hour < 6 or hour >= 20:
                    profile.night_logons += 1
                    logger.info(f"After-hours logon detected for {user_id} at {hour}:00")
            
            elif event_type == 'file' or event_type == 'file_transfer':
                profile.file_operations += 1
                
                # USB transfer detection
                if log.get('destination') == 'usb' or 'usb' in str(log).lower():
                    profile.usb_transfers += 1
                    logger.info(f"USB transfer detected for {user_id}")
                
                # Data upload detection
                if log.get('data_size', 0) > 1024 * 1024 or log.get('is_upload'):
                    profile.data_uploads += 1
                    logger.info(f"Large data upload detected for {user_id}")
            
            elif event_type == 'email':
                # External email detection
                if log.get('is_external'):
                    profile.external_emails += 1
                    logger.info(f"External email activity detected for {user_id}")
            
            elif event_type == 'device':
                # Device connection tracking
                if log.get('device_type'):
                    profile.device_connections += 1
                    logger.info(f"Device connection detected for {user_id}: {log.get('device_type')}")
            
            profile.total_events += 1
            profile.last_update = time.time()
            
            # Calculate risk score
            profile.risk_score = self._calculate_risk_score(profile)
            
            # Run inference on profile
            alert = self._run_inference(profile, log)
            
            return alert
    
    def _get_hour_from_timestamp(self, timestamp_str: str) -> int:
        """Extract hour from timestamp string"""
        try:
            if timestamp_str:
                dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                return dt.hour
        except:
            pass
        return datetime.now(timezone.utc).hour
    
    def _calculate_risk_score(self, profile: UserProfile) -> float:
        """
        Calculate risk score based on user profile
        Higher score = more suspicious behavior
        Range: 0.0 to 1.0
        """
        risk = 0.0
        
        # Night logons increase risk
        if profile.night_logons > 0:
            risk += min(0.25, profile.night_logons * 0.1)
        
        # USB transfers increase risk significantly
        if profile.usb_transfers > 0:
            risk += min(0.30, profile.usb_transfers * 0.15)
        
        # Large data uploads increase risk
        if profile.data_uploads > 0:
            risk += min(0.25, profile.data_uploads * 0.1)
        
        # External emails increase risk
        if profile.external_emails > 0:
            risk += min(0.20, profile.external_emails * 0.05)
        
        # Multiple device connections increase risk
        if profile.device_connections > 2:
            risk += min(0.15, (profile.device_connections - 2) * 0.05)
        
        return min(1.0, risk)
    
    def _run_inference(self, profile: UserProfile, log: Dict[str, Any]) -> Optional[UBAAlert]:
        """
        Run ML inference on user profile to detect threats.
        Generates alert if high-risk behavior is detected.
        """
        # Check thresholds for automatic alerts
        
        # High-risk combination: Night logon + USB transfer
        if profile.night_logons > 0 and profile.usb_transfers > 0:
            alert = UBAAlert(
                timestamp=datetime.now(timezone.utc).isoformat(),
                user_id=profile.user_id,
                alert_type="SUSPICIOUS_BEHAVIOR_NIGHT_USB",
                severity="HIGH",
                threat_indicator="After-hours access combined with USB transfer",
                profile_snapshot=self._profile_to_dict(profile),
                confidence=0.85
            )
            self.alerts_generated += 1
            logger.warning(f"[ALERT] HIGH RISK: {profile.user_id} - Night logon + USB transfer")
            self._save_alert(alert)
            return alert
        
        # High-risk: Large data uploads during off-hours
        if profile.data_uploads > 0 and profile.night_logons > 0:
            alert = UBAAlert(
                timestamp=datetime.now(timezone.utc).isoformat(),
                user_id=profile.user_id,
                alert_type="DATA_EXFIL_RISK",
                severity="CRITICAL",
                threat_indicator="Large data uploads during off-hours",
                profile_snapshot=self._profile_to_dict(profile),
                confidence=0.90
            )
            self.alerts_generated += 1
            logger.error(f"[ALERT] CRITICAL: {profile.user_id} - Potential data exfiltration")
            self._save_alert(alert)
            return alert
        
        # Medium risk: Multiple USB transfers
        if profile.usb_transfers > 2:
            alert = UBAAlert(
                timestamp=datetime.now(timezone.utc).isoformat(),
                user_id=profile.user_id,
                alert_type="REPEATED_USB_ACTIVITY",
                severity="MEDIUM",
                threat_indicator=f"Multiple USB transfers ({profile.usb_transfers})",
                profile_snapshot=self._profile_to_dict(profile),
                confidence=0.75
            )
            self.alerts_generated += 1
            logger.warning(f"[WARN] MEDIUM: {profile.user_id} - Repeated USB activity")
            self._save_alert(alert)
            return alert
        
        # Use ML model if available
        if self.model_manager_enabled and self.model_manager:
            try:
                ml_features = self._extract_ml_features(profile)
                predictions = self.model_manager.predict_all(ml_features, data_type="behavioral")
                
                # Check for high-confidence threats
                for model_name, prediction in predictions.items():
                    if prediction and prediction.is_threat and prediction.confidence >= 0.75:
                        alert = UBAAlert(
                            timestamp=datetime.now(timezone.utc).isoformat(),
                            user_id=profile.user_id,
                            alert_type=f"ML_INSIDER_THREAT_{prediction.threat_type}",
                            severity="HIGH" if prediction.confidence >= 0.85 else "MEDIUM",
                            threat_indicator=f"ML detected: {prediction.threat_type}",
                            profile_snapshot=self._profile_to_dict(profile),
                            confidence=prediction.confidence
                        )
                        self.alerts_generated += 1
                        logger.warning(f"ML ALERT: {profile.user_id} - {prediction.threat_type} ({prediction.confidence:.2%})")
                        self._save_alert(alert)
                        return alert
            except Exception as e:
                logger.debug(f"ML inference error: {e}")
        
        return None
    
    def _extract_ml_features(self, profile: UserProfile) -> Dict[str, Any]:
        """Extract features for ML model from user profile"""
        now = datetime.now(timezone.utc)
        
        return {
            'user_id': profile.user_id,
            'logon_count': profile.logon_count,
            'night_logons': profile.night_logons,
            'usb_transfers': profile.usb_transfers,
            'file_operations': profile.file_operations,
            'external_emails': profile.external_emails,
            'data_uploads': profile.data_uploads,
            'device_connections': profile.device_connections,
            'total_events': profile.total_events,
            'hour_of_day': now.hour,
            'day_of_week': now.weekday(),
            'is_after_hours': 1 if (now.hour < 6 or now.hour >= 20) else 0,
            'is_weekend': 1 if now.weekday() >= 5 else 0,
            'risk_score': profile.risk_score
        }
    
    def _profile_to_dict(self, profile: UserProfile) -> Dict[str, Any]:
        """Convert user profile to dictionary"""
        return {
            'user_id': profile.user_id,
            'logon_count': profile.logon_count,
            'night_logons': profile.night_logons,
            'usb_transfers': profile.usb_transfers,
            'file_operations': profile.file_operations,
            'external_emails': profile.external_emails,
            'data_uploads': profile.data_uploads,
            'device_connections': profile.device_connections,
            'total_events': profile.total_events,
            'risk_score': profile.risk_score,
            'last_update': profile.last_update
        }
    
    def _save_alert(self, alert: UBAAlert):
        """Save alert to file"""
        try:
            alert_dict = asdict(alert)
            
            # Append to alerts file
            if self.uba_alerts_file.exists():
                with open(self.uba_alerts_file, 'a') as f:
                    f.write(json.dumps(alert_dict) + '\n')
            else:
                with open(self.uba_alerts_file, 'w') as f:
                    f.write(json.dumps(alert_dict) + '\n')
        except Exception as e:
            logger.error(f"Error saving alert: {e}")
    
    def get_user_profile(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get current profile for a user"""
        with self.lock:
            if user_id in self.user_profiles:
                return self._profile_to_dict(self.user_profiles[user_id])
        return None
    
    def get_all_profiles(self) -> Dict[str, Dict[str, Any]]:
        """Get all user profiles"""
        with self.lock:
            return {
                user_id: self._profile_to_dict(profile)
                for user_id, profile in self.user_profiles.items()
            }
    
    def get_high_risk_users(self, threshold: float = 0.7) -> List[Dict[str, Any]]:
        """Get users with risk score above threshold"""
        with self.lock:
            high_risk = [
                self._profile_to_dict(profile)
                for profile in self.user_profiles.values()
                if profile.risk_score >= threshold
            ]
        return sorted(high_risk, key=lambda x: x['risk_score'], reverse=True)
    
    def reset_user_profile(self, user_id: str):
        """Reset profile for a user (e.g., after incident resolution)"""
        with self.lock:
            if user_id in self.user_profiles:
                self.user_profiles[user_id] = UserProfile(user_id=user_id)
                logger.info(f"Profile reset for user: {user_id}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get UBA engine statistics"""
        with self.lock:
            return {
                'users_monitored': self.users_monitored,
                'alerts_generated': self.alerts_generated,
                'total_events_processed': sum(
                    p.total_events for p in self.user_profiles.values()
                ),
                'high_risk_users': len(self.get_high_risk_users()),
                'ml_model_enabled': self.model_manager_enabled
            }
    
    def shutdown(self):
        """Shutdown UBA engine"""
        logger.info(f"UBA Engine shutdown. Stats: {self.get_stats()}")


# Global UBA engine instance
_uba_instance = None


def get_uba_engine() -> UBAEngine:
    """Get or create global UBA engine instance"""
    global _uba_instance
    if _uba_instance is None:
        _uba_instance = UBAEngine()
    return _uba_instance


# Example usage / Testing
if __name__ == "__main__":
    uba = get_uba_engine()
    
    print("\n=== UBA Engine Test ===\n")
    
    # Simulate event stream
    events = [
        {"user_id": "alice", "event_type": "logon", "timestamp": "2025-12-07T14:00:00Z"},
        {"user_id": "alice", "event_type": "file", "destination": "local", "timestamp": "2025-12-07T14:30:00Z"},
        
        {"user_id": "bob", "event_type": "logon", "timestamp": "2025-12-07T23:00:00Z"},  # After-hours
        {"user_id": "bob", "event_type": "file", "destination": "usb", "timestamp": "2025-12-07T23:05:00Z"},  # USB
        
        {"user_id": "charlie", "event_type": "logon", "timestamp": "2025-12-07T22:00:00Z"},  # After-hours
        {"user_id": "charlie", "event_type": "file", "destination": "usb", "data_size": 5368709120, "is_upload": True, "timestamp": "2025-12-07T22:15:00Z"},  # Large upload
    ]
    
    for event in events:
        alert = uba.update_user_state(event)
        if alert:
            print(f"\n[WARN] ALERT: {json.dumps(asdict(alert), indent=2)}")
    
    print("\n=== User Profiles ===")
    for user_id, profile in uba.get_all_profiles().items():
        print(f"\n{user_id}: Risk={profile['risk_score']:.2f}")
        print(f"  - Logons: {profile['logon_count']} (Night: {profile['night_logons']})")
        print(f"  - USB: {profile['usb_transfers']}, Data Uploads: {profile['data_uploads']}")
    
    print("\n=== High Risk Users ===")
    for user in uba.get_high_risk_users():
        print(f"{user['user_id']}: {user['risk_score']:.2f}")
    
    print("\n=== Stats ===")
    print(json.dumps(uba.get_stats(), indent=2))
