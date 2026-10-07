#!/usr/bin/env python3
"""
SOAR Integration with Inference API

Connects SOAR engine to FastAPI-based ML inference service.
Replaces direct model loading with API calls for Federated Learning support.

Usage:
    from vajra.api.client import InferenceAPIClient
    
    # Create client
    client = InferenceAPIClient(api_url="http://localhost:8001")
    
    # Query predictions
    result = client.predict("sqli", features_dict)
"""

import logging
import requests
from typing import Dict, Any, Optional
from dataclasses import dataclass

logger = logging.getLogger("soar_api_integration")


# API Client

@dataclass
class APIPredictionResult:
    """Result from API prediction"""
    model_name: str
    prediction: int
    confidence: float
    is_threat: bool
    threat_type: str
    probabilities: Optional[list]
    inference_time_ms: float
    

class InferenceAPIClient:
    """Client for ML Inference API"""
    
    def __init__(self, api_url: str = "http://localhost:8001", timeout: int = 5):
        """
        Initialize API client
        
        Args:
            api_url: Base URL of inference API
            timeout: Request timeout in seconds
        """
        self.api_url = api_url.rstrip('/')
        self.timeout = timeout
        self._healthy = False
        
        # Check health on init
        self.check_health()
    
    def check_health(self) -> bool:
        """
        Check if API is healthy
        
        Returns:
            True if API is reachable and healthy
        """
        try:
            response = requests.get(
                f"{self.api_url}/health",
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                data = response.json()
                self._healthy = data.get('status') == 'healthy'
                logger.info(f"API health check: {data}")
                return self._healthy
            else:
                logger.warning(f"API health check failed: {response.status_code}")
                return False
        
        except requests.exceptions.RequestException as e:
            logger.warning(f"API not reachable: {e}")
            self._healthy = False
            return False
    
    def predict(
        self, 
        model_type: str, 
        features: Dict[str, Any],
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        protocol: Optional[str] = None,
        signature: Optional[str] = None
    ) -> Optional[APIPredictionResult]:
        """
        Get prediction from API
        
        Args:
            model_type: Model type (sqli, ddos, xss, general)
            features: Feature dictionary
            src_ip: Source IP (optional)
            dst_ip: Destination IP (optional)
            protocol: Protocol (optional)
            signature: Alert signature (optional)
        
        Returns:
            Prediction result or None if failed
        """
        try:
            # Prepare request
            request_data = {
                "features": features,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": protocol,
                "signature": signature
            }
            
            # Make API call
            response = requests.post(
                f"{self.api_url}/predict/{model_type}",
                json=request_data,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                data = response.json()
                
                return APIPredictionResult(
                    model_name=data['model_name'],
                    prediction=data['prediction'],
                    confidence=data['confidence'],
                    is_threat=data['is_threat'],
                    threat_type=data['threat_type'],
                    probabilities=data.get('probabilities'),
                    inference_time_ms=data['inference_time_ms']
                )
            else:
                logger.error(f"API prediction failed: {response.status_code} - {response.text}")
                return None
        
        except requests.exceptions.Timeout:
            logger.error(f"API request timeout for {model_type}")
            return None
        
        except requests.exceptions.RequestException as e:
            logger.error(f"API request failed for {model_type}: {e}")
            return None
        
        except Exception as e:
            logger.error(f"Unexpected error in API prediction: {e}")
            return None
    
    def list_models(self) -> Optional[list]:
        """
        Get list of available models from API
        
        Returns:
            List of model info dicts or None if failed
        """
        try:
            response = requests.get(
                f"{self.api_url}/models",
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"Failed to list models: {response.status_code}")
                return None
        
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to list models: {e}")
            return None
    
    def reload_models(self) -> bool:
        """
        Trigger model reload on API
        
        Returns:
            True if reload started successfully
        """
        try:
            response = requests.post(
                f"{self.api_url}/reload",
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                logger.info("Model reload initiated")
                return True
            else:
                logger.error(f"Failed to reload models: {response.status_code}")
                return False
        
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to reload models: {e}")
            return False


# SOAR Integration Helpers

def create_features_from_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert Suricata alert to feature dictionary for API
    
    Args:
        alert: Suricata alert dictionary
    
    Returns:
        Feature dictionary suitable for API
    """
    features = {}
    
    # Extract basic fields
    features['src_port'] = alert.get('src_port', 0)
    features['dest_port'] = alert.get('dest_port', 0)
    features['protocol'] = alert.get('proto', 'TCP')
    
    # Protocol encoding
    proto_map = {'TCP': 6, 'UDP': 17, 'ICMP': 1}
    features['protocol_num'] = proto_map.get(features['protocol'], 0)
    
    # Flow features
    flow = alert.get('flow', {})
    features['flow_pkts_toserver'] = flow.get('pkts_toserver', 0)
    features['flow_pkts_toclient'] = flow.get('pkts_toclient', 0)
    features['flow_bytes_toserver'] = flow.get('bytes_toserver', 0)
    features['flow_bytes_toclient'] = flow.get('bytes_toclient', 0)
    
    # Packet info
    packet_info = alert.get('packet_info', {})
    features['packet_length'] = packet_info.get('length', 0)
    
    # Payload
    payload = alert.get('payload', '')
    features['payload_size'] = len(payload)
    features['has_payload'] = len(payload) > 0
    features['payload'] = payload  # Include for model-specific feature extraction
    
    # Alert metadata
    alert_info = alert.get('alert', {})
    features['severity'] = alert_info.get('severity', 3)
    features['signature'] = alert_info.get('signature', '')
    
    return features


def determine_model_type(alert: Dict[str, Any]) -> str:
    """
    Determine which model type to use for an alert
    
    Args:
        alert: Suricata alert dictionary
    
    Returns:
        Model type (sqli, ddos, xss, general)
    """
    signature = alert.get('alert', {}).get('signature', '').upper()
    
    # Check for specific attack types
    if any(kw in signature for kw in ['SQL', 'INJECTION', 'UNION', 'SELECT']):
        return 'sqli'
    elif any(kw in signature for kw in ['DOS', 'DDOS', 'FLOOD', 'SYN']):
        return 'ddos'
    elif any(kw in signature for kw in ['XSS', 'SCRIPT', 'CROSS-SITE']):
        return 'xss'
    else:
        return 'general'


# Example Usage

def example_usage():
    """Example of how to use the API client"""
    
    # Create client
    client = InferenceAPIClient(api_url="http://localhost:8001")
    
    # Check if API is healthy
    if not client.check_health():
        logger.error("API is not healthy!")
        return
    
    # List available models
    models = client.list_models()
    logger.info(f"Available models: {models}")
    
    # Example alert
    sample_alert = {
        'src_ip': '192.168.1.100',
        'dst_ip': '192.168.1.1',
        'src_port': 54321,
        'dest_port': 80,
        'proto': 'TCP',
        'alert': {
            'signature': 'VAJRA DROP SQL Injection Attempt',
            'severity': 1
        },
        'payload': "SELECT * FROM users WHERE id='1' OR '1'='1'",
        'flow': {
            'pkts_toserver': 5,
            'pkts_toclient': 3,
            'bytes_toserver': 1024,
            'bytes_toclient': 512
        }
    }
    
    # Determine model type
    model_type = determine_model_type(sample_alert)
    logger.info(f"Using model type: {model_type}")
    
    # Extract features
    features = create_features_from_alert(sample_alert)
    
    # Get prediction
    result = client.predict(
        model_type=model_type,
        features=features,
        src_ip=sample_alert['src_ip'],
        dst_ip=sample_alert['dst_ip'],
        protocol=sample_alert['proto'],
        signature=sample_alert['alert']['signature']
    )
    
    if result:
        logger.info(f"Prediction: {result.threat_type}")
        logger.info(f"Confidence: {result.confidence:.2f}")
        logger.info(f"Is Threat: {result.is_threat}")
        logger.info(f"Inference Time: {result.inference_time_ms:.2f}ms")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    example_usage()
