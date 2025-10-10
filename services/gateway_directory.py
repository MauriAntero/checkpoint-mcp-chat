"""
Gateway Directory Service
Manages discovered gateways from management MCP and enables automatic credential sharing.
"""

import json
from datetime import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path


class GatewayDirectory:
    """
    Manages a cache of discovered gateways from Check Point Management API.
    Enables automatic credential sharing for unconfigured gateways.
    """
    
    def __init__(self, cache_file: str = "data/gateway_directory.json"):
        self.cache_file = Path(cache_file)
        self.gateways: Dict[str, Dict[str, Any]] = {}
        self.enabled = False  # Requires admin consent
        self.template_gateway = None  # Gateway to clone credentials from
        self._load_cache()
    
    def _load_cache(self):
        """Load gateway directory from cache file"""
        if self.cache_file.exists():
            try:
                with open(self.cache_file, 'r') as f:
                    data = json.load(f)
                    self.gateways = data.get('gateways', {})
                    self.enabled = data.get('enabled', False)
                    self.template_gateway = data.get('template_gateway')
                    print(f"[GatewayDirectory] Loaded {len(self.gateways)} gateways from cache")
            except Exception as e:
                print(f"[GatewayDirectory] Failed to load cache: {e}")
                self.gateways = {}
    
    def _save_cache(self):
        """Save gateway directory to cache file"""
        try:
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.cache_file, 'w') as f:
                json.dump({
                    'gateways': self.gateways,
                    'enabled': self.enabled,
                    'template_gateway': self.template_gateway,
                    'last_updated': datetime.now().isoformat()
                }, f, indent=2)
            print(f"[GatewayDirectory] Saved {len(self.gateways)} gateways to cache")
        except Exception as e:
            print(f"[GatewayDirectory] Failed to save cache: {e}")
    
    def enable(self, template_gateway_name: str):
        """Enable automatic credential sharing with admin consent
        
        Args:
            template_gateway_name: Name of configured gateway to clone credentials from
        """
        self.enabled = True
        self.template_gateway = template_gateway_name
        self._save_cache()
        print(f"[GatewayDirectory] Enabled credential sharing using '{template_gateway_name}' as template")
    
    def disable(self):
        """Disable automatic credential sharing"""
        self.enabled = False
        self.template_gateway = None
        self._save_cache()
        print(f"[GatewayDirectory] Disabled credential sharing")
    
    def update_from_management_api(self, gateways_data: List[Dict[str, Any]]):
        """Update gateway directory from management API response
        
        Args:
            gateways_data: List of gateway objects from show_gateways_and_servers
        """
        timestamp = datetime.now().isoformat()
        
        for gw in gateways_data:
            gateway_name = gw.get('name')
            if not gateway_name:
                continue
            
            # Extract gateway information
            gateway_info = {
                'name': gateway_name,
                'ip_address': gw.get('ipv4-address', gw.get('ipv4_address')),
                'type': gw.get('type', 'gateway'),
                'domain': gw.get('domain', {}).get('name') if isinstance(gw.get('domain'), dict) else None,
                'uid': gw.get('uid'),
                'last_seen': timestamp,
                'trust_score': self.gateways.get(gateway_name, {}).get('trust_score', 100),  # Preserve score
                'shared_credential_attempts': self.gateways.get(gateway_name, {}).get('shared_credential_attempts', 0),
                'shared_credential_successes': self.gateways.get(gateway_name, {}).get('shared_credential_successes', 0),
                'shared_credential_failures': self.gateways.get(gateway_name, {}).get('shared_credential_failures', 0),
                'credential_source': self.gateways.get(gateway_name, {}).get('credential_source', 'none')
            }
            
            self.gateways[gateway_name] = gateway_info
        
        self._save_cache()
        print(f"[GatewayDirectory] Updated directory with {len(gateways_data)} gateways")
    
    def get_gateway(self, gateway_name: str) -> Optional[Dict[str, Any]]:
        """Get gateway information by name
        
        Args:
            gateway_name: Name of the gateway
            
        Returns:
            Gateway information dict or None if not found
        """
        return self.gateways.get(gateway_name)
    
    def gateway_exists(self, gateway_name: str) -> bool:
        """Check if gateway exists in directory
        
        Args:
            gateway_name: Name of the gateway
            
        Returns:
            True if gateway exists, False otherwise
        """
        return gateway_name in self.gateways
    
    def can_use_shared_credentials(self, gateway_name: str) -> bool:
        """Check if gateway can use shared credentials
        
        Args:
            gateway_name: Name of the gateway
            
        Returns:
            True if gateway can use shared credentials, False otherwise
        """
        if not self.enabled:
            return False
        
        if not self.template_gateway:
            return False
        
        # Validate template gateway still exists
        if not self.gateway_exists(self.template_gateway):
            print(f"[GatewayDirectory] Template gateway '{self.template_gateway}' not found in directory")
            return False
        
        if not self.gateway_exists(gateway_name):
            return False
        
        # SECURITY: Stop credential sharing after FIRST failure (no retries)
        # This prevents brute-force attempts on sensitive gateways
        gateway = self.gateways[gateway_name]
        if gateway.get('shared_credential_failures', 0) > 0:
            print(f"[GatewayDirectory] Gateway '{gateway_name}' has failed credential attempts ({gateway.get('shared_credential_failures')}), blocked for security")
            return False
        
        return True
    
    def record_credential_attempt(self, gateway_name: str, success: bool, source_gateway: str):
        """Record the result of a shared credential attempt
        
        Args:
            gateway_name: Target gateway name
            success: Whether the attempt succeeded
            source_gateway: Gateway that provided the credentials
        """
        if gateway_name not in self.gateways:
            return
        
        gateway = self.gateways[gateway_name]
        gateway['shared_credential_attempts'] = gateway.get('shared_credential_attempts', 0) + 1
        gateway['credential_source'] = source_gateway
        
        if success:
            gateway['shared_credential_successes'] = gateway.get('shared_credential_successes', 0) + 1
            # Increase trust score (max 100)
            gateway['trust_score'] = min(100, gateway.get('trust_score', 100) + 10)
            print(f"[GatewayDirectory] ✓ Shared credentials worked for '{gateway_name}' (trust: {gateway['trust_score']})")
        else:
            gateway['shared_credential_failures'] = gateway.get('shared_credential_failures', 0) + 1
            # Decrease trust score
            gateway['trust_score'] = max(0, gateway.get('trust_score', 100) - 20)
            print(f"[GatewayDirectory] ✗ Shared credentials failed for '{gateway_name}' (trust: {gateway['trust_score']})")
        
        gateway['last_attempt'] = datetime.now().isoformat()
        self._save_cache()
    
    def get_all_gateways(self) -> List[Dict[str, Any]]:
        """Get all discovered gateways
        
        Returns:
            List of gateway information dicts
        """
        return list(self.gateways.values())
    
    def get_gateways_with_shared_credentials(self) -> List[Dict[str, Any]]:
        """Get gateways that are using shared credentials
        
        Returns:
            List of gateways using shared credentials
        """
        return [
            gw for gw in self.gateways.values()
            if gw.get('shared_credential_attempts', 0) > 0 and gw.get('credential_source') != 'none'
        ]
    
    def get_status(self) -> Dict[str, Any]:
        """Get current directory status
        
        Returns:
            Status information dict
        """
        return {
            'enabled': self.enabled,
            'template_gateway': self.template_gateway,
            'total_gateways': len(self.gateways),
            'gateways_with_shared_creds': len(self.get_gateways_with_shared_credentials()),
            'gateways': self.get_all_gateways()
        }
