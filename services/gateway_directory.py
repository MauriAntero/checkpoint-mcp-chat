"""
Simple Gateway Cache

Caches discovered gateways from Check Point Management API (name → IP mapping)
to enable automatic SSH credential sharing when admin consents.
"""

import json
from pathlib import Path
from typing import Dict, List, Optional, Any


class GatewayDirectory:
    """Simple gateway name → IP cache for credential sharing"""
    
    def __init__(self, data_dir: str = "./data"):
        self.data_dir = Path(data_dir)
        self.cache_file = self.data_dir / "gateway_cache.json"
        
        # Simple cache: {gateway_name: gateway_ip}
        self.gateways: Dict[str, str] = {}
        
        # Load existing cache
        self._load_cache()
    
    def _load_cache(self):
        """Load gateway cache from disk"""
        if self.cache_file.exists():
            try:
                with open(self.cache_file, 'r') as f:
                    self.gateways = json.load(f)
                    print(f"[GatewayDirectory] Loaded {len(self.gateways)} gateways from cache")
            except Exception as e:
                print(f"[GatewayDirectory] Error loading cache: {e}")
        else:
            self.data_dir.mkdir(parents=True, exist_ok=True)
    
    def _save_cache(self):
        """Save gateway cache to disk"""
        try:
            with open(self.cache_file, 'w') as f:
                json.dump(self.gateways, f, indent=2)
        except Exception as e:
            print(f"[GatewayDirectory] Error saving cache: {e}")
    
    def update_from_management_api(self, gateways_data: List[Dict[str, Any]]):
        """Update gateway cache from management API response
        
        Args:
            gateways_data: List of gateway objects from show_gateways_and_servers
        """
        updated_count = 0
        
        for gw in gateways_data:
            # Skip non-dict items (defensive check)
            if not isinstance(gw, dict):
                continue
                
            # Only process actual gateway objects (exclude interoperable-device)
            if gw.get('type') == 'interoperable-device':
                continue
            
            name = gw.get('name')
            ip = gw.get('ipv4-address')
            
            if name and ip:
                self.gateways[name] = ip
                updated_count += 1
        
        if updated_count > 0:
            self._save_cache()
            print(f"[GatewayDirectory] Updated {updated_count} gateways from management API")
    
    def get_gateway_ip(self, gateway_name: str) -> Optional[str]:
        """Get IP address for a gateway
        
        Args:
            gateway_name: Name of the gateway
            
        Returns:
            IP address if found, None otherwise
        """
        return self.gateways.get(gateway_name)
    
    def get_gateway_name(self, gateway_ip: str) -> Optional[str]:
        """Get gateway name from IP address (reverse lookup)
        
        Args:
            gateway_ip: IP address of the gateway
            
        Returns:
            Gateway name if found, None otherwise
        """
        for name, ip in self.gateways.items():
            if ip == gateway_ip:
                return name
        return None
    
    def get_all_gateways(self) -> Dict[str, str]:
        """Get all cached gateways
        
        Returns:
            Dict of {gateway_name: gateway_ip}
        """
        return self.gateways.copy()
