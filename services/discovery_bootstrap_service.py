"""Discovery Bootstrap Service - Centralized Management API Discovery

Eliminates Stage 1 rate limiting by prefetching core datasets via Direct Management API
before intent analysis, populating intelligent cache to prevent data loss.

Architecture:
- Single authenticated session for all discovery
- Sequenced API calls with rate limit protection
- Writes to intelligent cache with management-context scoping
- MCP servers remain available as fallback
"""

import time
from typing import Dict, List, Any, Optional
from datetime import datetime
from services.management_api_client import ManagementAPIClient
from services.intelligent_cache import get_cache

def _ts():
    """Return timestamp for logging"""
    return datetime.now().strftime("%H:%M:%S")

class DiscoveryBootstrapService:
    """Centralized discovery service using Direct Management API"""
    
    def __init__(self, management_host: str, port: str, username: str, password: str):
        self.mgmt_client = ManagementAPIClient(management_host, port, username, password)
        self.cache = get_cache()
        self.management_context = f"{management_host}:{port}"
        
    def prefetch_core_datasets(self) -> Dict[str, Any]:
        """
        Prefetch core Management API datasets and populate cache
        
        Returns:
            Dict with discovery results and statistics
        """
        print(f"[Discovery] [{_ts()}] Starting centralized discovery bootstrap...")
        start_time = time.time()
        
        results = {
            'success': True,
            'datasets_fetched': [],
            'datasets_failed': [],
            'cache_entries_written': 0,
            'elapsed_seconds': 0
        }
        
        # Login once for all discovery
        if not self.mgmt_client.login():
            print(f"[Discovery] [{_ts()}] ✗ Failed to login to Management API")
            results['success'] = False
            return results
        
        print(f"[Discovery] [{_ts()}] ✓ Authenticated to Management API")
        
        # Dataset 1: Gateways and Servers (critical for routing context)
        try:
            print(f"[Discovery] [{_ts()}] Fetching gateways and servers...")
            gateways_data = self._fetch_gateways_and_servers()
            if gateways_data:
                self._write_to_cache('gateways_and_servers', gateways_data, ttl=600)
                results['datasets_fetched'].append('gateways_and_servers')
                results['cache_entries_written'] += 1
                print(f"[Discovery] [{_ts()}] ✓ Cached {len(gateways_data)} gateways/servers")
            time.sleep(0.5)  # Rate limit protection
        except Exception as e:
            print(f"[Discovery] [{_ts()}] ⚠️ Failed to fetch gateways: {e}")
            results['datasets_failed'].append('gateways_and_servers')
        
        # Dataset 2: Policy Packages (needed for policy review queries)
        try:
            print(f"[Discovery] [{_ts()}] Fetching policy packages...")
            packages = self.mgmt_client.get_packages()
            if packages:
                self._write_to_cache('policy_packages', packages, ttl=900)
                results['datasets_fetched'].append('policy_packages')
                results['cache_entries_written'] += 1
                print(f"[Discovery] [{_ts()}] ✓ Cached {len(packages)} policy packages")
            time.sleep(0.5)
        except Exception as e:
            print(f"[Discovery] [{_ts()}] ⚠️ Failed to fetch packages: {e}")
            results['datasets_failed'].append('policy_packages')
        
        # Dataset 3: Access Layers (firewall policy structure)
        try:
            print(f"[Discovery] [{_ts()}] Fetching access layers...")
            layers = self._fetch_access_layers()
            if layers:
                self._write_to_cache('access_layers', layers, ttl=900)
                results['datasets_fetched'].append('access_layers')
                results['cache_entries_written'] += 1
                print(f"[Discovery] [{_ts()}] ✓ Cached {len(layers)} access layers")
            time.sleep(0.5)
        except Exception as e:
            print(f"[Discovery] [{_ts()}] ⚠️ Failed to fetch access layers: {e}")
            results['datasets_failed'].append('access_layers')
        
        # Dataset 4: HTTPS Inspection Layers (if available)
        try:
            print(f"[Discovery] [{_ts()}] Fetching HTTPS inspection layers...")
            https_layers = self._fetch_https_layers()
            if https_layers:
                self._write_to_cache('https_inspection_layers', https_layers, ttl=900)
                results['datasets_fetched'].append('https_inspection_layers')
                results['cache_entries_written'] += 1
                print(f"[Discovery] [{_ts()}] ✓ Cached {len(https_layers)} HTTPS layers")
            else:
                print(f"[Discovery] [{_ts()}] ℹ️ No HTTPS inspection layers found (may not be configured)")
            time.sleep(0.5)
        except Exception as e:
            print(f"[Discovery] [{_ts()}] ℹ️ HTTPS layers not available: {e}")
            results['datasets_failed'].append('https_inspection_layers')
        
        # Dataset 5: VPN Communities (already handled by management_api_client caching)
        try:
            print(f"[Discovery] [{_ts()}] Fetching VPN communities...")
            vpn_star = self.mgmt_client.get_vpn_communities_star()
            vpn_meshed = self.mgmt_client.get_vpn_communities_meshed()
            vpn_remote = self.mgmt_client.get_vpn_communities_remote_access()
            total_vpn = len(vpn_star) + len(vpn_meshed) + len(vpn_remote)
            if total_vpn > 0:
                results['datasets_fetched'].append('vpn_communities')
                print(f"[Discovery] [{_ts()}] ✓ Cached {total_vpn} VPN communities")
        except Exception as e:
            print(f"[Discovery] [{_ts()}] ⚠️ Failed to fetch VPN communities: {e}")
            results['datasets_failed'].append('vpn_communities')
        
        # Logout
        self.mgmt_client.logout()
        
        results['elapsed_seconds'] = round(time.time() - start_time, 2)
        print(f"[Discovery] [{_ts()}] ✓ Discovery complete: {len(results['datasets_fetched'])} datasets cached in {results['elapsed_seconds']}s")
        
        return results
    
    def _fetch_gateways_and_servers(self) -> List[Dict[str, Any]]:
        """Fetch all gateways and servers"""
        response = self.mgmt_client._call_api('show-gateways-and-servers', {
            'limit': 500,
            'details-level': 'standard'
        })
        
        if response and 'objects' in response:
            return response['objects']
        return []
    
    def _fetch_access_layers(self) -> List[Dict[str, Any]]:
        """Fetch all access control layers"""
        response = self.mgmt_client._call_api('show-access-layers', {
            'limit': 100,
            'details-level': 'standard'
        })
        
        if response and 'access-layers' in response:
            return response['access-layers']
        return []
    
    def _fetch_https_layers(self) -> List[Dict[str, Any]]:
        """Fetch HTTPS inspection layers (may not exist in all environments)"""
        response = self.mgmt_client._call_api('show-https-layers', {
            'limit': 100,
            'details-level': 'standard'
        })
        
        if response and 'https-layers' in response:
            return response['https-layers']
        return []
    
    def _write_to_cache(self, data_type: str, data: Any, ttl: int = 600):
        """Write discovery data to intelligent cache with management-context scoping"""
        cache_key = f"{self.management_context}:{data_type}"
        
        self.cache._cache[cache_key] = {
            'data': data,
            'timestamp': time.time(),
            'ttl': ttl,
            'data_type': data_type,
            'gateway': self.management_context,
            'source': 'discovery_bootstrap'
        }
        
        print(f"[Discovery] [{_ts()}] 💾 Wrote '{data_type}' to cache (TTL: {ttl}s)")


def should_run_discovery(mcp_manager) -> bool:
    """
    Check if discovery bootstrap should run by checking cache freshness
    
    Args:
        mcp_manager: MCPManager instance with server configurations
        
    Returns:
        True if discovery should run (cache cold/stale), False if cache is warm
    """
    all_servers = mcp_manager.get_all_servers()
    
    if 'quantum-management' not in all_servers:
        return False
    
    server_config = all_servers['quantum-management']
    server_env = server_config.get('env', {})
    
    host = server_env.get('MANAGEMENT_HOST', '')
    port = server_env.get('PORT', '443')
    management_context = f"{host}:{port}"
    
    # Check if core datasets exist in cache and are fresh
    cache = get_cache()
    core_datasets = ['gateways_and_servers', 'policy_packages', 'access_layers']
    
    for dataset in core_datasets:
        cache_key = f"{management_context}:{dataset}"
        if cache_key not in cache._cache:
            print(f"[Discovery] [{_ts()}] Cache cold: '{dataset}' not found")
            return True
        
        # Check if data is stale
        entry = cache._cache[cache_key]
        age = time.time() - entry['timestamp']
        if age > entry['ttl']:
            print(f"[Discovery] [{_ts()}] Cache stale: '{dataset}' expired ({int(age)}s old, TTL: {entry['ttl']}s)")
            return True
    
    print(f"[Discovery] [{_ts()}] Cache warm: All core datasets fresh")
    return False


def run_discovery_bootstrap(mcp_manager) -> Optional[Dict[str, Any]]:
    """
    Run discovery bootstrap if quantum-management is configured
    
    Args:
        mcp_manager: MCPManager instance with server configurations
        
    Returns:
        Discovery results dict or None if not available
    """
    all_servers = mcp_manager.get_all_servers()
    
    if 'quantum-management' not in all_servers:
        print(f"[Discovery] [{_ts()}] quantum-management not configured, skipping bootstrap")
        return None
    
    server_config = all_servers['quantum-management']
    server_env = server_config.get('env', {})
    
    host = server_env.get('MANAGEMENT_HOST', '')
    port = server_env.get('PORT', '443')
    username = server_env.get('USERNAME', '')
    password = server_env.get('PASSWORD', '')
    
    if not all([host, username, password]):
        print(f"[Discovery] [{_ts()}] Missing Management API credentials, skipping bootstrap")
        return None
    
    try:
        service = DiscoveryBootstrapService(host, port, username, password)
        return service.prefetch_core_datasets()
    except Exception as e:
        print(f"[Discovery] [{_ts()}] ✗ Bootstrap failed: {e}")
        import traceback
        traceback.print_exc()
        return None
