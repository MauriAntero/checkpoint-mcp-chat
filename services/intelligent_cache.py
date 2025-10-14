"""
Intelligent Component-Level Cache with Gateway Awareness

Provides smart caching of CheckPoint data components that can be reused
across different queries and tasks. Separates gateway-specific data from
global management data.

Features:
- Gateway-aware: Separates data by gateway for multi-firewall networks
- Component-level: Caches individual data types for maximum reuse
- Intelligent TTL: Different expiration times based on data stability
- Lightweight: In-memory only, no database required
"""

import time
from typing import Any, Dict, Optional, Callable
from datetime import datetime


class IntelligentCache:
    """Gateway-aware intelligent cache for CheckPoint data"""
    
    # Data type configurations with TTLs and characteristics
    DATA_TYPES = {
        # Gateway-specific data (per firewall/gateway)
        'firewall_rules': {'ttl': 300, 'scope': 'gateway', 'stable': False},
        'nat_rules': {'ttl': 300, 'scope': 'gateway', 'stable': False},
        'https_inspection': {'ttl': 300, 'scope': 'gateway', 'stable': False},
        'threat_prevention': {'ttl': 300, 'scope': 'gateway', 'stable': False},
        'routing_table': {'ttl': 600, 'scope': 'gateway', 'stable': True},
        'interface_config': {'ttl': 600, 'scope': 'gateway', 'stable': True},
        'gateway_stats': {'ttl': 60, 'scope': 'gateway', 'stable': False},
        
        # Global data (management-level, applies to all gateways)
        'vpn_communities': {'ttl': 600, 'scope': 'global', 'stable': True},
        'threat_profiles': {'ttl': 600, 'scope': 'global', 'stable': True},
        'network_objects': {'ttl': 600, 'scope': 'global', 'stable': True},
        'network_topology': {'ttl': 900, 'scope': 'global', 'stable': True},
        'all_gateways': {'ttl': 600, 'scope': 'global', 'stable': True},
        'policy_packages': {'ttl': 600, 'scope': 'global', 'stable': True},
        'access_layers': {'ttl': 600, 'scope': 'global', 'stable': True},
    }
    
    def __init__(self):
        """Initialize empty cache"""
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._stats = {
            'hits': 0,
            'misses': 0,
            'evictions': 0,
            'total_fetches': 0
        }
    
    def _get_cache_key(self, data_type: str, gateway_name: Optional[str] = None, management_context: Optional[str] = None) -> str:
        """
        Build cache key with gateway and management context
        
        Args:
            data_type: Type of data (e.g., 'firewall_rules', 'vpn_communities')
            gateway_name: Gateway name for gateway-specific data, None for global
            management_context: Management server identifier (host:port or domain) to prevent cross-domain cache pollution
            
        Returns:
            Cache key string
        """
        config = self.DATA_TYPES.get(data_type, {'scope': 'global'})
        
        # Management context prefix (to separate different management servers/domains)
        mgmt_prefix = management_context or 'default'
        
        if config['scope'] == 'gateway':
            if not gateway_name:
                raise ValueError(f"Gateway name required for gateway-specific data type: {data_type}")
            return f"{mgmt_prefix}:{gateway_name}:{data_type}"
        else:
            # Global data - but still scoped to management server
            return f"{mgmt_prefix}:global:{data_type}"
    
    def get(self, data_type: str, gateway_name: Optional[str] = None, management_context: Optional[str] = None) -> Optional[Any]:
        """
        Get data from cache if available and not expired
        
        Args:
            data_type: Type of data to retrieve
            gateway_name: Gateway name for gateway-specific data
            management_context: Management server identifier
            
        Returns:
            Cached data if available and fresh, None otherwise
        """
        cache_key = self._get_cache_key(data_type, gateway_name, management_context)
        
        if cache_key not in self._cache:
            self._stats['misses'] += 1
            return None
        
        entry = self._cache[cache_key]
        now = time.time()
        
        # Check if expired
        if now - entry['timestamp'] > entry['ttl']:
            # Expired - remove from cache
            del self._cache[cache_key]
            self._stats['evictions'] += 1
            self._stats['misses'] += 1
            return None
        
        # Cache hit
        self._stats['hits'] += 1
        return entry['data']
    
    def set(self, data_type: str, data: Any, gateway_name: Optional[str] = None, management_context: Optional[str] = None, custom_ttl: Optional[int] = None):
        """
        Store data in cache
        
        Args:
            data_type: Type of data being cached
            data: The data to cache
            gateway_name: Gateway name for gateway-specific data
            management_context: Management server identifier
            custom_ttl: Optional custom TTL override (seconds)
        """
        cache_key = self._get_cache_key(data_type, gateway_name, management_context)
        config = self.DATA_TYPES.get(data_type, {'ttl': 300})
        
        ttl = custom_ttl if custom_ttl is not None else config['ttl']
        
        self._cache[cache_key] = {
            'data': data,
            'timestamp': time.time(),
            'ttl': ttl,
            'data_type': data_type,
            'gateway': gateway_name
        }
    
    def get_or_fetch(self, data_type: str, fetch_func: Callable, gateway_name: Optional[str] = None, 
                     management_context: Optional[str] = None, custom_ttl: Optional[int] = None) -> Any:
        """
        Get from cache or fetch if not available
        
        Args:
            data_type: Type of data
            fetch_func: Function to call if cache miss (should return data)
            gateway_name: Gateway name for gateway-specific data
            management_context: Management server identifier
            custom_ttl: Optional custom TTL override
            
        Returns:
            Data from cache or freshly fetched
        """
        # Try cache first
        cached_data = self.get(data_type, gateway_name, management_context)
        if cached_data is not None:
            return cached_data
        
        # Cache miss - fetch fresh data
        self._stats['total_fetches'] += 1
        data = fetch_func()
        
        # Store in cache
        self.set(data_type, data, gateway_name, management_context, custom_ttl)
        
        return data
    
    def invalidate(self, data_type: str, gateway_name: Optional[str] = None, management_context: Optional[str] = None):
        """
        Invalidate (clear) specific cached data
        
        Args:
            data_type: Type of data to invalidate
            gateway_name: Gateway name for gateway-specific data
            management_context: Management server identifier
        """
        cache_key = self._get_cache_key(data_type, gateway_name, management_context)
        if cache_key in self._cache:
            del self._cache[cache_key]
            self._stats['evictions'] += 1
    
    def invalidate_gateway(self, gateway_name: str, management_context: Optional[str] = None):
        """
        Invalidate all cached data for a specific gateway
        
        Args:
            gateway_name: Gateway to invalidate
            management_context: Management server identifier (required for proper key matching)
        """
        # Build the proper prefix with management context
        mgmt_prefix = management_context or 'default'
        prefix_to_match = f"{mgmt_prefix}:{gateway_name}:"
        
        keys_to_remove = [k for k in self._cache.keys() if k.startswith(prefix_to_match)]
        for key in keys_to_remove:
            del self._cache[key]
            self._stats['evictions'] += 1
    
    def invalidate_all(self):
        """Clear entire cache"""
        count = len(self._cache)
        self._cache.clear()
        self._stats['evictions'] += count
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics
        
        Returns:
            Dictionary with hit rate, miss rate, and other stats
        """
        total_requests = self._stats['hits'] + self._stats['misses']
        hit_rate = (self._stats['hits'] / total_requests * 100) if total_requests > 0 else 0
        
        return {
            'total_requests': total_requests,
            'hits': self._stats['hits'],
            'misses': self._stats['misses'],
            'hit_rate_percent': round(hit_rate, 2),
            'evictions': self._stats['evictions'],
            'total_fetches': self._stats['total_fetches'],
            'cached_items': len(self._cache),
            'cache_size_mb': self._estimate_size_mb()
        }
    
    def _estimate_size_mb(self) -> float:
        """Rough estimate of cache size in MB"""
        import sys
        total_size = sum(sys.getsizeof(entry['data']) for entry in self._cache.values())
        return round(total_size / (1024 * 1024), 2)
    
    def get_cache_info(self) -> Dict[str, Any]:
        """
        Get detailed cache information
        
        Returns:
            Dictionary with cache contents and metadata
        """
        now = time.time()
        items = []
        
        for key, entry in self._cache.items():
            age = now - entry['timestamp']
            remaining_ttl = entry['ttl'] - age
            
            items.append({
                'key': key,
                'data_type': entry['data_type'],
                'gateway': entry['gateway'],
                'age_seconds': round(age, 1),
                'remaining_ttl_seconds': round(remaining_ttl, 1),
                'fresh': remaining_ttl > 0
            })
        
        return {
            'stats': self.get_stats(),
            'items': items
        }


# Global singleton instance
_global_cache = IntelligentCache()


def get_cache() -> IntelligentCache:
    """Get global cache instance"""
    return _global_cache
