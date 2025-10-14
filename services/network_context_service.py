"""
Network Context Service - Provides network topology awareness for intelligent security investigations

Discovers and classifies networks into zones (internal, external, VPN/partner, DMZ) by:
1. Querying Check Point Management API for network objects and VPN communities
2. Parsing gateway routing tables to identify internet gateways
3. Allowing manual overrides for special cases

This context is injected into LLM prompts to guide intelligent threat analysis.
"""

import json
import ipaddress
import asyncio
from typing import Dict, List, Optional, Set, Tuple
from datetime import datetime, timedelta
from pathlib import Path

class NetworkContextService:
    """Discovers and maintains network topology context for security investigations"""
    
    def __init__(self, mcp_manager, cache_dir: str = "data"):
        self.mcp_manager = mcp_manager
        self.cache_file = Path(cache_dir) / "network_context_cache.json"
        self.cache_file.parent.mkdir(parents=True, exist_ok=True)
        
        # RFC1918 private address ranges
        self.RFC1918_RANGES = [
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16")
        ]
        
        # Cached network context
        self.context_cache = None
        self.cache_timestamp = None
        self.cache_ttl = timedelta(hours=24)  # Refresh daily
        
    def _is_rfc1918(self, network_str: str) -> bool:
        """Check if network is in RFC1918 private address space
        
        Returns True only if the network is a strict subnet of RFC1918 ranges.
        This prevents 0.0.0.0/0 (Any object) from being classified as internal.
        """
        try:
            network = ipaddress.ip_network(network_str, strict=False)
            # Only return True if network is a SUBNET of RFC1918 (not supernet or equal)
            # This prevents Any (0.0.0.0/0) from being classified as internal
            for rfc_range in self.RFC1918_RANGES:
                if network.subnet_of(rfc_range):
                    return True
            return False
        except:
            return False
    
    def _parse_routing_table(self, routing_output: str) -> Dict[str, any]:
        """Parse gateway routing table to identify default gateway and egress interfaces
        
        Args:
            routing_output: Output from 'netstat -rn' or 'show route' command
            
        Returns:
            Dict with default_gateway, egress_interface, and routes
        """
        routes = []
        default_gateway = None
        egress_interface = None
        
        # Parse netstat -rn format
        for line in routing_output.split('\n'):
            parts = line.split()
            if len(parts) >= 4:
                # Look for default route (0.0.0.0 or default)
                if parts[0] in ['0.0.0.0', 'default']:
                    default_gateway = parts[1]
                    egress_interface = parts[-1] if len(parts) > 3 else None
                
                # Collect all routes
                if parts[0] not in ['Destination', 'Kernel', 'default']:
                    routes.append({
                        'destination': parts[0],
                        'gateway': parts[1] if len(parts) > 1 else None,
                        'interface': parts[-1] if len(parts) > 2 else None
                    })
        
        return {
            'default_gateway': default_gateway,
            'egress_interface': egress_interface,
            'routes': routes
        }
    
    async def discover_networks_from_management(self) -> Dict[str, List[str]]:
        """Discover networks from Check Point Management API
        
        Uses Direct Management API for reliable network object discovery.
        
        Returns:
            Dict with 'internal_networks', 'vpn_networks', 'all_objects'
        """
        print(f"[NetworkContext] [{datetime.now().strftime('%H:%M:%S')}] Discovering networks from Management API...")
        
        internal_networks = []
        vpn_networks = []
        all_objects = []
        
        # Check if quantum-management MCP is configured
        all_servers = self.mcp_manager.get_all_servers()
        if 'quantum-management' not in all_servers:
            print(f"[NetworkContext] quantum-management not configured, skipping Management API discovery")
            return {
                'internal_networks': internal_networks,
                'vpn_networks': vpn_networks,
                'all_objects': all_objects
            }
        
        try:
            from services.management_api_client import ManagementAPIClient
            
            server_config = all_servers['quantum-management']
            server_env = server_config.get('env', {})
            
            # Extract connection details
            host = server_env.get('MANAGEMENT_HOST', '')
            port = server_env.get('PORT', '443')
            username = server_env.get('USERNAME', '')
            password = server_env.get('PASSWORD', '')
            
            if not all([host, username, password]):
                print(f"[NetworkContext] Missing Management API credentials")
                return {
                    'internal_networks': internal_networks,
                    'vpn_networks': vpn_networks,
                    'all_objects': all_objects
                }
            
            # Use Direct Management API
            print(f"[NetworkContext] Using Direct Management API for network discovery...")
            mgmt_client = ManagementAPIClient(host, port, username, password)
            
            if not mgmt_client.login():
                print(f"[NetworkContext] Failed to login to Management API")
                return {
                    'internal_networks': internal_networks,
                    'vpn_networks': vpn_networks,
                    'all_objects': all_objects
                }
            
            # Query 1: Get all network objects via Management API
            print(f"[NetworkContext] Fetching host objects...")
            hosts_response = mgmt_client._call_api('show-hosts', {'limit': 500, 'details-level': 'standard'})
            
            # Parse hosts from Management API response
            if hosts_response and 'objects' in hosts_response:
                print(f"[NetworkContext] Found {len(hosts_response['objects'])} host objects")
                for obj in hosts_response['objects']:
                    name = obj.get('name', '')
                    ipv4 = obj.get('ipv4-address')
                    
                    if ipv4:
                        cidr = f"{ipv4}/32"  # Hosts are typically /32
                        all_objects.append({'name': name, 'network': cidr, 'type': 'host'})
                        
                        # Classify as internal if RFC1918
                        if self._is_rfc1918(cidr):
                            internal_networks.append(cidr)
                            print(f"[NetworkContext] Found internal host: {cidr} ({name})")
            
            # Query 2: Get network objects (subnets)
            print(f"[NetworkContext] Fetching network objects...")
            networks_response = mgmt_client._call_api('show-networks', {'limit': 500, 'details-level': 'standard'})
            
            if networks_response and 'objects' in networks_response:
                print(f"[NetworkContext] Found {len(networks_response['objects'])} network objects")
                for obj in networks_response['objects']:
                    name = obj.get('name', '')
                    subnet = obj.get('subnet4')
                    mask_len = obj.get('mask-length4')
                    
                    if subnet and mask_len:
                        cidr = f"{subnet}/{mask_len}"
                        all_objects.append({'name': name, 'network': cidr, 'type': 'network'})
                        
                        # Classify as internal if RFC1918
                        if self._is_rfc1918(cidr):
                            internal_networks.append(cidr)
                            print(f"[NetworkContext] Found internal network: {cidr} ({name})")
            
            # Query 3: Get VPN communities using Management API client's VPN methods
            print(f"[NetworkContext] Fetching VPN communities...")
            vpn_star = mgmt_client.get_vpn_communities_star()
            vpn_meshed = mgmt_client.get_vpn_communities_meshed()
            vpn_remote = mgmt_client.get_vpn_communities_remote_access()
            
            for community in vpn_star + vpn_meshed + vpn_remote:
                vpn_name = community.get('name', 'VPN')
                vpn_networks.append(vpn_name)
                print(f"[NetworkContext] Found VPN community: {vpn_name}")
            
            # Logout
            mgmt_client.logout()
        
        except Exception as e:
            print(f"[NetworkContext] Error discovering from Management API: {e}")
        
        print(f"[NetworkContext] Discovered {len(internal_networks)} internal, {len(vpn_networks)} VPN networks")
        return {
            'internal_networks': list(set(internal_networks)),
            'vpn_networks': list(set(vpn_networks)),
            'all_objects': all_objects
        }
    
    async def discover_routing_context(self, gateway_name: Optional[str] = None) -> Dict:
        """Discover routing context from gateway CLI
        
        Args:
            gateway_name: Specific gateway to query, or None to auto-discover
            
        Returns:
            Dict with routing table analysis
        """
        print(f"[NetworkContext] [{datetime.now().strftime('%H:%M:%S')}] Discovering routing context from gateway...")
        
        # Check if quantum-gw-cli is configured
        all_servers = self.mcp_manager.get_all_servers()
        if 'quantum-gw-cli' not in all_servers:
            print(f"[NetworkContext] quantum-gw-cli not configured, skipping routing discovery")
            return {}
        
        try:
            from services.mcp_client_simple import query_mcp_server_async
            
            # CRITICAL: If no gateway_name provided, discover it from quantum-management FIRST
            # This prevents IP lookup failures in quantum-gw-cli
            if not gateway_name and 'quantum-management' in all_servers:
                print(f"[NetworkContext] Discovering gateway from quantum-management...")
                mgmt_config = all_servers['quantum-management']
                mgmt_env = mgmt_config.get('env', {})
                
                # Query for gateways
                mgmt_result = await query_mcp_server_async(
                    '@chkp/quantum-management-mcp',
                    mgmt_env,
                    ['show_gateways_and_servers']
                )
                
                # Extract first gateway name from discovered_resources (preferred) or tool_results
                if mgmt_result:
                    print(f"[NetworkContext] DEBUG: mgmt_result keys: {list(mgmt_result.keys())}")
                    
                    # First try: discovered_resources (contains parsed gateway data)
                    if 'discovered_resources' in mgmt_result:
                        print(f"[NetworkContext] DEBUG: discovered_resources keys: {list(mgmt_result['discovered_resources'].keys())}")
                        if 'show_gateways_and_servers' in mgmt_result['discovered_resources']:
                            gateways = mgmt_result['discovered_resources']['show_gateways_and_servers']
                            print(f"[NetworkContext] DEBUG: Found {len(gateways)} gateway/server objects")
                            for gw in gateways:
                                print(f"[NetworkContext] DEBUG: Object type={gw.get('type')}, name={gw.get('name')}")
                                if gw.get('type') == 'gateway':
                                    gateway_name = gw.get('name')
                                    print(f"[NetworkContext] Discovered gateway from discovered_resources: {gateway_name}")
                                    break
                        else:
                            print(f"[NetworkContext] DEBUG: 'show_gateways_and_servers' not in discovered_resources")
                    else:
                        print(f"[NetworkContext] DEBUG: 'discovered_resources' not in mgmt_result")
                    
                    # Fallback: Parse from tool_results JSON
                    if not gateway_name and 'tool_results' in mgmt_result:
                        print(f"[NetworkContext] DEBUG: Trying tool_results fallback...")
                        for tool_result in mgmt_result['tool_results']:
                            if 'result' in tool_result and 'content' in tool_result['result']:
                                for item in tool_result['result']['content']:
                                    if isinstance(item, dict) and item.get('type') == 'text':
                                        try:
                                            data = json.loads(item.get('text', '{}'))
                                            if 'objects' in data and len(data['objects']) > 0:
                                                gateway_name = data['objects'][0].get('name')
                                                print(f"[NetworkContext] Discovered gateway from tool_results: {gateway_name}")
                                                break
                                        except Exception as e:
                                            print(f"[NetworkContext] DEBUG: Failed to parse tool_result: {e}")
                else:
                    print(f"[NetworkContext] DEBUG: mgmt_result is None or empty")
            
            # If still no gateway_name, skip routing discovery
            if not gateway_name:
                print(f"[NetworkContext] No gateway discovered, skipping routing table query")
                return {}
            
            server_config = all_servers['quantum-gw-cli']
            server_env = server_config.get('env', {})
            package_name = '@chkp/quantum-gw-cli-mcp'
            
            # Build query with discovered gateway name
            data_points = [f"gateway_identifier:{gateway_name}", "run_clish_command:show route"]
            
            print(f"[NetworkContext] Querying routing table from gateway: {gateway_name}")
            routing_result = await query_mcp_server_async(
                package_name,
                server_env,
                data_points
            )
            
            # Parse routing output
            if routing_result and 'tool_results' in routing_result:
                for tool_result in routing_result['tool_results']:
                    if 'result' in tool_result and 'content' in tool_result['result']:
                        for item in tool_result['result']['content']:
                            if isinstance(item, dict) and item.get('type') == 'text':
                                text_data = item.get('text', '')
                                # Parse routing table
                                routing_info = self._parse_routing_table(text_data)
                                print(f"[NetworkContext] Found default gateway: {routing_info.get('default_gateway')}")
                                return routing_info
        
        except Exception as e:
            print(f"[NetworkContext] Error discovering routing context: {e}")
        
        return {}
    
    def classify_networks(self, networks: Dict, routing_info: Dict, manual_overrides: Optional[Dict] = None) -> Dict:
        """Classify discovered networks into zones
        
        Args:
            networks: Dict from discover_networks_from_management()
            routing_info: Dict from discover_routing_context()
            manual_overrides: Optional user-defined network classifications
            
        Returns:
            Classified network context with zones
        """
        print(f"[NetworkContext] [{datetime.now().strftime('%H:%M:%S')}] Classifying networks into zones...")
        
        context = {
            'internal_networks': [],
            'external_networks': [],
            'vpn_partner_networks': [],
            'internet_gateway': None,
            'egress_interface': None,
            'discovery_time': datetime.now().isoformat()
        }
        
        # Apply manual overrides first (highest priority)
        if manual_overrides:
            context['internal_networks'].extend(manual_overrides.get('internal_networks', []))
            context['vpn_partner_networks'].extend(manual_overrides.get('vpn_networks', []))
            context['external_networks'].extend(manual_overrides.get('external_networks', []))
        
        # Add discovered internal networks (RFC1918 from management)
        context['internal_networks'].extend(networks.get('internal_networks', []))
        
        # Add VPN networks from management
        context['vpn_partner_networks'].extend(networks.get('vpn_networks', []))
        
        # Extract internet gateway from routing
        context['internet_gateway'] = routing_info.get('default_gateway')
        context['egress_interface'] = routing_info.get('egress_interface')
        
        # Deduplicate
        context['internal_networks'] = list(set(context['internal_networks']))
        context['vpn_partner_networks'] = list(set(context['vpn_partner_networks']))
        context['external_networks'] = list(set(context['external_networks']))
        
        print(f"[NetworkContext] Classification complete:")
        print(f"  - Internal: {len(context['internal_networks'])} networks")
        print(f"  - VPN/Partner: {len(context['vpn_partner_networks'])} networks")
        print(f"  - Internet GW: {context['internet_gateway']}")
        
        return context
    
    async def get_network_context(self, force_refresh: bool = False, gateway_name: Optional[str] = None) -> Dict:
        """Get network context, using cache if available and fresh
        
        Args:
            force_refresh: Force refresh even if cache is valid
            gateway_name: Specific gateway to query for routing info
            
        Returns:
            Network context dict with zone classifications
        """
        # Check if cache is valid
        if not force_refresh and self.context_cache and self.cache_timestamp:
            if datetime.now() - self.cache_timestamp < self.cache_ttl:
                print(f"[NetworkContext] Using cached context (age: {(datetime.now() - self.cache_timestamp).seconds // 3600}h)")
                return self.context_cache
        
        print(f"[NetworkContext] Refreshing network context (force={force_refresh})...")
        
        # Discover networks from management API
        networks = await self.discover_networks_from_management()
        
        # Discover routing context from gateway
        routing_info = await self.discover_routing_context(gateway_name)
        
        # Load manual overrides if configured
        manual_overrides = self._load_manual_overrides()
        
        # Classify networks into zones
        context = self.classify_networks(networks, routing_info, manual_overrides or {})
        
        # Cache the result
        self.context_cache = context
        self.cache_timestamp = datetime.now()
        self._save_cache(context)
        
        return context
    
    def _load_manual_overrides(self) -> Optional[Dict]:
        """Load manual network overrides from config file"""
        override_file = Path("config/network_overrides.json")
        if override_file.exists():
            try:
                with open(override_file, 'r') as f:
                    overrides = json.load(f)
                    print(f"[NetworkContext] Loaded manual overrides from {override_file}")
                    return overrides
            except Exception as e:
                print(f"[NetworkContext] Error loading overrides: {e}")
        return None
    
    def _save_cache(self, context: Dict):
        """Save network context to cache file"""
        try:
            with open(self.cache_file, 'w') as f:
                json.dump(context, f, indent=2)
            print(f"[NetworkContext] Saved context to cache: {self.cache_file}")
        except Exception as e:
            print(f"[NetworkContext] Error saving cache: {e}")
    
    def format_context_for_llm(self, context: Dict) -> str:
        """Format network context for LLM prompt injection
        
        Args:
            context: Network context from get_network_context()
            
        Returns:
            Formatted string for LLM prompt
        """
        internal_nets = ', '.join(context.get('internal_networks', [])) or 'None discovered'
        vpn_nets = ', '.join(context.get('vpn_partner_networks', [])) or 'None discovered'
        internet_gw = context.get('internet_gateway', 'Unknown')
        
        return f"""
NETWORK TOPOLOGY CONTEXT:
- Internal/Protected Networks: {internal_nets}
- VPN/Partner Networks: {vpn_nets}
- Internet Gateway: {internet_gw} (via {context.get('egress_interface', 'unknown')})

INVESTIGATION PRIORITIES for security threats:
1. HIGHEST: Internal → External/Internet (data exfiltration, command & control)
2. HIGH: External → Internal (intrusion attempts, attacks)
3. MEDIUM: Internal → VPN/Partner (lateral movement, unauthorized access)
4. MEDIUM: VPN/Partner → Internal (compromised partner)
5. LOW: Internal → Internal (normal business traffic)

When investigating "suspicious activity", prioritize traffic flows in the order above.
"""
