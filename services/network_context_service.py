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
            from services.mcp_client_simple import query_mcp_server_async
            
            server_config = all_servers['quantum-management']
            server_env = server_config.get('env', {})
            package_name = '@chkp/quantum-management-mcp'
            
            # Query 1: Get all network objects
            print(f"[NetworkContext] Querying network objects...")
            networks_result = await query_mcp_server_async(
                package_name,
                server_env,
                ['show_networks']
            )
            
            # Parse network objects
            if networks_result and 'tool_results' in networks_result:
                for tool_result in networks_result['tool_results']:
                    if 'result' in tool_result and 'content' in tool_result['result']:
                        for item in tool_result['result']['content']:
                            if isinstance(item, dict) and item.get('type') == 'text':
                                try:
                                    data = json.loads(item.get('text', '{}'))
                                    if 'objects' in data:
                                        for obj in data['objects']:
                                            name = obj.get('name', '')
                                            subnet = obj.get('subnet4', obj.get('ipv4-address'))
                                            mask = obj.get('subnet-mask4', obj.get('mask-length4'))
                                            
                                            if subnet:
                                                cidr = f"{subnet}/{mask}" if mask else subnet
                                                all_objects.append({'name': name, 'network': cidr})
                                                
                                                # Classify as internal if RFC1918
                                                if self._is_rfc1918(cidr):
                                                    internal_networks.append(cidr)
                                except:
                                    pass
            
            # Query 2: Get VPN communities to identify partner networks
            print(f"[NetworkContext] Querying VPN communities...")
            vpn_result = await query_mcp_server_async(
                package_name,
                server_env,
                ['show_vpn_communities']
            )
            
            # Parse VPN communities
            if vpn_result and 'tool_results' in vpn_result:
                for tool_result in vpn_result['tool_results']:
                    if 'result' in tool_result and 'content' in tool_result['result']:
                        for item in tool_result['result']['content']:
                            if isinstance(item, dict) and item.get('type') == 'text':
                                try:
                                    data = json.loads(item.get('text', '{}'))
                                    # VPN communities indicate partner/remote networks
                                    # Extract encryption domain from communities
                                    if 'objects' in data:
                                        for community in data['objects']:
                                            # VPN community networks are considered partner networks
                                            if 'encryption-domain' in community:
                                                vpn_networks.append(community.get('name', 'VPN'))
                                except:
                                    pass
        
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
            
            server_config = all_servers['quantum-gw-cli']
            server_env = server_config.get('env', {})
            package_name = '@chkp/quantum-gw-cli-mcp'
            
            # Build query - use specific gateway or let MCP auto-discover
            data_points = []
            if gateway_name:
                data_points.append(f"gateway_identifier:{gateway_name}")
            data_points.append("run_clish_command:show route")
            
            print(f"[NetworkContext] Querying routing table...")
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
