"""Direct CheckPoint Management API Client - No MCP Server Bugs"""

import requests
import urllib3
from typing import Dict, List, Any, Optional
from datetime import datetime
from services.intelligent_cache import get_cache

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def _ts():
    """Return timestamp string for debug logging"""
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]

class ManagementAPIClient:
    """Direct CheckPoint Management API client - bypasses buggy MCP servers"""
    
    def __init__(self, host: str, port: str = "443", username: str = None, password: str = None):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.base_url = f"https://{host}:{port}/web_api"
        self.session_id = None
        self.cache = get_cache()  # Use global intelligent cache
        self.management_context = f"{host}:{port}"  # Unique identifier for this management server
        
    def login(self, max_retries: int = 5) -> bool:
        """Login to Management API and obtain session ID with retry logic for rate limiting"""
        import time
        
        # If already logged in with valid session, skip login
        if self.session_id:
            print(f"[MGMT_API] [{_ts()}] Reusing existing session")
            return True
        
        for attempt in range(max_retries):
            try:
                url = f"{self.base_url}/login"
                data = {"user": self.username, "password": self.password}
                
                if attempt > 0:
                    print(f"[MGMT_API] [{_ts()}] Login attempt {attempt + 1}/{max_retries}...")
                else:
                    print(f"[MGMT_API] [{_ts()}] Logging in to {self.host}...")
                
                resp = requests.post(url, json=data, verify=False, timeout=30)
                
                # Check for rate limiting
                if resp.status_code == 403:
                    try:
                        error_data = resp.json()
                        if error_data.get('code') == 'err_too_many_requests':
                            # Rate limited - retry with longer exponential backoff
                            wait_time = (2 ** attempt) * 3  # 3s, 6s, 12s, 24s, 48s
                            print(f"[MGMT_API] [{_ts()}] Rate limited - waiting {wait_time}s before retry...")
                            time.sleep(wait_time)
                            continue
                    except:
                        pass
                
                if resp.status_code != 200:
                    print(f"[MGMT_API] Login failed: {resp.status_code} - {resp.text}")
                    return False
                
                self.session_id = resp.json().get('sid')
                if not self.session_id:
                    print(f"[MGMT_API] No session ID received")
                    return False
                
                print(f"[MGMT_API] [{_ts()}] ✓ Logged in successfully")
                return True
                
            except Exception as e:
                print(f"[MGMT_API] Login error: {e}")
                if attempt < max_retries - 1:
                    wait_time = (2 ** attempt) * 3
                    print(f"[MGMT_API] [{_ts()}] Retrying in {wait_time}s...")
                    time.sleep(wait_time)
                else:
                    return False
        
        return False
    
    def logout(self):
        """Logout from Management API"""
        if not self.session_id:
            return
        
        try:
            url = f"{self.base_url}/logout"
            headers = {"X-chkp-sid": self.session_id}
            requests.post(url, headers=headers, verify=False, timeout=10)
            print(f"[MGMT_API] [{_ts()}] Logged out")
            self.session_id = None
        except Exception as e:
            print(f"[MGMT_API] Logout error: {e}")
    
    def _call_api(self, endpoint: str, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Make API call with current session"""
        if not self.session_id:
            if not self.login():
                return None
        
        try:
            url = f"{self.base_url}/{endpoint}"
            headers = {"X-chkp-sid": self.session_id, "Content-Type": "application/json"}
            
            resp = requests.post(url, json=data, headers=headers, verify=False, timeout=30)
            
            if resp.status_code != 200:
                print(f"[MGMT_API] API error: {resp.status_code} - {resp.text}")
                return None
            
            return resp.json()
            
        except Exception as e:
            print(f"[MGMT_API] API call error: {e}")
            return None
    
    def get_packages(self) -> List[Dict[str, Any]]:
        """Get all policy packages (cached)"""
        return self.cache.get_or_fetch('policy_packages', self._fetch_packages, management_context=self.management_context)
    
    def _fetch_packages(self) -> List[Dict[str, Any]]:
        """Internal: Fetch packages from API"""
        print(f"[MGMT_API] [{_ts()}] Fetching policy packages...")
        
        data = self._call_api("show-packages", {"details-level": "standard"})
        if not data or 'packages' not in data:
            return []
        
        packages = []
        for pkg in data['packages']:
            packages.append({
                'name': pkg.get('name'),
                'uid': pkg.get('uid'),
                'type': 'policy-package'
            })
        
        print(f"[MGMT_API] [{_ts()}] ✓ Found {len(packages)} packages")
        return packages
    
    def get_access_layers(self) -> List[Dict[str, Any]]:
        """Get all access control layers (cached)"""
        return self.cache.get_or_fetch('access_layers', self._fetch_access_layers, management_context=self.management_context)
    
    def _fetch_access_layers(self) -> List[Dict[str, Any]]:
        """Internal: Fetch access layers from API"""
        print(f"[MGMT_API] [{_ts()}] Fetching access layers...")
        
        data = self._call_api("show-access-layers", {"details-level": "standard"})
        if not data or 'access-layers' not in data:
            return []
        
        layers = []
        for layer in data['access-layers']:
            layers.append({
                'name': layer.get('name'),
                'uid': layer.get('uid'),
                'type': 'access-layer'
            })
        
        print(f"[MGMT_API] [{_ts()}] ✓ Found {len(layers)} access layers")
        return layers
    
    def get_access_rulebase(self, layer_name: str, package_name: str) -> Dict[str, Any]:
        """Get firewall access rulebase with correct action values (with pagination)"""
        print(f"[MGMT_API] [{_ts()}] Fetching access rulebase: layer={layer_name}, package={package_name}")
        
        all_rules = []
        offset = 0
        limit = 50
        total = None
        
        # Paginate through all results
        while True:
            data = self._call_api("show-access-rulebase", {
                "name": layer_name,
                "package": package_name,
                "details-level": "full",
                "use-object-dictionary": False,
                "offset": offset,
                "limit": limit
            })
            
            if not data:
                break
            
            # Get total on first iteration
            if total is None:
                total = data.get('total', 0)
                print(f"[MGMT_API] [{_ts()}] Total access rules: {total}")
            
            # Extract rules from this page
            for rule in data.get('rulebase', []):
                if isinstance(rule, dict):
                    clean_rule = {
                        'rule-number': rule.get('rule-number'),
                        'name': rule.get('name', ''),
                        'uid': rule.get('uid'),
                        'type': rule.get('type'),
                        'enabled': rule.get('enabled'),
                        'comments': rule.get('comments', ''),
                    }
                    
                    # Extract action (this is the CORRECT value from API)
                    action = rule.get('action')
                    if isinstance(action, dict):
                        clean_rule['action'] = action.get('name')
                    else:
                        clean_rule['action'] = action
                    
                    # Extract source
                    source = rule.get('source', [])
                    clean_rule['source'] = [s.get('name') if isinstance(s, dict) else s for s in source]
                    
                    # Extract destination  
                    destination = rule.get('destination', [])
                    clean_rule['destination'] = [d.get('name') if isinstance(d, dict) else d for d in destination]
                    
                    # Extract service
                    service = rule.get('service', [])
                    clean_rule['service'] = [s.get('name') if isinstance(s, dict) else s for s in service]
                    
                    # Extract track
                    track = rule.get('track', {})
                    if isinstance(track, dict):
                        clean_rule['track'] = {
                            'type': track.get('type', {}).get('name') if isinstance(track.get('type'), dict) else track.get('type'),
                            'accounting': track.get('accounting'),
                            'per-session': track.get('per-session'),
                            'per-connection': track.get('per-connection')
                        }
                    
                    # Extract install-on
                    install_on = rule.get('install-on', [])
                    clean_rule['install-on'] = [i.get('name') if isinstance(i, dict) else i for i in install_on]
                    
                    # Extract VPN column data (encryption/decryption/directional)
                    vpn = rule.get('vpn')
                    if vpn:
                        if isinstance(vpn, dict):
                            # Check for directional VPN (site-to-site with to/from members)
                            if 'directional' in vpn:
                                directional = vpn['directional']
                                if isinstance(directional, dict):
                                    clean_rule['vpn'] = {
                                        'type': 'directional',
                                        'from': directional.get('from', {}).get('name') if isinstance(directional.get('from'), dict) else directional.get('from'),
                                        'to': directional.get('to', {}).get('name') if isinstance(directional.get('to'), dict) else directional.get('to'),
                                        'encryption-mode': directional.get('encryption-mode')
                                    }
                                else:
                                    clean_rule['vpn'] = {'type': 'directional', 'value': directional}
                            # Check for standard community (name-based)
                            elif 'name' in vpn:
                                clean_rule['vpn'] = {'type': 'community', 'name': vpn['name']}
                            # Check for encryption/decryption indicators
                            elif 'encrypt' in vpn or 'decrypt' in vpn:
                                clean_rule['vpn'] = {
                                    'type': 'encrypt-decrypt',
                                    'encrypt': vpn.get('encrypt'),
                                    'decrypt': vpn.get('decrypt')
                                }
                            else:
                                # Fallback: capture whatever structure exists
                                clean_rule['vpn'] = vpn
                        elif isinstance(vpn, list):
                            # Multiple VPN communities - process each
                            clean_vpn_list = []
                            for v in vpn:
                                if isinstance(v, dict):
                                    if 'name' in v:
                                        clean_vpn_list.append({'type': 'community', 'name': v['name']})
                                    else:
                                        clean_vpn_list.append(v)
                                else:
                                    clean_vpn_list.append(v)
                            clean_rule['vpn'] = clean_vpn_list
                        else:
                            # Simple string value
                            clean_rule['vpn'] = vpn
                    
                    all_rules.append(clean_rule)
            
            # Check if we've retrieved all rules
            current_to = data.get('to', 0)
            if current_to >= total:
                break
            
            # Move to next page
            offset = current_to
            print(f"[MGMT_API] [{_ts()}] Fetching next page: offset={offset}")
        
        print(f"[MGMT_API] [{_ts()}] ✓ Retrieved {len(all_rules)} firewall rules with correct actions (paginated)")
        
        return {
            'uid': data.get('uid') if data else None,
            'name': layer_name,
            'rulebase': all_rules,
            'total': total or len(all_rules)
        }
    
    def get_nat_rulebase(self, package_name: str) -> Dict[str, Any]:
        """Get NAT rulebase (with pagination)"""
        print(f"[MGMT_API] [{_ts()}] Fetching NAT rulebase: package={package_name}")
        
        all_rules = []
        offset = 0
        limit = 50
        total = None
        
        # Paginate through all results
        while True:
            data = self._call_api("show-nat-rulebase", {
                "package": package_name,
                "details-level": "full",
                "use-object-dictionary": False,
                "offset": offset,
                "limit": limit
            })
            
            if not data:
                break
            
            # Get total on first iteration
            if total is None:
                total = data.get('total', 0)
                print(f"[MGMT_API] [{_ts()}] Total NAT rules: {total}")
            
            # Extract NAT rules from this page
            for rule in data.get('rulebase', []):
                if isinstance(rule, dict):
                    clean_rule = {
                        'rule-number': rule.get('rule-number'),
                        'uid': rule.get('uid'),
                        'type': rule.get('type'),
                        'enabled': rule.get('enabled'),
                        'method': rule.get('method'),
                        'comments': rule.get('comments', ''),
                    }
                    
                    # Extract NAT fields
                    for field in ['original-source', 'translated-source', 'original-destination', 
                                 'translated-destination', 'original-service', 'translated-service']:
                        value = rule.get(field)
                        if isinstance(value, dict):
                            clean_rule[field] = value.get('name')
                        else:
                            clean_rule[field] = value
                    
                    all_rules.append(clean_rule)
            
            # Check if we've retrieved all rules
            current_to = data.get('to', 0)
            if current_to >= total:
                break
            
            # Move to next page
            offset = current_to
            print(f"[MGMT_API] [{_ts()}] Fetching next page: offset={offset}")
        
        print(f"[MGMT_API] [{_ts()}] ✓ Retrieved {len(all_rules)} NAT rules (paginated)")
        
        return {
            'uid': data.get('uid') if data else None,
            'rulebase': all_rules,
            'total': total or len(all_rules)
        }
    
    def get_https_layers(self) -> List[Dict[str, Any]]:
        """Get HTTPS inspection layers"""
        print(f"[MGMT_API] [{_ts()}] Fetching HTTPS layers...")
        
        data = self._call_api("show-https-layers", {"details-level": "standard"})
        if not data or 'https-layers' not in data:
            return []
        
        layers = []
        for layer in data['https-layers']:
            layers.append({
                'name': layer.get('name'),
                'uid': layer.get('uid'),
                'type': 'https-layer'
            })
        
        print(f"[MGMT_API] [{_ts()}] ✓ Found {len(layers)} HTTPS layers")
        return layers
    
    def get_https_rulebase(self, layer_name: str, package_name: str) -> Dict[str, Any]:
        """Get HTTPS inspection rulebase (with pagination)"""
        print(f"[MGMT_API] [{_ts()}] Fetching HTTPS rulebase: layer={layer_name}, package={package_name}")
        
        all_rules = []
        offset = 0
        limit = 50
        total = None
        
        # Paginate through all results
        while True:
            data = self._call_api("show-https-rulebase", {
                "name": layer_name,
                "package": package_name,
                "details-level": "full",
                "use-object-dictionary": False,
                "offset": offset,
                "limit": limit
            })
            
            if not data:
                break
            
            # Get total on first iteration
            if total is None:
                total = data.get('total', 0)
                print(f"[MGMT_API] [{_ts()}] Total HTTPS rules: {total}")
            
            # Extract HTTPS rules from this page
            for rule in data.get('rulebase', []):
                if isinstance(rule, dict):
                    clean_rule = {
                        'rule-number': rule.get('rule-number'),
                        'name': rule.get('name', ''),
                        'uid': rule.get('uid'),
                        'enabled': rule.get('enabled'),
                        'comments': rule.get('comments', ''),
                    }
                    
                    # Extract action
                    action = rule.get('action')
                    if isinstance(action, dict):
                        clean_rule['action'] = action.get('name')
                    else:
                        clean_rule['action'] = action
                    
                    # Extract source
                    source = rule.get('source', [])
                    clean_rule['source'] = [s.get('name') if isinstance(s, dict) else s for s in source]
                    
                    # Extract destination
                    destination = rule.get('destination', [])
                    clean_rule['destination'] = [d.get('name') if isinstance(d, dict) else d for d in destination]
                    
                    # Extract site-category (CRITICAL: preserve exact names)
                    site_category = rule.get('site-category', [])
                    clean_rule['site-category'] = [c.get('name') if isinstance(c, dict) else c for c in site_category]
                    
                    # Extract track
                    track = rule.get('track', {})
                    if isinstance(track, dict):
                        clean_rule['track'] = {
                            'type': track.get('type', {}).get('name') if isinstance(track.get('type'), dict) else track.get('type')
                        }
                    
                    all_rules.append(clean_rule)
            
            # Check if we've retrieved all rules
            current_to = data.get('to', 0)
            if current_to >= total:
                break
            
            # Move to next page
            offset = current_to
            print(f"[MGMT_API] [{_ts()}] Fetching next page: offset={offset}")
        
        print(f"[MGMT_API] [{_ts()}] ✓ Retrieved {len(all_rules)} HTTPS rules with correct site-categories (paginated)")
        
        return {
            'uid': data.get('uid') if data else None,
            'name': layer_name,
            'rulebase': all_rules,
            'total': total or len(all_rules)
        }
    
    def get_threat_layers(self) -> List[Dict[str, Any]]:
        """Get threat prevention layers"""
        print(f"[MGMT_API] [{_ts()}] Fetching threat prevention layers...")
        
        data = self._call_api("show-threat-layers", {"details-level": "standard"})
        if not data or 'threat-layers' not in data:
            return []
        
        layers = []
        for layer in data['threat-layers']:
            layers.append({
                'name': layer.get('name'),
                'uid': layer.get('uid'),
                'type': 'threat-layer'
            })
        
        print(f"[MGMT_API] [{_ts()}] ✓ Found {len(layers)} threat layers")
        return layers
    
    def _get_threat_profile(self, profile_uid: str) -> Dict[str, Any]:
        """Get threat prevention profile details (IPS, Anti-Virus, Anti-Bot settings)"""
        try:
            data = self._call_api("show-threat-profile", {
                "uid": profile_uid,
                "details-level": "full"
            })
            
            if not data:
                return None
            
            # Extract key protection settings
            profile = {
                'name': data.get('name'),
                'uid': data.get('uid'),
                'ips': data.get('ips', False),
                'ips-settings': {},
                'anti-bot': data.get('anti-bot', False),
                'anti-virus': data.get('anti-virus', False),
                'threat-emulation': data.get('threat-emulation', False),
                'anti-malware': data.get('activate-protections-against-malicious-courier-sites', False)
            }
            
            # Get IPS-specific settings if enabled
            if data.get('ips-protections-from-version'):
                profile['ips-settings']['protections-from-version'] = data.get('ips-protections-from-version')
            if data.get('use-indicators'):
                profile['ips-settings']['use-indicators'] = data.get('use-indicators')
            if data.get('malicious-mail-policy-settings'):
                profile['ips-settings']['malicious-mail-policy'] = data.get('malicious-mail-policy-settings')
            
            return profile
            
        except Exception as e:
            print(f"[MGMT_API] Warning: Could not fetch threat profile {profile_uid}: {e}")
            return None
    
    def get_threat_rulebase(self, layer_name: str) -> Dict[str, Any]:
        """Get threat prevention rulebase (IPS, Anti-Virus, Anti-Bot, etc.) with pagination"""
        print(f"[MGMT_API] [{_ts()}] Fetching threat rulebase: layer={layer_name}")
        
        all_rules = []
        offset = 0
        limit = 50
        total = None
        
        # Paginate through all results
        while True:
            data = self._call_api("show-threat-rulebase", {
                "name": layer_name,
                "details-level": "full",
                "use-object-dictionary": False,
                "offset": offset,
                "limit": limit
            })
            
            if not data:
                break
            
            # Get total on first iteration
            if total is None:
                total = data.get('total', 0)
                print(f"[MGMT_API] [{_ts()}] Total threat prevention rules: {total}")
            
            # Extract threat rules from this page
            for rule in data.get('rulebase', []):
                if isinstance(rule, dict):
                    clean_rule = {
                        'rule-number': rule.get('rule-number'),
                        'name': rule.get('name', ''),
                        'uid': rule.get('uid'),
                        'enabled': rule.get('enabled'),
                        'comments': rule.get('comments', ''),
                    }
                    
                    # Extract action and expand threat prevention profiles
                    action = rule.get('action')
                    if isinstance(action, dict):
                        action_name = action.get('name')
                        clean_rule['action'] = action_name
                        
                        # If action references a threat prevention profile, expand it
                        if action.get('uid'):
                            profile_details = self._get_threat_profile(action.get('uid'))
                            if profile_details:
                                clean_rule['action_profile'] = profile_details
                    else:
                        clean_rule['action'] = action
                    
                    # Extract protected-scope
                    protected_scope = rule.get('protected-scope', [])
                    clean_rule['protected-scope'] = [p.get('name') if isinstance(p, dict) else p for p in protected_scope]
                    
                    # Extract track
                    track = rule.get('track', {})
                    if isinstance(track, dict):
                        clean_rule['track'] = {
                            'type': track.get('type', {}).get('name') if isinstance(track.get('type'), dict) else track.get('type')
                        }
                    
                    all_rules.append(clean_rule)
            
            # Check if we've retrieved all rules
            current_to = data.get('to', 0)
            if current_to >= total:
                break
            
            # Move to next page
            offset = current_to
            print(f"[MGMT_API] [{_ts()}] Fetching next page: offset={offset}")
        
        print(f"[MGMT_API] [{_ts()}] ✓ Retrieved {len(all_rules)} threat prevention rules (paginated)")
        
        return {
            'uid': data.get('uid') if data else None,
            'name': layer_name,
            'rulebase': all_rules,
            'total': total or len(all_rules)
        }
    
    def get_vpn_communities_star(self) -> List[Dict[str, Any]]:
        """Get all Star VPN communities (hub-and-spoke) (cached as part of vpn_communities)"""
        vpn_data = self.cache.get_or_fetch('vpn_communities', self._fetch_all_vpn_communities, management_context=self.management_context)
        return vpn_data.get('star', [])
    
    def get_vpn_communities_meshed(self) -> List[Dict[str, Any]]:
        """Get all Meshed VPN communities (site-to-site) (cached as part of vpn_communities)"""
        vpn_data = self.cache.get_or_fetch('vpn_communities', self._fetch_all_vpn_communities, management_context=self.management_context)
        return vpn_data.get('meshed', [])
    
    def get_vpn_communities_remote_access(self) -> List[Dict[str, Any]]:
        """Get all Remote Access VPN communities (cached as part of vpn_communities)"""
        vpn_data = self.cache.get_or_fetch('vpn_communities', self._fetch_all_vpn_communities, management_context=self.management_context)
        return vpn_data.get('remote_access', [])
    
    def _fetch_all_vpn_communities(self) -> Dict[str, List[Dict[str, Any]]]:
        """Internal: Fetch all VPN communities at once (more efficient)"""
        result = {'star': [], 'meshed': [], 'remote_access': []}
        
        # Fetch Star communities
        print(f"[MGMT_API] [{_ts()}] Fetching Star VPN communities...")
        data = self._call_api("show-vpn-communities-star", {"details-level": "full"})
        if data and 'objects' in data:
            for comm in data['objects']:
                center_gws = comm.get('center-gateways', [])
                center_names = [gw.get('name') if isinstance(gw, dict) else gw for gw in center_gws]
                satellite_gws = comm.get('satellite-gateways', [])
                satellite_names = [gw.get('name') if isinstance(gw, dict) else gw for gw in satellite_gws]
                
                result['star'].append({
                    'name': comm.get('name'),
                    'uid': comm.get('uid'),
                    'type': 'star',
                    'center-gateways': center_names,
                    'satellite-gateways': satellite_names,
                    'encryption-method': comm.get('encryption-method'),
                    'encryption-suite': comm.get('encryption-suite')
                })
        print(f"[MGMT_API] [{_ts()}] ✓ Found {len(result['star'])} Star VPN communities")
        
        # Fetch Meshed communities
        print(f"[MGMT_API] [{_ts()}] Fetching Meshed VPN communities...")
        data = self._call_api("show-vpn-communities-meshed", {"details-level": "full"})
        if data and 'objects' in data:
            for comm in data['objects']:
                gateways = comm.get('gateways', [])
                gateway_names = [gw.get('name') if isinstance(gw, dict) else gw for gw in gateways]
                
                result['meshed'].append({
                    'name': comm.get('name'),
                    'uid': comm.get('uid'),
                    'type': 'meshed',
                    'gateways': gateway_names,
                    'encryption-method': comm.get('encryption-method'),
                    'encryption-suite': comm.get('encryption-suite')
                })
        print(f"[MGMT_API] [{_ts()}] ✓ Found {len(result['meshed'])} Meshed VPN communities")
        
        # Fetch Remote Access communities
        print(f"[MGMT_API] [{_ts()}] Fetching Remote Access VPN communities...")
        data = self._call_api("show-vpn-communities-remote-access", {"details-level": "full"})
        if data and 'objects' in data:
            for comm in data['objects']:
                gateways = comm.get('gateways', [])
                gateway_names = [gw.get('name') if isinstance(gw, dict) else gw for gw in gateways]
                
                result['remote_access'].append({
                    'name': comm.get('name'),
                    'uid': comm.get('uid'),
                    'type': 'remote-access',
                    'gateways': gateway_names,
                    'encryption-method': comm.get('encryption-method'),
                    'encryption-suite': comm.get('encryption-suite')
                })
        print(f"[MGMT_API] [{_ts()}] ✓ Found {len(result['remote_access'])} Remote Access VPN communities")
        
        return result
    
    def get_gateways(self) -> List[Dict[str, Any]]:
        """Get all gateways and servers (cached)"""
        return self.cache.get_or_fetch('all_gateways', self._fetch_gateways, management_context=self.management_context)
    
    def _fetch_gateways(self) -> List[Dict[str, Any]]:
        """Internal: Fetch gateways from API"""
        print(f"[MGMT_API] [{_ts()}] Fetching gateways...")
        
        data = self._call_api("show-gateways-and-servers", {"details-level": "standard"})
        if not data or 'objects' not in data:
            return []
        
        gateways = []
        for gw in data['objects']:
            gateways.append({
                'name': gw.get('name'),
                'uid': gw.get('uid'),
                'type': gw.get('type', 'gateway'),
                'ipv4-address': gw.get('ipv4-address', '')
            })
        
        print(f"[MGMT_API] [{_ts()}] ✓ Found {len(gateways)} gateways")
        return gateways
    
    def __enter__(self):
        """Context manager entry"""
        self.login()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.logout()
