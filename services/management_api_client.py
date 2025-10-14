"""Direct CheckPoint Management API Client - No MCP Server Bugs"""

import requests
import urllib3
from typing import Dict, List, Any, Optional
from datetime import datetime

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
        
    def login(self) -> bool:
        """Login to Management API and obtain session ID"""
        try:
            url = f"{self.base_url}/login"
            data = {"user": self.username, "password": self.password}
            
            print(f"[MGMT_API] [{_ts()}] Logging in to {self.host}...")
            resp = requests.post(url, json=data, verify=False, timeout=30)
            
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
        """Get all policy packages"""
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
        """Get all access control layers"""
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
                    
                    # Extract action
                    action = rule.get('action')
                    if isinstance(action, dict):
                        clean_rule['action'] = action.get('name')
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
    
    def get_gateways(self) -> List[Dict[str, Any]]:
        """Get all gateways and servers"""
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
