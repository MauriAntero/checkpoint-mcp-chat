"""Query orchestrator for intelligent MCP server selection and LLM routing"""

import json
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
from services.gateway_directory import GatewayDirectory

@dataclass
class MCPServerCapability:
    """Describes what each MCP server can do"""
    server_type: str
    package: str
    capabilities: List[str]
    data_types: List[str]
    tools: Optional[List[str]] = None  # Main tool names for this MCP server
    
class QueryOrchestrator:
    """Orchestrates query execution across MCP servers and LLM models"""
    
    # Define MCP server capabilities
    MCP_CAPABILITIES = {
        "quantum-management": MCPServerCapability(
            server_type="quantum-management",
            package="@chkp/quantum-management-mcp",
            capabilities=[
                "policy management", "object management", "network topology",
                "access rules", "NAT rules", "firewall configuration"
            ],
            data_types=["policies", "rules", "network objects", "hosts", "gateways"],
            tools=["show_access_rulebase", "show_nat_rulebase", "show_hosts", "show_networks", "show_gateways_and_servers"]
        ),
        "management-logs": MCPServerCapability(
            server_type="management-logs",
            package="@chkp/management-logs-mcp",
            capabilities=[
                "connection logs", "audit logs", "log analysis",
                "traffic patterns", "connection history"
            ],
            data_types=["connection logs", "audit logs", "traffic data"],
            tools=["show_logs"]
        ),
        "threat-prevention": MCPServerCapability(
            server_type="threat-prevention",
            package="@chkp/threat-prevention-mcp",
            capabilities=[
                "IPS profiles", "anti-bot profiles", "anti-virus profiles",
                "zero phishing profiles", "threat emulation profiles",
                "threat indicators", "IOC feeds", "threat prevention policies"
            ],
            data_types=["IPS protections", "anti-bot data", "anti-virus signatures", "zero phishing detections", "threat policies", "IOC data"],
            tools=None  # Auto-detect: Let system discover actual tools from MCP server
        ),
        "https-inspection": MCPServerCapability(
            server_type="https-inspection",
            package="@chkp/https-inspection-mcp",
            capabilities=[
                "HTTPS inspection policies", "SSL/TLS inspection",
                "certificate management", "inspection exceptions"
            ],
            data_types=["HTTPS policies", "certificates", "inspection rules"],
            tools=None  # Auto-detect: Let system discover actual tools from MCP server
        ),
        "harmony-sase": MCPServerCapability(
            server_type="harmony-sase",
            package="@chkp/harmony-sase-mcp",
            capabilities=[
                "SASE regions", "network configuration", "application control",
                "user access policies"
            ],
            data_types=["SASE regions", "networks", "applications", "policies"]
        ),
        "reputation-service": MCPServerCapability(
            server_type="reputation-service",
            package="@chkp/reputation-service-mcp",
            capabilities=[
                "URL reputation", "IP reputation", "file reputation",
                "threat intelligence queries"
            ],
            data_types=["reputation scores", "threat intelligence"]
        ),
        "quantum-gw-cli": MCPServerCapability(
            server_type="quantum-gw-cli",
            package="@chkp/quantum-gw-cli-mcp",
            capabilities=[
                "gateway diagnostics", "system commands", "interface status",
                "routing information", "security status"
            ],
            data_types=["gateway status", "interface data", "routing tables"]
        ),
        "quantum-gw-connection-analysis": MCPServerCapability(
            server_type="quantum-gw-connection-analysis",
            package="@chkp/quantum-gw-connection-analysis-mcp",
            capabilities=[
                "connection analysis", "connection debugging",
                "packet analysis", "connection issues"
            ],
            data_types=["connection data", "packet traces", "debug info"]
        ),
        "threat-emulation": MCPServerCapability(
            server_type="threat-emulation",
            package="@chkp/threat-emulation-mcp",
            capabilities=[
                "malware analysis", "file sandboxing", "threat detection",
                "cloud-based analysis"
            ],
            data_types=["malware reports", "sandbox results", "threat analysis"]
        ),
        "quantum-gaia": MCPServerCapability(
            server_type="quantum-gaia",
            package="@chkp/quantum-gaia-mcp",
            capabilities=[
                "network interface configuration", "system settings",
                "OS-level configuration"
            ],
            data_types=["interface config", "system settings", "network config"]
        ),
        "spark-management": MCPServerCapability(
            server_type="spark-management",
            package="@chkp/spark-management-mcp",
            capabilities=[
                "Quantum Spark management", "appliance configuration",
                "SMB security management"
            ],
            data_types=["spark policies", "appliance status", "SMB config"]
        )
    }
    
    def __init__(self, ollama_client, mcp_manager, openrouter_client=None, gateway_script_executor=None):
        self.ollama_client = ollama_client
        self.gateway_script_executor = gateway_script_executor
        self.openrouter_client = openrouter_client
        self.mcp_manager = mcp_manager
        
        # Gateway directory for credential sharing
        self.gateway_directory = GatewayDirectory()
        
        # Network context service for topology awareness
        from services.network_context_service import NetworkContextService
        self.network_context_service = NetworkContextService(mcp_manager)
        
        # Session context for conversational caching
        self.session_context = {
            "last_gateway": None,
            "last_query_time": None,
            "session_timeout_minutes": 10,
            # Enhanced conversational context
            "last_timeframe": None,  # e.g., "last_24_hours", "today"
            "last_ip_addresses": [],  # List of IPs from previous query
            "last_usernames": [],  # List of usernames from previous query
            "last_domains": [],  # List of domains from previous query
            "last_task_type": None  # Last query task type
        }
    
    def _map_intent_to_classification(self, intent_task_type: str, user_query: str) -> tuple[str, list[str], list[str], str]:
        """Map Stage 1 intent task_type to Stage 2 classification with server filtering
        
        This provides semantic classification from LLM instead of brittle keyword matching.
        
        Args:
            intent_task_type: Task type from Stage 1 intent analysis
            user_query: Original user query (for performance/troubleshooting validation)
            
        Returns:
            Tuple of (query_type, allowed_servers, forbidden_servers, instructions)
        """
        query_lower = user_query.lower()
        
        # Check for performance keywords (override intent if present)
        performance_keywords = [
            'cpu', 'memory', 'ram', 'disk space', 'load', 'performance', 
            'concurrent connections', 'session count', 'sessions', 'connections count',
            'resource usage', 'utilization', 'capacity', 'processes', 'top processes',
            'bandwidth usage', 'throughput', 'latency', 'response time'
        ]
        is_performance_query = any(keyword in query_lower for keyword in performance_keywords)
        
        if is_performance_query:
            return (
                "PERFORMANCE/CAPACITY ANALYSIS",
                ["quantum-gw-cli", "quantum-management", "quantum-gaia"],
                ["management-logs"],
                """This is a PERFORMANCE/CAPACITY query requiring gateway metrics.
REQUIRED servers: quantum-gw-cli (for cpstat, fw ctl pstat, top, df, free commands)
OPTIONAL servers: quantum-management (for gateway discovery), quantum-gaia (for system commands)
FORBIDDEN servers: management-logs (logs don't contain performance metrics)

CRITICAL PERFORMANCE/CAPACITY COMMANDS (in priority order):
1. cpview -p (BEST: all metrics in one command - CPU, memory, disk, connections, throughput)
2. cpstat os -f all (Complete OS stats - CPU, memory, disk, interfaces, routes, sensors)
3. cpstat fw -f policy (Firewall performance - active connections, policy hits, sync stats)
4. cpstat ha (Cluster load distribution and synchronization)
5. top -b -n 1 (Process snapshot with CPU/memory per process)
6. fw ctl pstat (Connection table statistics and kernel memory usage)
7. fwaccel stat (SecureXL offload efficiency and F2F violations)
8. iostat -x (Disk I/O bottleneck detection)
9. mpstat -P ALL (Per-CPU core utilization)
10. free -h (Memory usage details)
11. df -h (Disk space usage)

ANALYSIS STRATEGY: Start with cpview -p or cpstat os -f all for holistic view, then drill into specific metrics if needed"""
            )
        
        # Map intent task_type to classification
        if intent_task_type == "troubleshooting":
            return (
                "CONNECTIVITY_TROUBLESHOOTING",
                ["management-logs", "quantum-management"],
                ["threat-prevention", "https-inspection"],
                """This is a CONNECTIVITY/TROUBLESHOOTING query - full stack diagnosis from application to gateway.
REQUIRED servers: 
  • management-logs (PRIMARY: traffic logs show connection attempts, drops, accepts)
  • quantum-management (REQUIRED: rulebase shows WHICH rule processed traffic and WHY)
  • quantum-gw-cli (OPTIONAL: gateway diagnostics for network/appliance-level issues)

FORBIDDEN servers: threat-prevention, https-inspection (not needed for connectivity troubleshooting)

TROUBLESHOOTING SCOPE - FULL STACK ANALYSIS:
1. TRAFFIC LOGS: Get logs from ALL security blades (Firewall, App Control, IPS, URL Filtering, etc.)
   - Connection attempts, drops, accepts, NAT translations
   - All enforcement blade logs (not just Firewall)

2. SECURITY POLICY: Retrieve firewall rulebase to correlate with log events
   - Use show_access_rulebase with show_raw=true for complete rule objects
   - Include Access Control and NAT rules
   - Match log 'rule' field to actual rule configurations

3. NETWORK-LEVEL DIAGNOSIS (if policy not the issue):
   - Routing problems (asymmetric routing, missing routes, conflicts)
   - Interface issues (down, VLAN, MTU, duplex mismatches)
   - NAT/topology issues (pool exhaustion, anti-spoofing)
   - Network connectivity (ARP, MAC, physical)

4. GATEWAY-LEVEL DIAGNOSIS (escalate if needed):
   - Resource issues (connection table full, memory/CPU exhaustion)
   - HA/cluster problems (ClusterXL state, split-brain)
   - Performance bottlenecks (packet drops, F2F violations, saturation)
   - Software bugs or service failures
   - Use gateway CLI tools: fw tab, fw ctl zdebug, tcpdump, cpstat, cpview

ESCALATION PATH:
  1. Check logs for drops/blocks (obvious issues)
  2. Correlate with firewall rules and blade enforcement
  3. If accepted but failing → routing/NAT/topology
  4. If intermittent → gateway resources/HA/performance
  5. If unexplained → run gateway diagnostics

DATA RETRIEVAL PATTERN:
  Step 1: Get traffic logs from ALL blades matching IPs/timeframe
  Step 2: Get rulebase with show_raw=true
  Step 3: Correlate logs→rules to identify enforcement chain
  Step 4: If needed, use gateway CLI for network/appliance diagnostics"""
            )
        elif intent_task_type in ["security_investigation", "threat_assessment"]:
            return (
                "PURE_THREAT",
                ["management-logs"],
                ["quantum-management", "threat-prevention", "https-inspection"],
                """This is a PURE THREAT/SECURITY query - looking for ACTUAL threat events.
ALLOWED servers: management-logs (actual threat events in logs)
FORBIDDEN servers: quantum-management, threat-prevention, https-inspection (these show POLICY/CONFIGURATION, not threat data)"""
            )
        elif intent_task_type == "policy_review":
            return (
                "PURE_POLICY",
                ["quantum-management", "threat-prevention", "https-inspection", "management-logs"],
                [],
                """This is a PURE POLICY query - reviewing CONFIGURATION/SETTINGS.
ALLOWED servers: quantum-management (firewall rules), threat-prevention (IPS/Anti-Bot profiles), https-inspection (HTTPS policies), management-logs (audit logs)
FORBIDDEN servers: None"""
            )
        elif intent_task_type in ["log_analysis", "network_analysis"]:
            # Get all available servers for mixed analysis
            available_servers = list(self.MCP_CAPABILITIES.keys())
            return (
                "MIXED",
                available_servers,
                [],
                """This is a MIXED query (or general query).
ALLOWED servers: All servers available"""
            )
        else:  # general_info or unknown
            available_servers = list(self.MCP_CAPABILITIES.keys())
            return (
                "GENERAL",
                available_servers,
                [],
                """This is a GENERAL query.
ALLOWED servers: All servers available"""
            )
    
    def _validate_execution_results(self, results: Dict[str, Any], query_type: str) -> tuple[bool, str]:
        """Validate if execution results contain meaningful data
        
        Args:
            results: Execution results from MCP servers
            query_type: Type of query that was executed
            
        Returns:
            Tuple of (is_valid, reason_if_invalid)
        """
        data_collected = results.get('data_collected', {})
        
        # Check if we got any data at all
        if not data_collected:
            return False, "No data collected from any MCP server"
        
        # Check if all servers returned errors
        errors = results.get('errors', [])
        if errors and len(errors) >= len(data_collected):
            return False, f"All servers returned errors: {'; '.join(errors[:2])}"
        
        # Check if primary data sources returned empty results
        total_items = 0
        for server_name, server_data in data_collected.items():
            if isinstance(server_data, dict):
                # Count items in various formats
                if 'logs' in server_data:
                    total_items += len(server_data.get('logs', []))
                elif 'objects' in server_data:
                    total_items += len(server_data.get('objects', []))
                elif 'data' in server_data:
                    total_items += len(server_data.get('data', []))
                elif isinstance(server_data, list):
                    total_items += len(server_data)
        
        if total_items == 0:
            return False, f"Primary data sources returned no items for {query_type} query"
        
        # Results are valid
        return True, ""
    
    def _get_fallback_classification(self, original_query_type: str, user_query: str) -> Optional[tuple[str, list[str], list[str], str]]:
        """Get fallback classification when primary returns no data
        
        Args:
            original_query_type: The query type that returned no results
            user_query: Original user query
            
        Returns:
            Tuple of (query_type, allowed_servers, forbidden_servers, instructions) or None if no fallback
        """
        query_lower = user_query.lower()
        available_servers = list(self.MCP_CAPABILITIES.keys())
        
        # Fallback strategies based on original classification
        if original_query_type == "CONNECTIVITY_TROUBLESHOOTING":
            # Troubleshooting returned no logs → Try adding gateway diagnostics
            if self.gateway_script_executor:
                return (
                    "TROUBLESHOOTING_WITH_DIAGNOSTICS",
                    ["management-logs", "quantum-gw-cli", "quantum-management"],
                    [],
                    """FALLBACK: No traffic logs found. Trying gateway diagnostic tools.
ALLOWED servers: management-logs (traffic logs), quantum-gw-cli (gateway diagnostics), quantum-management (gateway discovery)
FORBIDDEN servers: None"""
                )
        
        elif original_query_type == "PURE_THREAT":
            # Threat query returned no logs → Try adding policy review as fallback
            return (
                "THREAT_WITH_POLICY_CONTEXT",
                ["management-logs", "quantum-management", "threat-prevention"],
                [],
                """FALLBACK: No threat events found in logs. Adding policy context.
ALLOWED servers: management-logs (threat logs), quantum-management (policy rules), threat-prevention (threat profiles)
FORBIDDEN servers: None"""
            )
        
        elif original_query_type == "PURE_POLICY":
            # Policy query returned nothing → Try MIXED (all servers)
            return (
                "MIXED",
                available_servers,
                [],
                """FALLBACK: Policy servers returned no data. Trying all available servers.
ALLOWED servers: All servers available"""
            )
        
        # No fallback strategy available
        return None
    
    def _detect_troubleshooting_intent(self, user_query: str) -> bool:
        """Detect if query is about connectivity troubleshooting using robust regex patterns
        
        This is the single source of truth for troubleshooting detection, used by both
        planning stage (server selection) and analysis stage (prompt customization).
        
        Args:
            user_query: User's natural language query
            
        Returns:
            True if query is about troubleshooting, False otherwise
        """
        import re
        
        query_lower = user_query.lower()
        
        # Exact phrase matches (high confidence troubleshooting indicators)
        exact_troubleshooting_phrases = [
            'troubleshoot',
            'connectivity issue', 'connectivity problem', 'connectivity fail',
            'connection issue', 'connection problem', 'connection fail',
            'cannot connect', 'unable to connect', 'can\'t connect', 'not connecting',
            'cannot reach', 'unable to reach', 'not reachable',
            'connection refused', 'connection timeout', 'connection reset',
            'vpn down', 'vpn not working', 'vpn fail', 'vpn issue',
            'tunnel down', 'tunnel not working', 'tunnel fail', 'tunnel issue',
            'network down', 'network not working', 'network fail', 'network issue',
            'link down', 'link not working', 'link fail'
        ]
        
        # Pattern-based detection for question-style troubleshooting
        # Requires BOTH issue indicator (can't/cannot/unable) AND connectivity noun (vpn/tunnel/network/connection)
        # to avoid false positives like "Why can't we access threat logs?"
        troubleshooting_patterns = [
            # "Why can't users connect to VPN?" "Why can't X reach the tunnel?"
            r'\bwhy\s+(?:can\'t|cannot|unable)\s+.{0,50}?\b(?:connect|reach)\s+(?:to\s+)?(?:vpn|tunnel|network|gateway|server)',
            # "Users can't connect to VPN" "Unable to reach network"
            r'\b(?:can\'t|cannot|unable)\s+.{0,30}?\b(?:connect|reach)\s+(?:to\s+)?(?:vpn|tunnel|network|gateway|server)',
        ]
        
        exact_match = any(phrase in query_lower for phrase in exact_troubleshooting_phrases)
        pattern_match = any(re.search(pattern, query_lower) for pattern in troubleshooting_patterns)
        
        return exact_match or pattern_match
    
    def _extract_gateway_from_query(self, user_query: str) -> Optional[str]:
        """Extract gateway name from user query using regex patterns
        
        Args:
            user_query: User's natural language query
            
        Returns:
            Gateway name if found, None otherwise
        """
        import re
        
        # Time-related words to exclude from gateway extraction
        excluded_words = {
            'last', 'this', 'today', 'yesterday', 'week', 'month', 'hour', 
            'day', 'year', 'past', 'recent', 'current', 'previous', 'next',
            'all', 'any', 'some', 'every', 'each'
        }
        
        # CRITICAL: Pre-detect and skip IP patterns to avoid extracting IP fragments as gateway names
        # Pattern matches "from 192.168.1.15" or "on 10.0.0.1" etc. (case-insensitive)
        ip_context_pattern = r'\b(?:from|on|at|to|via)\s+(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        if re.search(ip_context_pattern, user_query, re.IGNORECASE):
            print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] ⚠️ Skipped gateway extraction - query contains IP addresses in context positions (IPs are traffic filters, not gateway names)")
            return None
        
        # Gateway name patterns (ordered by specificity - most specific first)
        patterns = [
            r'\b([a-zA-Z0-9_-]+?-(?:gw|fw|gateway|firewall))\b',   # "main-gw", "edge-fw" (specific suffixes)
            r'\b(cp-[a-zA-Z0-9_-]+)\b',                            # "cp-gw", "cp-fw-1" (cp- prefix)
            r'\bon\s+([a-zA-Z0-9_-]+(?:-gw|-fw|-gateway)?)\b',    # "on cp-gw"
            r'\bfrom\s+([a-zA-Z0-9_-]+(?:-gw|-fw|-gateway)?)\b',  # "from cp-gw"
        ]
        
        for pattern in patterns:
            match = re.search(pattern, user_query, re.IGNORECASE)
            if match:
                gateway_name = match.group(1)
                # Exclude time-related words
                if gateway_name.lower() not in excluded_words:
                    print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Extracted gateway name: '{gateway_name}'")
                    return gateway_name
        
        return None
    
    def _extract_gateway_from_plan(self, plan: Dict[str, Any]) -> Optional[str]:
        """Extract gateway name from LLM execution plan (more reliable than regex)
        
        Args:
            plan: Execution plan from Stage 2 LLM
            
        Returns:
            Gateway name if found in plan, None otherwise
        """
        # Time-related words to exclude (same as regex method)
        excluded_words = {
            'last', 'this', 'today', 'yesterday', 'week', 'month', 'hour', 
            'day', 'year', 'past', 'recent', 'current', 'previous', 'next',
            'all', 'any', 'some', 'every', 'each'
        }
        
        # 1. Check data_to_fetch array for gateway_identifier entries
        data_to_fetch = plan.get("data_to_fetch", [])
        for item in data_to_fetch:
            item_str = str(item)
            if "gateway_identifier:" in item_str:
                # Extract gateway name after the colon
                gateway_name = item_str.split("gateway_identifier:", 1)[1].strip()
                if gateway_name and gateway_name.lower() not in excluded_words:
                    print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Extracted gateway from plan (data_to_fetch): '{gateway_name}'")
                    return gateway_name
            elif "gateway_name:" in item_str:
                # Alternative format
                gateway_name = item_str.split("gateway_name:", 1)[1].strip()
                if gateway_name and gateway_name.lower() not in excluded_words:
                    print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Extracted gateway from plan (data_to_fetch): '{gateway_name}'")
                    return gateway_name
        
        # 2. Check execution_steps for gateway parameters (backup)
        execution_steps = plan.get("execution_steps", [])
        for step in execution_steps:
            if isinstance(step, dict):
                # Check for gateway-related parameters
                for key, value in step.items():
                    if "gateway" in key.lower() and isinstance(value, str):
                        if value and value.lower() not in excluded_words:
                            print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Extracted gateway from plan (execution_steps): '{value}'")
                            return value
        
        return None
    
    def _is_session_active(self) -> bool:
        """Check if session context is still active (within timeout window)"""
        if not self.session_context["last_query_time"]:
            return False
        
        from datetime import timedelta
        time_since_last_query = datetime.now() - self.session_context["last_query_time"]
        timeout = timedelta(minutes=self.session_context["session_timeout_minutes"])
        
        return time_since_last_query < timeout
    
    def _update_session_context(self, user_query: str, plan: Optional[Dict[str, Any]] = None, intent: Optional[Dict[str, Any]] = None):
        """Update session context with entities from plan and intent for conversational queries
        
        Args:
            user_query: User's natural language query
            plan: Optional execution plan from Stage 2 (preferred source for gateway extraction)
            intent: Optional intent from Stage 1 (contains extracted entities and timeframe)
        """
        self.session_context["last_query_time"] = datetime.now()
        
        # Extract gateway name
        gateway_name = None
        
        # Method 1 (PREFERRED): Extract from LLM execution plan (more reliable)
        if plan:
            gateway_name = self._extract_gateway_from_plan(plan)
        
        # Method 2 (FALLBACK): Extract from user query using regex (less reliable)
        if not gateway_name:
            gateway_name = self._extract_gateway_from_query(user_query)
            if gateway_name:
                print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Extracted gateway from query (regex fallback): '{gateway_name}'")
        
        # Update session context if gateway was found
        if gateway_name:
            self.session_context["last_gateway"] = gateway_name
            print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Session context updated: gateway='{gateway_name}'")
        
        # Extract and cache entities from Stage 1 intent (if available)
        if intent:
            extracted_entities = intent.get('extracted_entities', {})
            time_context = intent.get('time_context', {})
            task_type = intent.get('task_type')
            
            # Cache IP addresses
            if extracted_entities.get('ip_addresses'):
                self.session_context["last_ip_addresses"] = extracted_entities['ip_addresses']
                print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Session context updated: IPs={extracted_entities['ip_addresses']}")
            
            # Cache usernames
            if extracted_entities.get('usernames'):
                self.session_context["last_usernames"] = extracted_entities['usernames']
                print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Session context updated: users={extracted_entities['usernames']}")
            
            # Cache domains
            if extracted_entities.get('domains'):
                self.session_context["last_domains"] = extracted_entities['domains']
                print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Session context updated: domains={extracted_entities['domains']}")
            
            # Cache timeframe
            if time_context.get('relative_time'):
                self.session_context["last_timeframe"] = time_context['relative_time']
                print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Session context updated: timeframe={time_context['relative_time']}")
            
            # Cache task type
            if task_type:
                self.session_context["last_task_type"] = task_type
                print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Session context updated: task_type={task_type}")
    
    def _apply_session_context(self, data_to_fetch: List[str], user_query: str) -> List[str]:
        """Apply cached gateway name to data_to_fetch if no gateway specified in current query
        
        Args:
            data_to_fetch: Original data points from plan
            user_query: Current user query
            
        Returns:
            Modified data_to_fetch with cached gateway if applicable
        """
        # Check if current query has gateway name
        current_gateway = self._extract_gateway_from_query(user_query)
        
        # If query has explicit gateway, use it (already in data_to_fetch)
        if current_gateway:
            return data_to_fetch
        
        # Check if we have cached gateway and session is active
        cached_gateway = self.session_context.get("last_gateway")
        if cached_gateway and self._is_session_active():
            # Check if data_to_fetch already has a gateway identifier
            has_gateway = any("gateway_identifier:" in str(item) or "gateway:" in str(item) for item in data_to_fetch)
            
            if not has_gateway:
                print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Using cached gateway '{cached_gateway}' from session context")
                data_to_fetch.append(f"gateway_identifier:{cached_gateway}")
        
        return data_to_fetch
    
    def _update_gateway_directory_from_results(self, tool_results: List[Dict[str, Any]]):
        """Update gateway directory cache when gateways are discovered from management API
        
        Args:
            tool_results: Tool results from quantum-management MCP server
        """
        for tool_result in tool_results:
            tool_name = tool_result.get('tool', '')
            
            # Check if this is a gateway discovery tool
            if 'show_gateways_and_servers' not in tool_name:
                continue
            
            # Extract gateway data from result
            result = tool_result.get('result', {})
            if result.get('isError'):
                continue
            
            content = result.get('content', [])
            for item in content:
                if isinstance(item, dict) and item.get('type') == 'text':
                    try:
                        # Parse JSON response
                        data = json.loads(item.get('text', '{}'))
                        
                        # Check for 'objects' array (Check Point API response format)
                        gateways = data.get('objects', [])
                        if gateways and isinstance(gateways, list):
                            self.gateway_directory.update_from_management_api(gateways)
                            print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Updated gateway directory with {len(gateways)} gateways")
                            break
                    except json.JSONDecodeError:
                        pass
    
    def analyze_user_intent(self, user_query: str, planner_model: Optional[str] = None) -> Dict[str, Any]:
        """Stage 1: Analyze user intent to understand what they want
        
        Args:
            user_query: The user's natural language query
            planner_model: Model to use for intent analysis
            
        Returns:
            Structured intent containing task type, data needs, scope, and goals
        """
        print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Stage 1: Analyzing user intent...")
        
        # Build full MCP capabilities description (same as Phase 2 for complete context)
        capabilities_desc = self._build_capabilities_description()
        
        # Get network context (use cache if available)
        import asyncio
        try:
            # Try to get cached context quickly (no forced refresh)
            network_context = asyncio.run(self.network_context_service.get_network_context(force_refresh=False))
            network_context_text = self.network_context_service.format_context_for_llm(network_context)
        except Exception as e:
            print(f"[QueryOrchestrator] Could not load network context: {e}")
            network_context_text = "\nNETWORK TOPOLOGY: Not available\n"
        
        # Build session context section for conversational queries
        session_context_section = ""
        if self._is_session_active():
            context_items = []
            if self.session_context.get("last_gateway"):
                context_items.append(f"Gateway: {self.session_context['last_gateway']}")
            if self.session_context.get("last_timeframe"):
                context_items.append(f"Timeframe: {self.session_context['last_timeframe']}")
            if self.session_context.get("last_ip_addresses"):
                context_items.append(f"IPs: {', '.join(self.session_context['last_ip_addresses'])}")
            if self.session_context.get("last_usernames"):
                context_items.append(f"Users: {', '.join(self.session_context['last_usernames'])}")
            if self.session_context.get("last_domains"):
                context_items.append(f"Domains: {', '.join(self.session_context['last_domains'])}")
            if self.session_context.get("last_task_type"):
                context_items.append(f"Previous task: {self.session_context['last_task_type']}")
            
            if context_items:
                session_context_section = f"\n\nCONVERSATIONAL CONTEXT (from previous query - use if current query references 'it', 'them', 'same', 'more', etc.):\n" + " | ".join(context_items)
        
        intent_prompt = f"""You are analyzing a Check Point security platform query to understand what the user needs.

Available Capabilities:
{capabilities_desc}
{network_context_text}{session_context_section}
User Query: "{user_query}"

Return a JSON object describing the user's intent with IOCs and entities extracted:
{{
    "task_type": "log_analysis | security_investigation | troubleshooting | policy_review | network_analysis | threat_assessment | general_info",
    "primary_goal": "What the user wants to achieve",
    "data_requirements": {{
        "data_types": ["logs | policies | configs | threat_data | network_topology | etc."],
        "time_scope": "real-time | historical | specific_period | not_applicable",
        "specific_period": "last_hour | today | yesterday | last_24_hours | this_week | this_month | last_7_days | last_30_days | all_time | custom",
        "filters": ["IP addresses | users | applications | etc."]
    }},
    "extracted_entities": {{
        "ip_addresses": ["List any IP addresses mentioned"],
        "domains": ["List any domains/URLs mentioned"],
        "file_hashes": ["List any file hashes mentioned (MD5, SHA256, etc.)"],
        "usernames": ["List any usernames mentioned"],
        "gateway_names": ["List any gateway/firewall names mentioned"],
        "services_ports": ["List any services or port numbers mentioned"],
        "rule_numbers": ["List any rule numbers mentioned"]
    }},
    "time_context": {{
        "relative_time": "last_hour | today | yesterday | last_24_hours | etc. if mentioned, otherwise null",
        "absolute_start": "YYYY-MM-DD HH:MM if specific start time mentioned, otherwise null",
        "absolute_end": "YYYY-MM-DD HH:MM if specific end time mentioned, otherwise null"
    }},
    "expected_outcome": "summary | detailed_report | troubleshooting_steps | etc.",
    "urgency": "routine | important | critical",
    "context_clues": ["implicit requirements or context"],
    "file_path": "file path if mentioned, otherwise null"
}}

Intent Analysis:"""

        # Use planner model for intent analysis
        if planner_model:
            client, model_name = self._get_client_for_model(planner_model)
        else:
            client = self.ollama_client
            model_name = self.ollama_client.general_model
        
        try:
            response = client.generate_response(
                prompt=intent_prompt,
                model=model_name,
                temperature=0.2  # Very low temperature for precise intent extraction
            )
        except Exception as api_error:
            # Catch API errors during intent analysis
            error_msg = str(api_error)
            print(f"[QueryOrchestrator] API Error during intent analysis: {error_msg}")
            return {
                "task_type": "general_info",
                "primary_goal": f"API Error: {error_msg}",
                "data_requirements": {"data_types": [], "time_scope": "not_applicable"},
                "expected_outcome": "error_response",
                "api_error": error_msg  # Pass error through for later handling
            }
        
        if not response:
            return {
                "task_type": "general_info",
                "primary_goal": "Unable to analyze intent",
                "data_requirements": {"data_types": [], "time_scope": "not_applicable"},
                "expected_outcome": "general_response"
            }
        
        try:
            json_start = response.find('{')
            json_end = response.rfind('}') + 1
            if json_start >= 0 and json_end > json_start:
                json_str = response[json_start:json_end]
                intent = json.loads(json_str)
                print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Intent extracted: task_type={intent.get('task_type')}, time_scope={intent.get('data_requirements', {}).get('time_scope')}")
                return intent
            else:
                raise ValueError("No JSON found in response")
        except (json.JSONDecodeError, ValueError) as e:
            print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Failed to parse intent: {e}")
            print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Response was: {response}")
            return {
                "task_type": "general_info",
                "primary_goal": user_query,
                "data_requirements": {"data_types": ["general"], "time_scope": "not_applicable"},
                "expected_outcome": "general_response"
            }
    
    def _get_client_for_model(self, model_name: Optional[str]):
        """Determine which client to use based on model name prefix"""
        print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] _get_client_for_model called with: '{model_name}'")
        
        if not model_name:
            # Smart fallback: prefer OpenRouter if configured, otherwise Ollama
            if self.openrouter_client and self.openrouter_client.api_key:
                print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] No model specified, using OpenRouter default")
                return self.openrouter_client, self.openrouter_client.general_model
            print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] No model specified, using Ollama default")
            return self.ollama_client, self.ollama_client.general_model
        
        if model_name.startswith("Ollama:"):
            stripped = model_name.replace("Ollama: ", "")
            print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Using Ollama with model: '{stripped}'")
            return self.ollama_client, stripped
        elif model_name.startswith("OpenRouter:"):
            if not self.openrouter_client:
                raise ValueError("OpenRouter client not configured")
            stripped = model_name.replace("OpenRouter: ", "")
            print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Using OpenRouter with model: '{stripped}'")
            return self.openrouter_client, stripped
        else:
            # Default to Ollama for backward compatibility
            print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] No prefix detected, defaulting to Ollama with model: '{model_name}'")
            return self.ollama_client, model_name
    
    def create_execution_plan(self, user_query: str, planner_model: Optional[str] = None, intent: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Stage 2: Create technical execution plan based on user intent
        
        Args:
            user_query: The user's original query
            planner_model: Model to use for planning (format: "Provider: model_name")
            intent: Structured intent from Stage 1 (if None, will run Stage 1 first)
        """
        print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] create_execution_plan called with planner_model: '{planner_model}'")
        
        # Stage 1: Analyze user intent if not provided
        if not intent:
            print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] No intent provided, running Stage 1 first...")
            intent = self.analyze_user_intent(user_query, planner_model)
        
        print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Stage 2: Creating technical execution plan from intent...")
        
        # Build capabilities description with API specifications
        capabilities_desc = self._build_capabilities_description()
        
        # Get network context (use cache if available)
        import asyncio
        try:
            # Try to get cached context quickly (no forced refresh)
            network_context = asyncio.run(self.network_context_service.get_network_context(force_refresh=False))
            network_context_text = self.network_context_service.format_context_for_llm(network_context)
        except Exception as e:
            print(f"[QueryOrchestrator] Could not load network context for Stage 2: {e}")
            network_context_text = ""
        
        # Get list of available servers (includes both running and on-demand via npx)
        # Include all servers from MCP_CAPABILITIES that can be executed via npx
        active_server_names = self.mcp_manager.get_active_servers()
        
        # Add all MCP_CAPABILITIES servers (these can be run on-demand via npx)
        available_servers = set(active_server_names)
        available_servers.update(self.MCP_CAPABILITIES.keys())
        
        # Use all available servers for planning
        active_server_types = sorted(list(available_servers))
        
        print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Available MCP servers for planning: {', '.join(active_server_types)}")
        
        # Extract key information from intent
        task_type = intent.get('task_type', 'general_info')
        primary_goal = intent.get('primary_goal', user_query)
        data_requirements = intent.get('data_requirements', {})
        data_types = data_requirements.get('data_types', [])
        time_scope = data_requirements.get('time_scope', 'not_applicable')
        specific_period = data_requirements.get('specific_period', '')
        filters = data_requirements.get('filters', [])
        file_path = intent.get('file_path', None)
        
        # Extract entities from Stage 1 (IOCs, timeframes, etc.)
        extracted_entities = intent.get('extracted_entities', {})
        time_context = intent.get('time_context', {})
        
        # Add gateway script executor instructions if enabled
        gateway_executor_instructions = ""
        if self.gateway_script_executor:
            from services.gateway_script_executor import GATEWAY_EXECUTOR_LLM_PROMPT
            gateway_executor_instructions = f"\n\n{GATEWAY_EXECUTOR_LLM_PROMPT}"
        
        # Use Stage 1 intent for semantic classification (replaces keyword-based detection)
        # This is more reliable than substring matching
        query_type, allowed_servers, forbidden_servers, instructions = self._map_intent_to_classification(
            task_type, user_query
        )
        
        # Build extracted entities section for planning prompt
        entities_section = ""
        if extracted_entities and any(extracted_entities.values()):
            entities_lines = []
            if extracted_entities.get('ip_addresses'):
                entities_lines.append(f"  • IP Addresses: {', '.join(extracted_entities['ip_addresses'])}")
            if extracted_entities.get('domains'):
                entities_lines.append(f"  • Domains/URLs: {', '.join(extracted_entities['domains'])}")
            if extracted_entities.get('file_hashes'):
                entities_lines.append(f"  • File Hashes: {', '.join(extracted_entities['file_hashes'])}")
            if extracted_entities.get('usernames'):
                entities_lines.append(f"  • Usernames: {', '.join(extracted_entities['usernames'])}")
            if extracted_entities.get('gateway_names'):
                entities_lines.append(f"  • Gateway Names: {', '.join(extracted_entities['gateway_names'])}")
            if extracted_entities.get('services_ports'):
                entities_lines.append(f"  • Services/Ports: {', '.join(extracted_entities['services_ports'])}")
            if extracted_entities.get('rule_numbers'):
                entities_lines.append(f"  • Rule Numbers: {', '.join(extracted_entities['rule_numbers'])}")
            
            if entities_lines:
                entities_section = "\nExtracted Entities (use these directly, no need to re-extract):\n" + "\n".join(entities_lines)
        
        # Build time context section
        time_context_section = ""
        if time_context:
            time_lines = []
            if time_context.get('relative_time'):
                time_lines.append(f"  • Relative Time: {time_context['relative_time']}")
            if time_context.get('absolute_start') or time_context.get('absolute_end'):
                if time_context.get('absolute_start'):
                    time_lines.append(f"  • Start Time: {time_context['absolute_start']}")
                if time_context.get('absolute_end'):
                    time_lines.append(f"  • End Time: {time_context['absolute_end']}")
            
            if time_lines:
                time_context_section = "\nTime Context:\n" + "\n".join(time_lines)
        
        planning_prompt = f"""You are creating a technical plan to retrieve data from Check Point security platform MCP servers.

User Query: "{user_query}"

QUERY CLASSIFICATION: {query_type}
{instructions}

Available MCP Servers:
{capabilities_desc}
{network_context_text}
Active Servers: {', '.join(active_server_types) if active_server_types else 'None'}{gateway_executor_instructions}

User Intent:
- Task: {task_type}
- Goal: {primary_goal}
- Data Needed: {', '.join(data_types)}
- Time Scope: {time_scope} {f"({specific_period})" if specific_period else ""}
{f"- Filters: {', '.join(filters)}" if filters else ""}{entities_section}{time_context_section}
{f"- File Path: {file_path}" if file_path else ""}

MANDATORY SERVER SELECTION:
You MUST select ONLY from allowed servers: {', '.join(allowed_servers)}
You MUST NOT select forbidden servers: {', '.join(forbidden_servers) if forbidden_servers else 'None'}

CRITICAL TOOL NAMING RULES - NO EXCEPTIONS:
1. Use ONLY exact tool names from the "Tools:" lists in the capabilities above
2. NEVER create descriptive tool names like "show_logs:traffic_analysis" or "run_script:fw stat"
3. NEVER add colons, descriptions, or parameters to tool names
4. Valid examples: "show_logs", "show_access_rulebase", "show_nat_rulebase"
5. Invalid examples: "show_logs:anything", "traffic_analysis", "fw stat", "run_script"
6. If a tool doesn't exist in the Tools list, DO NOT use it

VPN TRAFFIC DISTINCTION (CRITICAL):
- VPN CLIENT connections → Regular traffic logs (no special blade filter needed) - appears in normal firewall logs
- VPN SITE-TO-SITE connections → VPN blade logs (requires VPN blade filter) - appears in VPN-specific logs
- For connectivity troubleshooting: Consider BOTH logs AND gateway diagnostic tools (run_script) when available

CONNECTIVITY TROUBLESHOOTING GUIDANCE:
- For connection/connectivity issues: Combine management-logs (traffic analysis) with gateway diagnostic tools
- Gateway diagnostics can reveal routing, interface, or tunnel issues not visible in logs alone
- Example tools: Check routing tables, interface status, VPN tunnel state, connection tracking

Return a JSON execution plan:
{{
    "understanding": "{primary_goal}",
    "required_servers": ["server names to query"],
    "data_to_fetch": ["exact tool names from Tools list above"],
    "analysis_type": "{task_type}",
    "time_parameters": {{
        "time_scope": "{time_scope}",
        "specific_period": "{specific_period if specific_period else 'not_applicable'}"
    }},
    "execution_steps": [
        {{"step": 1, "action": "describe action", "server": "server-name"}}
    ],
    "expected_output": "expected format"
}}

Technical Execution Plan:"""

        # Use specified planner model or default to ollama general model
        if planner_model:
            client, model_name = self._get_client_for_model(planner_model)
        else:
            client = self.ollama_client
            model_name = self.ollama_client.general_model
        
        # Use appropriate client for planning
        try:
            response = client.generate_response(
                prompt=planning_prompt,
                model=model_name,
                temperature=0.3  # Low temperature for more structured output
            )
        except Exception as api_error:
            # Catch API errors and return them to user
            error_msg = str(api_error)
            print(f"[QueryOrchestrator] API Error during planning: {error_msg}")
            return {
                "error": f"API Error: {error_msg}",
                "understanding": f"⚠️ {error_msg}",
                "required_servers": [],
                "execution_steps": [],
                "user_query": user_query  # Include for session context caching
            }
        
        if not response:
            return {
                "error": "Failed to create execution plan",
                "understanding": "Could not analyze query",
                "required_servers": [],
                "execution_steps": [],
                "user_query": user_query  # Include for session context caching
            }
        
        # Parse JSON response
        try:
            # Extract JSON from response (in case there's extra text)
            json_start = response.find('{')
            json_end = response.rfind('}') + 1
            if json_start >= 0 and json_end > json_start:
                json_str = response[json_start:json_end]
                plan = json.loads(json_str)
                
                # CRITICAL: ENFORCE server selection based on query classification
                if 'required_servers' in plan:
                    original_servers = plan['required_servers']
                    
                    # Filter out forbidden servers and ensure allowed servers are included
                    validated_servers = []
                    for server in original_servers:
                        if server in forbidden_servers:
                            print(f"[QueryOrchestrator] ❌ REJECTED forbidden server '{server}' for {query_type} query")
                        elif server in allowed_servers:
                            validated_servers.append(server)
                        else:
                            # Server not in allowed list but also not forbidden (e.g., reputation-service)
                            # Allow it if not explicitly forbidden
                            if server in active_server_types:
                                validated_servers.append(server)
                    
                    # For PURE_THREAT queries, ensure ONLY management-logs is used (actual threat data)
                    if query_type == "PURE_THREAT":
                        if "management-logs" not in validated_servers and "management-logs" in active_server_types:
                            print(f"[QueryOrchestrator] ✅ ADDED required server 'management-logs' for {query_type} query (actual threat events)")
                            validated_servers.append("management-logs")
                        # Remove any policy/config servers that shouldn't be there
                        policy_servers = ["threat-prevention", "https-inspection", "quantum-management"]
                        for policy_server in policy_servers:
                            if policy_server in validated_servers:
                                validated_servers.remove(policy_server)
                                print(f"[QueryOrchestrator] ❌ REMOVED policy server '{policy_server}' from {query_type} query (not threat data)")
                    
                    # Update plan with validated servers
                    if validated_servers != original_servers:
                        print(f"[QueryOrchestrator] 🔄 Server list corrected: {original_servers} → {validated_servers}")
                        plan['required_servers'] = validated_servers
                
                # CRITICAL: Inject user_query, query_type, and intent into plan for session context caching and validation
                plan['user_query'] = user_query
                plan['query_type'] = query_type
                plan['intent'] = intent  # Store intent for session context updates
                return plan
            else:
                # Fallback: create basic plan
                return self._create_fallback_plan(user_query)
        except json.JSONDecodeError as e:
            print(f"Failed to parse execution plan: {e}")
            print(f"Response was: {response}")
            return self._create_fallback_plan(user_query)
    
    def execute_plan(self, plan: Dict[str, Any], user_parameter_selections: Optional[Dict[str, str]] = None, user_query: Optional[str] = None) -> Dict[str, Any]:
        """Execute the plan by querying MCP servers and collecting data
        
        Args:
            plan: Execution plan from planner
            user_parameter_selections: User-selected values for ambiguous parameters
            user_query: Original user query for session context (overrides plan['user_query'] if provided)
        """
        
        results = {
            "plan_summary": plan.get("understanding", ""),
            "servers_queried": [],
            "data_collected": {},
            "errors": [],
            "warnings": []
        }
        
        required_servers = plan.get("required_servers", [])
        all_servers = self.mcp_manager.get_all_servers()
        
        print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] All configured servers: {list(all_servers.keys())}")
        print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Required servers: {required_servers}")
        
        # Update session context with current query (for conversational caching)
        # Use parameter user_query if provided, otherwise fall back to plan['user_query']
        query_text = user_query if user_query else plan.get("user_query", "")
        intent = plan.get("intent")  # Get intent if stored in plan
        self._update_session_context(query_text, plan, intent)  # Pass plan and intent for full context extraction
        
        # Apply session context to data_to_fetch (inject cached gateway if applicable)
        data_to_fetch = self._apply_session_context(plan.get("data_to_fetch", []), query_text)
        
        # PRIORITY VALIDATION: Ensure management sources are primary for ANY data-oriented queries
        # This runs for ALL queries to ensure management-logs is used when needed
        query_lower = query_text.lower()
        
        # Expanded detection: ANY data/log/traffic/security query needs management sources
        # Only specific security/data nouns - NO generic verbs, NO time keywords (time is contextual)
        security_data_keywords = [
            # Log/event keywords
            'log', 'logs', 'event', 'events', 'alert', 'alerts',
            # Threat/security keywords
            'threat', 'threats', 'suspicious', 'attack', 'attacks', 'malicious', 'intrusion', 'incident', 'incidents',
            # Traffic/connection keywords (specific data context)
            'traffic', 'connection', 'connections', 'connectivity', 'session', 'sessions', 'flow', 'flows',
            # Troubleshooting/issue keywords
            'issue', 'problem', 'fail', 'failure', 'error', 'timeout', 'unable', 'cannot', 'not working',
            # Action keywords (security-related)
            'dropped', 'blocked', 'rejected', 'denied', 'accepted', 'allowed',
            # Security investigation keywords
            'malware', 'virus', 'exploit', 'vulnerability', 'breach'
        ]
        
        # Time keywords (only meaningful when combined with security/data keywords)
        time_keywords = ['last', 'days', 'hours', 'minutes', 'yesterday', 'past', 'week', 'month', 'ago', 'since', 'from', 'to', 'recent']
        
        # Pure diagnostic keywords (system/gateway health checks)
        pure_diagnostic_keywords = ['health', 'cpu', 'memory', 'disk', 'uptime', 'performance', 'status', 'cluster', 'interface', 'ha', 'gateway', 'firewall']
        
        # Data query detection: security/data keywords present (time keywords alone don't count)
        has_security_data = any(keyword in query_lower for keyword in security_data_keywords)
        has_time_context = any(keyword in query_lower for keyword in time_keywords)
        has_data_query = has_security_data  # Only security/data keywords trigger, not time alone
        is_pure_diagnostic = any(keyword in query_lower for keyword in pure_diagnostic_keywords) and not has_data_query
        has_logs_server = 'management-logs' in required_servers
        
        # Check if run_script commands are present (for supplemental diagnostics)
        run_script_commands = []
        if self.gateway_script_executor:
            run_script_commands = [item for item in data_to_fetch if isinstance(item, str) and item.startswith("run_script:")]
        
        # RULE: If it's a data query OR management-logs already selected, ENSURE management-logs is PRIMARY
        # run_script can run as supplemental, but management-logs must be primary for data queries
        if (has_data_query or has_logs_server) and not is_pure_diagnostic:
            print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] PRIORITY VALIDATION: Data query detected (data_query={has_data_query}, logs_server={has_logs_server}, pure_diagnostic={is_pure_diagnostic})")
            
            # Ensure management-logs is PRIMARY source (add it if missing)
            if 'management-logs' not in required_servers:
                required_servers.insert(0, 'management-logs')  # Insert at beginning for priority
                print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Auto-added management-logs as PRIMARY source for data query")
                
                if run_script_commands:
                    results["warnings"].append(
                        "ℹ️ Using management-logs MCP as primary data source with gateway diagnostics as supplemental context."
                    )
        
        # DEPENDENCY INJECTION: quantum-gw-cli requires quantum-management for gateway discovery
        # Auto-add quantum-management if quantum-gw-cli is selected but quantum-management is not
        if 'quantum-gw-cli' in required_servers and 'quantum-management' not in required_servers:
            if 'quantum-management' in all_servers:
                required_servers.insert(0, 'quantum-management')  # Add at beginning for Phase 1 execution
                print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Auto-injected quantum-management dependency for quantum-gw-cli")
            else:
                results["warnings"].append(
                    "⚠️ quantum-gw-cli requires quantum-management for gateway discovery, but quantum-management is not configured."
                )
        
        # PARALLEL EXECUTION: Query all required servers simultaneously
        import asyncio
        
        # CRITICAL FIX: quantum-management must run FIRST to populate gateway directory
        # before quantum-gw-cli tries to resolve IPs to gateway names
        async def run_queries_with_dependencies():
            """Execute queries with dependency handling for gateway directory"""
            all_results = []
            server_task_map = {}
            
            # Phase 1: Execute quantum-management first if it's required
            # This populates the gateway directory before other servers need it
            if 'quantum-management' in required_servers and 'quantum-management' in all_servers:
                print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Phase 1: Querying quantum-management first (gateway directory dependency)")
                try:
                    mgmt_result = await self._query_mcp_server_async('quantum-management', data_to_fetch, user_parameter_selections, query_text)
                    all_results.append(mgmt_result)
                    server_task_map[0] = 'quantum-management'
                    
                    # Update gateway directory immediately after quantum-management completes
                    if mgmt_result and 'tool_results' in mgmt_result:
                        self._update_gateway_directory_from_results(mgmt_result['tool_results'])
                        print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Gateway directory updated, ready for quantum-gw-cli")
                except Exception as e:
                    # Capture exception (same behavior as return_exceptions=True in asyncio.gather)
                    print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] quantum-management failed: {e}")
                    all_results.append(e)
                    server_task_map[0] = 'quantum-management'
                    results["errors"].append(f"Server 'quantum-management' failed: {str(e)}")
                
                # Remove quantum-management from list (already processed)
                remaining_servers = [s for s in required_servers if s != 'quantum-management']
            else:
                remaining_servers = required_servers
            
            # Phase 2: Execute remaining servers in parallel
            if remaining_servers:
                tasks = []
                task_start_index = len(all_results)
                
                for server_name in remaining_servers:
                    if server_name in all_servers:
                        task = self._query_mcp_server_async(server_name, data_to_fetch, user_parameter_selections, query_text)
                        tasks.append(task)
                        server_task_map[task_start_index + len(tasks) - 1] = server_name
                    else:
                        results["errors"].append(f"Required server '{server_name}' is not configured. Please add it in MCP Servers page.")
                
                if tasks:
                    print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Phase 2: Querying {len(tasks)} servers in parallel")
                    parallel_results = await asyncio.gather(*tasks, return_exceptions=True)
                    all_results.extend(parallel_results)
            
            return all_results, server_task_map
        
        # Execute queries with dependency handling
        if required_servers:
            num_servers = len([s for s in required_servers if s in all_servers])
            print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Executing {num_servers} MCP server queries in PARALLEL...")
            
            if self.progress_callback:
                self.progress_callback(f"🔌 Querying {num_servers} MCP tool(s) in parallel...")
            
            # Streamlit-compatible async execution: check for existing event loop
            try:
                # Try to get the running event loop (Streamlit/async contexts)
                loop = asyncio.get_running_loop()
                # If we have a running loop, we need to use nest_asyncio or run in executor
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    future = executor.submit(asyncio.run, run_queries_with_dependencies())
                    parallel_results, server_task_map = future.result()
            except RuntimeError:
                # No running event loop, safe to use asyncio.run()
                parallel_results, server_task_map = asyncio.run(run_queries_with_dependencies())
            
            # Process results from parallel execution
            for idx, result in enumerate(parallel_results):
                server_name = server_task_map.get(idx)
                
                # Handle exceptions from parallel execution
                if isinstance(result, Exception):
                    print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Server '{server_name}' raised exception: {result}")
                    results["errors"].append(f"Server '{server_name}' failed: {str(result)}")
                    continue
                
                # At this point, result is definitely a Dict (not an Exception)
                if not result or not isinstance(result, dict):
                    continue
                
                server_data = result
                    
                # Check if server needs user input for parameters
                if server_data.get("needs_user_input"):
                    return {
                        "needs_user_input": True,
                        "parameter_options": server_data.get("parameter_options", {}),
                        "plan_summary": plan.get("understanding", ""),
                        "servers_queried": results["servers_queried"]
                    }
                
                results["servers_queried"].append(server_name)
                
                # Check for API errors in tool results
                tool_results = server_data.get("tool_results", [])
                api_errors = []
                successful_tools = []
                
                for tool_result in tool_results:
                    # Check for exceptions during tool execution
                    if "error" in tool_result:
                        error_cat = tool_result.get("error_category", "unknown")
                        if error_cat == "missing_parameter":
                            results["warnings"].append(
                                f"Server '{server_name}' tool '{tool_result['tool']}' needs additional parameters. "
                                f"This is a limitation of the MCP server package."
                            )
                        else:
                            results["warnings"].append(
                                f"Server '{server_name}' tool '{tool_result['tool']}' failed: {tool_result.get('error', 'Unknown error')}"
                            )
                    # Check for API errors in successful tool execution
                    elif tool_result.get("result", {}).get("isError"):
                        api_error_msg = tool_result.get("result", {}).get("api_error")
                        if api_error_msg:
                            api_errors.append({
                                "tool": tool_result["tool"],
                                "error": api_error_msg
                            })
                            results["warnings"].append(
                                f"Check Point API error in '{server_name}' tool '{tool_result['tool']}': {api_error_msg}"
                            )
                        else:
                            # Generic error without specific message
                            results["warnings"].append(
                                f"Server '{server_name}' tool '{tool_result['tool']}' returned an error"
                            )
                    else:
                        # Tool executed successfully
                        successful_tools.append(tool_result)
                
                # Log API errors but continue with successful tools
                if api_errors:
                    print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Server '{server_name}' had {len(api_errors)} API errors but {len(successful_tools)} successful tools")
                    server_data["api_errors"] = api_errors
                
                results["data_collected"][server_name] = server_data
                
                # Update gateway directory if gateways discovered from quantum-management
                if server_name == 'quantum-management':
                    self._update_gateway_directory_from_results(tool_results)
        
        return results
    
    async def _query_mcp_server_async(self, server_name: str, data_points: List[str], user_parameter_selections: Optional[Dict[str, str]] = None, user_query: str = "") -> Optional[Dict[str, Any]]:
        """Query a specific MCP server for data using MCP protocol (async version)
        
        Args:
            server_name: The name of the server (e.g., 'management-logs', 'quantum-management')
            data_points: List of data points to fetch
            user_parameter_selections: User-selected values for ambiguous parameters
            user_query: Original user query for context
        """
        from services.mcp_client_simple import query_mcp_server_async
        
        # Get all servers
        servers = self.mcp_manager.get_all_servers()
        
        # Check if server exists in config
        if server_name not in servers:
            return None
        
        server_config = servers[server_name]
        package_name = server_config.get('package')
        
        if not package_name:
            return {"error": f"No package name configured for server {server_name}"}
        
        # Get environment variables for authentication
        # Credentials are decrypted and populated in 'env' field by MCP manager
        env_vars = server_config.get('env', {})
        
        # AUTOMATIC GATEWAY CREDENTIAL SHARING
        # If querying gateway-specific MCPs and SSH credentials missing, try to clone from configured gateway
        if server_name in ['quantum-gw-cli', 'quantum-gw-connection-analysis'] and not env_vars.get('SSH_USERNAME'):
            # Check if admin consented to credential sharing
            import json
            from pathlib import Path
            config_file = Path('./config/app_config.json')
            consent_enabled = False
            if config_file.exists():
                try:
                    with open(config_file, 'r') as f:
                        config = json.load(f)
                        consent_enabled = config.get('auto_share_gateway_credentials', False)
                except:
                    pass
            
            if consent_enabled:
                # Extract gateway name from data_points
                gateway_name = None
                for dp in data_points:
                    if isinstance(dp, str) and ('gateway_identifier:' in dp or 'gateway:' in dp):
                        gateway_name = dp.split(':', 1)[1]
                        break
                
                if gateway_name:
                    # Get gateway IP from directory
                    gateway_ip = self.gateway_directory.get_gateway_ip(gateway_name)
                    
                    if gateway_ip:
                        # Find ANY configured quantum-gw-cli with SSH credentials
                        for srv_name, srv_config in servers.items():
                            if srv_config.get('package') == '@chkp/quantum-gw-cli-mcp':
                                srv_env = srv_config.get('env', {})
                                if srv_env.get('SSH_USERNAME') and srv_env.get('SSH_PASSWORD'):
                                    # Clone SSH credentials and override GATEWAY_HOST
                                    env_vars['SSH_USERNAME'] = srv_env['SSH_USERNAME']
                                    env_vars['SSH_PASSWORD'] = srv_env['SSH_PASSWORD']
                                    env_vars['GATEWAY_HOST'] = gateway_ip
                                    print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] ✓ Auto-shared SSH credentials for gateway '{gateway_name}' ({gateway_ip}) from '{srv_name}'")
                                    break
        
        # AUTO-PASS GAIA WEB CREDENTIALS (same as SSH)
        # quantum-gaia MCP connects to GAIA web API which uses same credentials as SSH
        if server_name == 'quantum-gaia':
            # If SSH credentials already configured, pass them to GAIA
            if env_vars.get('SSH_USERNAME') and env_vars.get('SSH_PASSWORD'):
                env_vars['GAIA_USERNAME'] = env_vars['SSH_USERNAME']
                env_vars['GAIA_PASSWORD'] = env_vars['SSH_PASSWORD']
                print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] ✓ Auto-passed SSH credentials to GAIA web API (username: {env_vars['SSH_USERNAME']})")
            
            # If no SSH credentials, try credential sharing (same logic as quantum-gw-cli)
            elif not env_vars.get('SSH_USERNAME'):
                # Check if admin consented to credential sharing
                import json
                from pathlib import Path
                config_file = Path('./config/app_config.json')
                consent_enabled = False
                if config_file.exists():
                    try:
                        with open(config_file, 'r') as f:
                            config = json.load(f)
                            consent_enabled = config.get('auto_share_gateway_credentials', False)
                    except:
                        pass
                
                if consent_enabled:
                    # Extract gateway name from data_points
                    gateway_name = None
                    for dp in data_points:
                        if isinstance(dp, str) and ('gateway_identifier:' in dp or 'gateway:' in dp):
                            gateway_name = dp.split(':', 1)[1]
                            break
                    
                    if gateway_name:
                        # Get gateway IP from directory
                        gateway_ip = self.gateway_directory.get_gateway_ip(gateway_name)
                        
                        if gateway_ip:
                            # Find ANY configured gateway with SSH credentials
                            for srv_name, srv_config in servers.items():
                                if srv_config.get('package') in ['@chkp/quantum-gw-cli-mcp', '@chkp/quantum-gaia-mcp']:
                                    srv_env = srv_config.get('env', {})
                                    if srv_env.get('SSH_USERNAME') and srv_env.get('SSH_PASSWORD'):
                                        # Clone SSH credentials and override GATEWAY_HOST
                                        env_vars['SSH_USERNAME'] = srv_env['SSH_USERNAME']
                                        env_vars['SSH_PASSWORD'] = srv_env['SSH_PASSWORD']
                                        env_vars['GATEWAY_HOST'] = gateway_ip
                                        # Also set GAIA credentials
                                        env_vars['GAIA_USERNAME'] = srv_env['SSH_USERNAME']
                                        env_vars['GAIA_PASSWORD'] = srv_env['SSH_PASSWORD']
                                        print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] ✓ Auto-shared SSH credentials for GAIA on gateway '{gateway_name}' ({gateway_ip}) from '{srv_name}'")
                                        break
        
        # CRITICAL FIX: quantum-gw-cli needs BOTH gateway SSH + management server credentials
        # Copy management credentials from quantum-management if querying quantum-gw-cli
        if server_name == 'quantum-gw-cli' and 'quantum-management' in servers:
            mgmt_env = servers['quantum-management'].get('env', {})
            # Copy management server credentials (S1C_URL, API_KEY, MANAGEMENT_HOST, PORT, USERNAME, PASSWORD)
            # Gateway SSH credentials (GATEWAY_HOST, SSH_USERNAME, SSH_PASSWORD) already in env_vars
            for key in ['S1C_URL', 'API_KEY', 'CLOUD_INFRA_TOKEN', 'MANAGEMENT_HOST', 'PORT', 'USERNAME', 'PASSWORD']:
                if key in mgmt_env and key not in env_vars:
                    env_vars[key] = mgmt_env[key]
            print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Copied management credentials to quantum-gw-cli: {list(mgmt_env.keys())}")
        
        # Use the simplified MCP client to query the server
        # This will start its own subprocess, connect, query, and clean up
        try:
            # Pass session gateway for reliable target_gateway auto-fill
            session_gw = self.session_context.get("last_gateway")
            results = await query_mcp_server_async(package_name, env_vars, data_points, user_parameter_selections, True, user_query, False, session_gw)
            
            # Add server name to results
            results["server_name"] = server_name
            
            return results
            
        except Exception as e:
            print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Error querying MCP server {server_name}: {e}")
            import traceback
            traceback.print_exc()
            return {"error": str(e), "server_name": server_name}
    
    def _query_mcp_server(self, server_name: str, data_points: List[str], user_parameter_selections: Optional[Dict[str, str]] = None, user_query: str = "") -> Optional[Dict[str, Any]]:
        """Query a specific MCP server for data using MCP protocol (synchronous wrapper)
        
        Args:
            server_name: The name of the server (e.g., 'management-logs', 'quantum-management')
            data_points: List of data points to fetch
            user_parameter_selections: User-selected values for ambiguous parameters
        """
        import asyncio
        return asyncio.run(self._query_mcp_server_async(server_name, data_points, user_parameter_selections, user_query))
    
    def _reduce_context_intelligently(self, data_collected: Dict[str, Any], max_tokens: int) -> Dict[str, Any]:
        """Intelligently reduce context size while preserving critical information
        
        Args:
            data_collected: Original MCP server data
            max_tokens: Target maximum tokens (characters / 4)
            
        Returns:
            Reduced data dictionary that fits within token budget
        """
        # Stage 1: Create initial reduced version
        reduced_data = {}
        
        for server_name, server_data in data_collected.items():
            reduced_server = {
                "server_name": server_data.get("server_name"),
                "tool_results": [],
                "discovered_resources": server_data.get("discovered_resources", {})
            }
            
            # Copy API errors (critical info)
            if "api_errors" in server_data:
                reduced_server["api_errors"] = server_data["api_errors"]
            
            # Process tool results
            tool_results = server_data.get("tool_results", [])
            for tool_result in tool_results:
                reduced_tool = self._summarize_tool_result(tool_result, max_chars=3000)
                if reduced_tool:
                    reduced_server["tool_results"].append(reduced_tool)
            
            # Limit discovered resources
            if "discovered_resources" in reduced_server:
                for tool_name, resources in list(reduced_server["discovered_resources"].items()):
                    if isinstance(resources, list) and len(resources) > 15:
                        reduced_server["discovered_resources"][tool_name] = resources[:15] + [
                            {"name": f"[{len(resources)-15} more items]", "type": "summary"}
                        ]
            
            reduced_data[server_name] = reduced_server
        
        # Stage 2: Iteratively reduce until under budget
        # Note: Using char-based estimation (1 token ≈ 4 chars) as we don't have a tokenizer
        # This is a standard approximation that works well for most content
        max_chars = max_tokens * 4
        attempts = 0
        max_attempts = 5
        
        while attempts < max_attempts:
            current_json = json.dumps(reduced_data, indent=2)
            current_size = len(current_json)
            
            if current_size <= max_chars:
                print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Context fits within budget after {attempts} reduction passes")
                break
            
            print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Reduction pass {attempts+1}: {current_size} chars, target {max_chars}")
            
            # Calculate per-tool char budget based on remaining size
            char_budget_per_tool = max(500, 2000 // (attempts + 1))
            
            for server_name, server_data in reduced_data.items():
                # Reduce tool results
                tool_results = server_data.get("tool_results", [])
                
                # First limit number of tools if too many
                if len(tool_results) > 3:
                    server_data["tool_results"] = tool_results[:3] + [{
                        "tool": "summary",
                        "result": {"content": [{"type": "text", "text": f"[{len(tool_results)-3} additional tools truncated]"}]}
                    }]
                    tool_results = server_data["tool_results"]
                
                # Then reduce content in each remaining tool
                for tool_result in tool_results:
                    if "result" in tool_result and "content" in tool_result["result"]:
                        tool_result["result"]["content"] = self._truncate_content(
                            tool_result["result"]["content"], 
                            max_chars=char_budget_per_tool
                        )
                
                # Reduce discovered resources with char limits
                if "discovered_resources" in server_data:
                    # Progressive reduction: 10 -> 5 -> 3 -> 2 -> 1
                    max_resources = max(1, 10 // (attempts + 1))
                    for tool_name, resources in list(server_data["discovered_resources"].items()):
                        if isinstance(resources, list):
                            if len(resources) > max_resources:
                                server_data["discovered_resources"][tool_name] = resources[:max_resources] + [
                                    {"name": f"[{len(resources)-max_resources} more]", "type": "summary"}
                                ]
                            # Summarize each resource to limit char size
                            resource_char_limit = max(50, 200 // (attempts + 1))
                            server_data["discovered_resources"][tool_name] = [
                                self._limit_resource_size(r, max_chars=resource_char_limit)
                                for r in server_data["discovered_resources"][tool_name]
                            ]
            
            attempts += 1
        
        # Final safety check: if still oversized, do emergency truncation
        final_json = json.dumps(reduced_data, indent=2)
        if len(final_json) > max_chars:
            print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] EMERGENCY: Still {len(final_json)} chars after {attempts} passes, applying final truncation")
            # Aggressive emergency truncation: keep only critical error info
            emergency_data = {}
            for server_name, server_data in list(reduced_data.items())[:1]:
                # Collect only errors and API failures
                error_tools = [
                    r for r in server_data.get("tool_results", [])
                    if "error" in r or r.get("result", {}).get("isError")
                ]
                
                emergency_data[server_name] = {
                    "server_name": server_name,
                    "tool_results": error_tools[:2],  # Max 2 error entries
                    "summary": f"EMERGENCY TRUNCATION: Reduced from {len(final_json):,} chars. Showing critical errors only."
                }
                
                if "api_errors" in server_data:
                    emergency_data[server_name]["api_errors"] = server_data["api_errors"][:3]  # Max 3 API errors
            
            reduced_data = emergency_data
            print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Emergency truncation complete: {len(json.dumps(reduced_data)):,} chars")
        
        return reduced_data
    
    def _sequential_chunked_analysis(
        self, 
        context: str, 
        analysis_prompt: str,
        user_query: str,
        client,
        model_name: str,
        chunk_size_tokens: int
    ) -> str:
        """Perform sequential chunked analysis to preserve full field-level detail
        
        This method:
        1. Splits context into chunks that fit token limits
        2. Sends chunks sequentially with "store, do not analyze" instruction
        3. Sends final chunk with "now analyze everything" instruction
        4. LLM accumulates all data in context before analyzing
        
        This preserves pattern recognition (low & slow attacks, temporal correlations)
        while staying within token limits.
        
        Args:
            context: Full context data to analyze
            analysis_prompt: The analysis instructions
            user_query: Original user question
            client: LLM client (OpenRouter or Ollama)
            model_name: Model to use
            chunk_size_tokens: Maximum tokens per chunk
            
        Returns:
            Final analysis result from LLM
        """
        print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Starting sequential chunked analysis...")
        
        # Calculate chunks
        chunk_size_chars = chunk_size_tokens * 4
        total_chars = len(context)
        chunks = []
        
        # Split context into chunks (preserve complete lines)
        current_pos = 0
        while current_pos < total_chars:
            end_pos = min(current_pos + chunk_size_chars, total_chars)
            
            # Try to break at a newline to preserve log entry integrity
            if end_pos < total_chars:
                # Look back up to 1000 chars for a good break point
                search_back = min(1000, end_pos - current_pos)
                chunk_text = context[current_pos:end_pos]
                last_newline = chunk_text.rfind('\n', -search_back)
                
                if last_newline > 0:
                    end_pos = current_pos + last_newline + 1
            
            chunk = context[current_pos:end_pos]
            chunks.append(chunk)
            current_pos = end_pos
        
        total_chunks = len(chunks)
        print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Split context into {total_chunks} chunks (~{chunk_size_tokens:,} tokens each)")
        
        # TRUE multi-turn conversation for sequential chunk processing
        # Each API call builds on previous conversation history
        # This allows the LLM to accumulate data across multiple calls without hitting token limits per call
        
        # Check if client supports conversation history
        if not hasattr(client, 'generate_response_with_history'):
            print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Client doesn't support conversation history - using single-request chunking")
            # Fallback: send all chunks in one request with markers
            return self._single_request_chunked_analysis(chunks, total_chunks, user_query, analysis_prompt, client, model_name)
        
        # Initialize conversation with system instruction
        messages = [{
            "role": "system",
            "content": f"""You are a CheckPoint security analyst. You will receive security log data in {total_chunks} sequential chunks.

CRITICAL INSTRUCTIONS:
1. For chunks 1-{total_chunks-1}: Acknowledge receipt and store the data in your memory. DO NOT ANALYZE YET.
2. For chunk {total_chunks} (final): Perform comprehensive analysis across ALL chunks received.
3. Look for patterns across the entire dataset: low & slow attacks, temporal correlations, multi-stage attacks.
4. Each log entry contains: time, source, destination, ports, protocol, action, blade, severity.

Your memory will preserve all previous chunks as we proceed."""
        }]
        
        # Sequential chunk submission with conversation history
        for i, chunk in enumerate(chunks):
            chunk_num = i + 1
            is_final = (chunk_num == total_chunks)
            
            if is_final:
                # Final chunk: trigger analysis
                user_message = f"""This is CHUNK {chunk_num} of {total_chunks} (FINAL).

{chunk}

{'='*80}
ANALYSIS REQUIRED
{'='*80}

User's Question: "{user_query}"

You have now received ALL {total_chunks} chunks. Perform comprehensive analysis:

{analysis_prompt}

CRITICAL REQUIREMENTS:
- Analyze ALL chunks (1-{total_chunks}), not just this final one
- Count total events across all chunks for exact statistics  
- Correlate events temporally to detect low & slow attacks
- Identify attack patterns that span multiple chunks
- Report specific IOCs, IPs, ports, and threats found across the entire dataset

Begin comprehensive analysis now."""
            else:
                # Intermediate chunk: store only
                user_message = f"""This is CHUNK {chunk_num} of {total_chunks}.

{chunk}

Please acknowledge receipt. Store this data in your memory. DO NOT analyze yet - wait for all {total_chunks} chunks."""
            
            # Add user message to conversation
            messages.append({"role": "user", "content": user_message})
            
            print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Sending chunk {chunk_num}/{total_chunks} to LLM (conversation turn {len(messages)//2})...")
            
            # Make API call with full conversation history
            response = client.generate_response_with_history(
                messages=messages,
                model=model_name,
                max_tokens=None,  # Auto-calculate based on context
                temperature=0.1 if is_final else 0.3
            )
            
            if not response:
                return f"Failed to process chunk {chunk_num}/{total_chunks}. Analysis incomplete."
            
            # Add assistant response to conversation
            messages.append({"role": "assistant", "content": response})
            
            if is_final:
                print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] ✓ Sequential conversation complete - analyzed all {total_chunks} chunks")
                print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Final conversation: {len(messages)} messages, {len(messages)//2} turns")
                return response
            else:
                print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] ✓ Chunk {chunk_num} stored in conversation (response: {len(response)} chars)")
        
        return "Sequential chunked conversation completed but no final analysis received."
    
    def _single_request_chunked_analysis(self, chunks, total_chunks, user_query, analysis_prompt, client, model_name):
        """Fallback: Send all chunks in single request with clear markers (for clients without conversation support)"""
        accumulated_context = "SECURITY LOG DATA - ALL CHUNKS\n\n"
        
        for i, chunk in enumerate(chunks):
            accumulated_context += f"\n{'='*80}\nCHUNK {i+1} of {total_chunks}\n{'='*80}\n\n{chunk}\n"
        
        accumulated_context += f"\n{'='*80}\nANALYSIS REQUIRED\n{'='*80}\n\nUser's Question: \"{user_query}\"\n\n{analysis_prompt}\n\nAnalyze ALL {total_chunks} chunks above."
        
        print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Sending {total_chunks} chunks in single request (~{len(accumulated_context)//4:,} tokens)")
        
        response = client.generate_response(
            prompt="",
            model=model_name,
            context=accumulated_context,
            temperature=0.1,
            max_tokens=None if client.__class__.__name__ == 'OpenRouterClient' else 4000
        )
        
        return response if response else "Single-request chunked analysis failed."
    
    def _extract_log_metadata(self, data_collected: Dict[str, Any]) -> str:
        """Extract structured metadata from log data for preservation during truncation
        
        Args:
            data_collected: Complete MCP server data with logs
            
        Returns:
            Formatted metadata summary string with total counts, distributions, time range
        """
        metadata_lines = []
        total_logs = 0
        blade_counts = {}
        severity_counts = {}
        earliest_time = None
        latest_time = None
        
        # Scan all servers for log data
        for server_name, server_data in data_collected.items():
            # Skip non-dict entries (e.g., gateway_script_executor is a list)
            if not isinstance(server_data, dict):
                continue
            
            tool_results = server_data.get("tool_results", [])
            
            for tool_result in tool_results:
                result = tool_result.get("result", {})
                content = result.get("content", [])
                
                # Look for log arrays in content
                for item in content:
                    if isinstance(item, dict) and 'text' in item:
                        try:
                            import json
                            data = json.loads(item['text'])
                            
                            # Check for logs array
                            if 'logs' in data and isinstance(data['logs'], list):
                                logs = data['logs']
                                log_count = len(logs)
                                total_logs += log_count
                                
                                # Extract blade and severity distributions
                                for log in logs:
                                    # Blade distribution
                                    blade = log.get('blade', 'Unknown')
                                    blade_counts[blade] = blade_counts.get(blade, 0) + 1
                                    
                                    # Severity distribution
                                    severity = log.get('severity', log.get('log_level', 'Unknown'))
                                    severity_counts[severity] = severity_counts.get(severity, 0) + 1
                                    
                                    # Time range tracking
                                    time_val = log.get('time', log.get('timestamp'))
                                    if time_val:
                                        if earliest_time is None or time_val < earliest_time:
                                            earliest_time = time_val
                                        if latest_time is None or time_val > latest_time:
                                            latest_time = time_val
                            
                            # Also check for threat_logs or other log variants
                            for log_field in ['threat_logs', 'audit_logs', 'connection_logs']:
                                if log_field in data and isinstance(data[log_field], list):
                                    total_logs += len(data[log_field])
                        except:
                            pass
        
        # Build metadata summary
        if total_logs > 0:
            metadata_lines.append(f"TOTAL LOGS ANALYZED: {total_logs:,}")
            
            if earliest_time and latest_time:
                metadata_lines.append(f"TIME RANGE: {earliest_time} to {latest_time}")
            
            if blade_counts:
                metadata_lines.append("\nEVENTS BY BLADE:")
                for blade, count in sorted(blade_counts.items(), key=lambda x: x[1], reverse=True):
                    metadata_lines.append(f"  - {blade}: {count:,} events")
            
            if severity_counts:
                metadata_lines.append("\nEVENTS BY SEVERITY:")
                for severity, count in sorted(severity_counts.items(), key=lambda x: x[1], reverse=True):
                    metadata_lines.append(f"  - {severity}: {count:,} events")
            
            metadata_lines.append(f"\n⚠️ IMPORTANT: Base your analysis on these exact counts, not the sample data below.")
        
        return "\n".join(metadata_lines) if metadata_lines else ""
    
    def _limit_resource_size(self, resource: Dict[str, Any], max_chars: int) -> Dict[str, Any]:
        """Limit the size of a discovered resource object"""
        if not isinstance(resource, dict):
            return resource
        
        # Keep only essential fields
        limited = {}
        total_chars = 0
        for key in ["name", "type", "uid"]:
            if key in resource:
                val_str = str(resource[key])
                if total_chars + len(val_str) <= max_chars:
                    limited[key] = resource[key]
                    total_chars += len(val_str)
        
        return limited if limited else resource
    
    def _summarize_tool_result(self, tool_result: Dict[str, Any], max_chars: int = 3000) -> Optional[Dict[str, Any]]:
        """Summarize a single tool result, preserving structure and key info"""
        # Always keep errors
        if "error" in tool_result:
            return tool_result
        
        result = tool_result.get("result", {})
        
        # Keep API errors
        if result.get("isError"):
            return {
                "tool": tool_result.get("tool"),
                "result": {
                    "isError": True,
                    "api_error": result.get("api_error", "Unknown error")
                }
            }
        
        # Summarize successful results
        content = result.get("content", [])
        summarized_content = self._summarize_content(content, max_chars)
        
        return {
            "tool": tool_result.get("tool"),
            "result": {
                "content": summarized_content,
                "isError": False
            }
        }
    
    def _summarize_content(self, content: Any, max_chars: int) -> Any:
        """Summarize content while preserving both text and structured data"""
        if not content:
            return content
        
        if isinstance(content, str):
            return content[:max_chars] + "..." if len(content) > max_chars else content
        
        if isinstance(content, list):
            summarized = []
            total_chars = 0
            
            for item in content[:20]:  # Max 20 items
                if isinstance(item, dict):
                    if item.get("type") == "text":
                        text = item.get("text", "")
                        if total_chars + len(text) > max_chars:
                            remaining = max_chars - total_chars
                            if remaining > 100:
                                summarized.append({"type": "text", "text": text[:remaining] + "..."})
                            break
                        summarized.append({"type": "text", "text": text})
                        total_chars += len(text)
                    else:
                        # Preserve structured data with summarization
                        summary = self._summarize_structured_item(item)
                        summarized.append({"type": "structured_summary", "text": summary})
                        total_chars += len(summary)
                else:
                    # Handle non-dict items
                    item_str = str(item)[:500]
                    summarized.append({"type": "text", "text": item_str})
                    total_chars += len(item_str)
                
                if total_chars > max_chars:
                    break
            
            if len(content) > len(summarized):
                summarized.append({
                    "type": "text",
                    "text": f"[{len(content) - len(summarized)} more items omitted]"
                })
            
            return summarized
        
        return content
    
    def _summarize_structured_item(self, item: Dict[str, Any]) -> str:
        """Convert structured data to concise text summary"""
        # Extract key fields for common CheckPoint objects
        if "name" in item and "type" in item:
            return f"{item['type']}: {item['name']}"
        elif "uid" in item:
            return f"Object: {item.get('name', item['uid'])}"
        else:
            # Fallback: show first few key-value pairs
            keys = list(item.keys())[:3]
            summary_parts = [f"{k}={item[k]}" for k in keys if k in item]
            return ", ".join(summary_parts)
    
    def _truncate_content(self, content: Any, max_chars: int) -> Any:
        """Simple truncation without data manipulation - send as-is up to max_chars"""
        if isinstance(content, list):
            if not content:
                return []
            # Keep only first item
            first = content[0]
            if isinstance(first, dict) and first.get("type") == "text":
                text = first.get("text", "")[:max_chars]
                return [{"type": "text", "text": text + f"... [+{len(content)-1} items truncated]"}]
            return [first]
        elif isinstance(content, str):
            return content[:max_chars] + "..."
        return content
    
    def _format_firewall_rules_for_llm(self, data_collected: Dict[str, Any]) -> Dict[str, Any]:
        """Convert firewall rulebase data from double-escaped JSON to human-readable markdown tables.
        
        This preprocesses firewall rules so the LLM receives clean, structured data instead of 
        having to mentally parse escaped JSON strings.
        
        Args:
            data_collected: Raw MCP server data with escaped JSON in 'text' fields
            
        Returns:
            Formatted data with firewall rules as markdown tables
        """
        formatted_data = {}
        
        for server_name, server_data in data_collected.items():
            if not isinstance(server_data, dict):
                formatted_data[server_name] = server_data
                continue
            
            formatted_server_data = server_data.copy()
            formatted_tool_results = []
            
            # Process tool_results
            tool_results = server_data.get('tool_results', [])
            for tool_result in tool_results:
                if not isinstance(tool_result, dict):
                    formatted_tool_results.append(tool_result)
                    continue
                
                formatted_tool_result = tool_result.copy()
                
                # Check if this tool has firewall rulebase data
                if 'result' in tool_result and isinstance(tool_result['result'], dict):
                    result = tool_result['result']
                    if 'content' in result and isinstance(result['content'], list):
                        formatted_content = []
                        
                        for item in result['content']:
                            if isinstance(item, dict) and item.get('type') == 'text':
                                text = item.get('text', '')
                                
                                # Try to parse as JSON to detect firewall rulebase
                                try:
                                    data_obj = json.loads(text) if isinstance(text, str) else text
                                    
                                    # Check if this is firewall rulebase data
                                    if isinstance(data_obj, dict) and 'rulebase' in data_obj:
                                        # Format the rulebase as markdown table
                                        formatted_text = self._format_rulebase_as_markdown(data_obj)
                                        formatted_content.append({
                                            'type': 'text',
                                            'text': formatted_text
                                        })
                                    else:
                                        # Not a rulebase, keep original
                                        formatted_content.append(item)
                                except (json.JSONDecodeError, TypeError):
                                    # Not JSON or parsing failed, keep original
                                    formatted_content.append(item)
                            else:
                                formatted_content.append(item)
                        
                        formatted_result = result.copy()
                        formatted_result['content'] = formatted_content
                        formatted_tool_result['result'] = formatted_result
                
                formatted_tool_results.append(formatted_tool_result)
            
            formatted_server_data['tool_results'] = formatted_tool_results
            formatted_data[server_name] = formatted_server_data
        
        return formatted_data
    
    def _format_rulebase_as_markdown(self, rulebase_data: Dict[str, Any]) -> str:
        """Format firewall rulebase as human-readable markdown table with dynamic headers.
        
        Args:
            rulebase_data: Dictionary containing rulebase data with rules
            
        Returns:
            Markdown formatted string with rule table
        """
        output = []
        
        # DEBUG: Log what we receive
        from datetime import datetime
        ts = datetime.now().strftime('%H:%M:%S.%f')[:-3]
        print(f"[DEBUG] [{ts}] _format_rulebase_as_markdown called")
        print(f"[DEBUG] [{ts}] rulebase_data keys: {list(rulebase_data.keys()) if isinstance(rulebase_data, dict) else 'NOT A DICT'}")
        print(f"[DEBUG] [{ts}] rulebase array length: {len(rulebase_data.get('rulebase', [])) if isinstance(rulebase_data, dict) else 'N/A'}")
        
        # Extract rules first to determine type
        rules = rulebase_data.get('rulebase', [])
        if not rules:
            return json.dumps(rulebase_data, indent=2)  # No rules, return original
        
        # Determine rulebase type from first rule
        rulebase_type = "UNKNOWN"
        if rules and isinstance(rules[0], dict):
            rule_type = rules[0].get('type', '')
            if rule_type == 'access-rule':
                rulebase_type = "ACCESS RULEBASE (FIREWALL RULES)"
            elif rule_type == 'nat-rule':
                rulebase_type = "NAT RULEBASE"
            else:
                rulebase_type = f"RULEBASE ({rule_type})"
        
        # Add clear header with rulebase type
        output.append(f"**═══ {rulebase_type} ═══**")
        
        # Add policy package name if available
        if 'name' in rulebase_data:
            output.append(f"**Policy Package: {rulebase_data['name']}**\n")
        
        print(f"[DEBUG] [{ts}] Formatting {len(rules)} rules as {rulebase_type}")
        
        # Determine available fields from actual rule data
        # Priority fields in preferred order
        priority_fields = ['rule-number', 'name', 'source', 'destination', 'service', 'action', 'track']
        available_fields = []
        
        # Collect all unique fields from all rules
        all_fields = set()
        for rule in rules:
            if isinstance(rule, dict):
                all_fields.update(rule.keys())
        
        # Add priority fields that exist in data
        for field in priority_fields:
            if field in all_fields:
                available_fields.append(field)
        
        # Map fields to display headers
        header_map = {
            'rule-number': 'No.',
            'name': 'Name',
            'source': 'Source',
            'destination': 'Destination',
            'service': 'Service',
            'action': 'Action',
            'track': 'Track',
            'enabled': 'Enabled',
            'comments': 'Comments'
        }
        
        # Build markdown table header dynamically
        headers = [header_map.get(field, field.replace('-', ' ').title()) for field in available_fields]
        output.append("| " + " | ".join(headers) + " |")
        output.append("|" + "|".join(["-----" for _ in headers]) + "|")
        
        # Format each rule
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            
            # Build row dynamically based on available_fields
            row_values = []
            for field in available_fields:
                value = rule.get(field)
                
                # Format based on field type
                if field == 'rule-number':
                    formatted = str(value) if value is not None else rule.get('uid', '?')
                
                elif field in ['source', 'destination']:
                    if isinstance(value, list):
                        formatted = ', '.join(value) if value else 'Any'
                    else:
                        formatted = str(value) if value else 'Any'
                
                elif field == 'service':
                    # Deduplicate services (MCP server sometimes returns duplicates)
                    if isinstance(value, list):
                        seen = set()
                        unique_services = []
                        for svc in value:
                            if svc not in seen:
                                seen.add(svc)
                                unique_services.append(svc)
                        formatted = ', '.join(unique_services) if unique_services else 'Any'
                    else:
                        formatted = str(value) if value else 'Any'
                
                elif field == 'action':
                    if isinstance(value, dict):
                        formatted = value.get('name', value.get('type', '-'))
                    elif isinstance(value, str):
                        formatted = value
                    else:
                        formatted = str(value) if value else '-'
                
                elif field == 'track':
                    if isinstance(value, dict):
                        formatted = value.get('type', '-')
                    else:
                        formatted = str(value) if value else '-'
                
                elif field == 'name':
                    formatted = str(value) if value else '-'
                
                elif field == 'enabled':
                    formatted = 'Yes' if value else 'No'
                
                else:
                    # Generic formatting for other fields
                    if isinstance(value, (list, dict)):
                        formatted = str(value)
                    else:
                        formatted = str(value) if value is not None else '-'
                
                row_values.append(formatted)
            
            # DO NOT truncate - send complete data to LLM (user requirement)
            # LLM needs full service names and object names for accurate analysis
            
            # Add row
            output.append("| " + " | ".join(row_values) + " |")
        
        output.append(f"\n**Total Rules: {len(rules)}**")
        output.append(f"\n**NOTE**: Rulebase action field may be inaccurate due to MCP server limitations. **Always rely on LOG 'action' field for actual enforcement actions (Drop/Accept/Reject)**.")
        
        return '\n'.join(output)
    
    def _remove_duplicate_data(self, data_collected: Dict[str, Any]) -> Dict[str, Any]:
        """Remove duplicate logs and objects across MCP servers
        
        This deduplicates the same logs or objects being sent multiple times,
        which wastes tokens and confuses the LLM.
        
        Returns:
            Deduplicated data_collected dict
        """
        print(f"[DEBUG] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Starting deduplication...")
        
        # Track seen items globally
        seen_log_hashes = set()
        seen_object_hashes = set()
        removed_count = 0
        
        deduplicated_data = {}
        
        for server_name, server_data in data_collected.items():
            if not isinstance(server_data, dict):
                deduplicated_data[server_name] = server_data
                continue
            
            deduplicated_server_data = server_data.copy()
            deduplicated_tool_results = []
            
            # Process tool_results
            tool_results = server_data.get('tool_results', [])
            for tool_result in tool_results:
                if isinstance(tool_result, dict) and 'result' in tool_result:
                    result = tool_result['result']
                    
                    # Check content array
                    if isinstance(result, dict) and 'content' in result:
                        deduplicated_content = []
                        
                        for item in result.get('content', []):
                            if isinstance(item, dict) and item.get('type') == 'text':
                                try:
                                    text_data = json.loads(item.get('text', '{}'))
                                    
                                    # Skip if not a dict
                                    if not isinstance(text_data, dict):
                                        deduplicated_content.append(item)
                                        continue
                                    
                                    # Process each array in the data
                                    deduplicated_text_data = {}
                                    for key, value in text_data.items():
                                        if isinstance(value, list) and len(value) > 0:
                                            first_item = value[0]
                                            if isinstance(first_item, dict):
                                                # CRITICAL: Check if it's a firewall rule FIRST (before checking logs)
                                                # Rulebases should NOT be deduplicated (each rule is unique even if action/source match)
                                                is_rulebase = (key == 'rulebase' or 'rule-number' in first_item)
                                                
                                                # Check if it's a log
                                                has_time = any(k in first_item for k in ['time', 'timestamp'])
                                                has_action = any(k in first_item for k in ['action', 'severity', 'blade'])
                                                
                                                unique_items = []
                                                if is_rulebase:
                                                    # Rulebases: Keep all rules as-is (no deduplication)
                                                    unique_items = value
                                                elif has_time and has_action:
                                                    # It's a log - deduplicate
                                                    for log in value:
                                                        log_hash = f"{log.get('time')}_{log.get('src')}_{log.get('dst')}_{log.get('action')}"
                                                        if log_hash not in seen_log_hashes:
                                                            seen_log_hashes.add(log_hash)
                                                            unique_items.append(log)
                                                        else:
                                                            removed_count += 1
                                                else:
                                                    # It's an object - deduplicate
                                                    for obj in value:
                                                        obj_hash = f"{obj.get('name')}_{obj.get('type')}_{obj.get('uid', '')}"
                                                        if obj_hash not in seen_object_hashes:
                                                            seen_object_hashes.add(obj_hash)
                                                            unique_items.append(obj)
                                                        else:
                                                            removed_count += 1
                                                
                                                deduplicated_text_data[key] = unique_items
                                            else:
                                                # Not a dict array, keep as-is
                                                deduplicated_text_data[key] = value
                                        else:
                                            # Not a list, keep as-is
                                            deduplicated_text_data[key] = value
                                    
                                    # Update the text content with deduplicated data
                                    item_copy = item.copy()
                                    item_copy['text'] = json.dumps(deduplicated_text_data)
                                    deduplicated_content.append(item_copy)
                                    
                                except (json.JSONDecodeError, KeyError):
                                    deduplicated_content.append(item)
                            else:
                                deduplicated_content.append(item)
                        
                        # Update result with deduplicated content
                        tool_result_copy = tool_result.copy()
                        tool_result_copy['result'] = result.copy()
                        tool_result_copy['result']['content'] = deduplicated_content
                        deduplicated_tool_results.append(tool_result_copy)
                    else:
                        deduplicated_tool_results.append(tool_result)
                else:
                    deduplicated_tool_results.append(tool_result)
            
            deduplicated_server_data['tool_results'] = deduplicated_tool_results
            deduplicated_data[server_name] = deduplicated_server_data
        
        print(f"[DEBUG] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Deduplication complete: removed {removed_count} duplicate items")
        return deduplicated_data
    
    def _analyze_duplicate_data(self, data_collected: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze data for duplicates across MCP servers
        
        This checks if the same logs or objects are being sent multiple times,
        which wastes tokens and confuses the LLM.
        
        Returns:
            Dict with duplicate analysis results
        """
        print(f"[DEBUG] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Starting duplicate data analysis...")
        
        # Track all unique data items across servers
        all_logs = []
        all_objects = []
        log_hashes = set()
        object_hashes = set()
        duplicate_count = 0
        
        for server_name, server_data in data_collected.items():
            if not isinstance(server_data, dict):
                continue
            
            # Analyze tool_results
            tool_results = server_data.get('tool_results', [])
            for tool_result in tool_results:
                if isinstance(tool_result, dict) and 'result' in tool_result:
                    result = tool_result['result']
                    
                    # Check content array
                    if isinstance(result, dict) and 'content' in result:
                        for item in result.get('content', []):
                            if isinstance(item, dict) and item.get('type') == 'text':
                                try:
                                    text_data = json.loads(item.get('text', '{}'))
                                    
                                    # Skip if not a dict (could be a list or other type)
                                    if not isinstance(text_data, dict):
                                        continue
                                    
                                    # Check for log arrays
                                    for key, value in text_data.items():
                                        if isinstance(value, list) and len(value) > 0:
                                            first_item = value[0]
                                            if isinstance(first_item, dict):
                                                # Check if it's a log (has time/action fields)
                                                has_time = any(k in first_item for k in ['time', 'timestamp'])
                                                has_action = any(k in first_item for k in ['action', 'severity', 'blade'])
                                                
                                                if has_time and has_action:
                                                    # It's a log - check for duplicates
                                                    for log in value:
                                                        log_hash = f"{log.get('time')}_{log.get('src')}_{log.get('dst')}_{log.get('action')}"
                                                        if log_hash in log_hashes:
                                                            duplicate_count += 1
                                                        else:
                                                            log_hashes.add(log_hash)
                                                        all_logs.append(log)
                                                else:
                                                    # It's an object (rules, gateways, etc)
                                                    for obj in value:
                                                        obj_hash = f"{obj.get('name')}_{obj.get('type')}_{obj.get('uid', '')}"
                                                        if obj_hash in object_hashes:
                                                            duplicate_count += 1
                                                        else:
                                                            object_hashes.add(obj_hash)
                                                        all_objects.append(obj)
                                except (json.JSONDecodeError, KeyError):
                                    pass
        
        # Build analysis report
        analysis = {
            "duplicates_found": duplicate_count > 0,
            "duplicate_count": duplicate_count,
            "total_unique_logs": len(log_hashes),
            "total_unique_objects": len(object_hashes),
            "total_logs": len(all_logs),
            "total_objects": len(all_objects),
            "summary": f"{duplicate_count} duplicate items found out of {len(all_logs) + len(all_objects)} total items"
        }
        
        print(f"[DEBUG] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Duplicate analysis: {analysis['summary']}")
        return analysis
    
    def _is_relevant_security_log(self, log_item: Dict[str, Any]) -> bool:
        """Determine if a log entry is relevant for security analysis
        
        Filters out:
        - Control logs (policy installations, updates, reboots)
        - Informational system logs (configuration changes, status updates)
        - Routine operational logs (successful connections without security context)
        
        Keeps:
        - Actual security events (IPS attacks, malware, blocks, drops)
        - Threat-related logs (Anti-Bot, Anti-Virus detections)
        - Suspicious activity (rejected connections, authentication failures)
        - VPN security events
        - DLP violations
        
        Args:
            log_item: Individual log entry dict
            
        Returns:
            True if log should be kept for analysis, False to filter out
        """
        # Extract key fields for analysis (safely handle None/dict/list values)
        def safe_str(value):
            """Convert any value to lowercase string, handling None/dict/list"""
            if value is None:
                return ''
            if isinstance(value, str):
                return value.lower()
            # Convert dict/list to empty string (unexpected but safe)
            return ''
        
        log_type = safe_str(log_item.get('type'))
        product_family = safe_str(log_item.get('product_family'))
        product = safe_str(log_item.get('product'))
        action = safe_str(log_item.get('action'))
        description = safe_str(log_item.get('description'))
        severity = safe_str(log_item.get('severity'))
        
        # ALWAYS FILTER OUT: Control and system operational logs
        irrelevant_patterns = [
            # Policy/configuration updates
            'policy was successfully installed',
            'policy successfully installed',
            'engine version',
            'update was successfully installed',
            'configuration update',
            'software update',
            
            # System operations
            'reboot', 'restart', 'shutdown',
            'service started', 'service stopped',
            'interface up', 'interface down',
            
            # Routine status
            'activated successfully',
            'deactivated successfully',
            'synchronization completed',
            'backup completed',
            'health check',
        ]
        
        # Check if log matches irrelevant patterns
        for pattern in irrelevant_patterns:
            if pattern in description:
                return False
        
        # FILTER OUT: Pure control logs (type=Control) UNLESS they contain security keywords
        if log_type == 'control':
            # Keep control logs that have security implications
            security_control_keywords = ['block', 'drop', 'reject', 'fail', 'attack', 'threat', 'malware', 'breach']
            if not any(kw in description for kw in security_control_keywords):
                return False
        
        # ALWAYS KEEP: Security-critical log types
        security_log_types = ['threat', 'attack', 'drop', 'reject', 'block']
        if any(t in log_type for t in security_log_types):
            return True
        
        # ALWAYS KEEP: Threat product families
        if product_family in ['threat', 'dlp', 'compliance']:
            return True
        
        # ALWAYS KEEP: Security actions
        security_actions = ['drop', 'reject', 'block', 'prevent', 'quarantine', 'encrypt']
        if any(a in action for a in security_actions):
            return True
        
        # ALWAYS KEEP: High severity events
        if severity in ['high', 'critical', 'medium']:
            return True
        
        # ALWAYS KEEP: Logs with security keywords in description
        security_keywords = [
            'attack', 'threat', 'malware', 'virus', 'bot', 'suspicious',
            'intrusion', 'exploit', 'compromise', 'breach', 'infected',
            'phishing', 'ransomware', 'blocked', 'dropped', 'rejected',
            'failed authentication', 'unauthorized', 'violation', 'anomaly'
        ]
        if any(kw in description for kw in security_keywords):
            return True
        
        # Keep VPN logs that show security events (not just successful connections)
        if 'vpn' in product.lower():
            if any(kw in description for kw in ['fail', 'error', 'reject', 'timeout', 'encryption']):
                return True
            # Filter out routine "VPN connection succeeded" logs
            if 'succeeded' in description or 'established' in description:
                return False
        
        # Default: Keep logs for safety (anything unusual or not explicitly filtered)
        # Accept logs are kept to understand traffic patterns and destinations
        return True
    
    def _apply_smart_log_sampling(self, data_collected: Dict[str, Any], timeframe_hours: float = 24) -> Dict[str, Any]:
        """Apply intelligent temporal sampling to reduce log volume while preserving analysis coherence
        
        Strategy:
        - Short timeframes (<48h): First 15 + Last 15 logs per action type (30 total per action)
        - Long timeframes (≥48h): Stratified temporal sampling across time buckets
          * 2-10 days: 1 bucket per day, 3 samples per bucket per action
          * 11-30 days: 1 bucket per 2 days, 3 samples per bucket per action  
          * 31+ days: 1 bucket per week, 3 samples per bucket per action
        
        Always includes first and last log to show trend direction.
        
        Args:
            data_collected: Raw data from MCP servers
            timeframe_hours: Query timeframe in hours (used for stratification logic)
            
        Returns:
            Sampled data with metadata about sampling applied
        """
        from datetime import datetime as dt
        from collections import defaultdict
        
        print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] _apply_smart_log_sampling: Starting with timeframe={timeframe_hours}h...")
        
        sampled_data = {}
        total_original_logs = 0
        total_sampled_logs = 0
        
        for server_name, server_data in data_collected.items():
            if not isinstance(server_data, dict):
                sampled_data[server_name] = server_data
                continue
            
            sampled_server_data = server_data.copy()
            
            # Process tool_results for log data
            if 'tool_results' in server_data and isinstance(server_data['tool_results'], list):
                sampled_tool_results = []
                
                for tool_result in server_data['tool_results']:
                    if not isinstance(tool_result, dict):
                        sampled_tool_results.append(tool_result)
                        continue
                    
                    sampled_tool_result = tool_result.copy()
                    
                    # Check if this tool has log data
                    if 'result' in tool_result and isinstance(tool_result['result'], dict):
                        result = tool_result['result']
                        
                        if 'content' in result and isinstance(result['content'], list):
                            sampled_content = []
                            
                            for item in result['content']:
                                if isinstance(item, dict) and item.get('type') == 'text':
                                    text = item.get('text', '')
                                    
                                    # Try to parse as JSON to detect log data
                                    try:
                                        data_obj = json.loads(text) if isinstance(text, str) else text
                                        
                                        # Check if this is log data (has 'logs' array)
                                        if isinstance(data_obj, dict) and 'logs' in data_obj and isinstance(data_obj['logs'], list):
                                            logs = data_obj['logs']
                                            original_count = len(logs)
                                            total_original_logs += original_count
                                            
                                            if original_count == 0:
                                                sampled_content.append(item)
                                                continue
                                            
                                            # Apply sampling based on timeframe
                                            if timeframe_hours < 48:
                                                # Short timeframe: First 15 + Last 15 per action type
                                                sampled_logs, sampling_meta = self._sample_logs_short_timeframe(logs)
                                            else:
                                                # Long timeframe: Stratified temporal sampling
                                                sampled_logs, sampling_meta = self._sample_logs_long_timeframe(logs, timeframe_hours)
                                            
                                            total_sampled_logs += len(sampled_logs)
                                            
                                            # Update data object with sampled logs
                                            data_obj['logs'] = sampled_logs
                                            data_obj['_sampling_applied'] = sampling_meta
                                            
                                            # Convert back to text
                                            sampled_content.append({
                                                'type': 'text',
                                                'text': data_obj
                                            })
                                            
                                            print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Sampled {original_count} logs → {len(sampled_logs)} ({sampling_meta['strategy']})")
                                        else:
                                            # Not log data, keep as-is
                                            sampled_content.append(item)
                                    except (json.JSONDecodeError, TypeError):
                                        # Not JSON or parsing failed, keep original
                                        sampled_content.append(item)
                                else:
                                    sampled_content.append(item)
                            
                            # Update result with sampled content
                            sampled_result = result.copy()
                            sampled_result['content'] = sampled_content
                            sampled_tool_result['result'] = sampled_result
                        else:
                            # No content array, keep result as-is
                            pass
                    else:
                        # No result dict, keep tool_result as-is
                        pass
                
                    sampled_tool_results.append(sampled_tool_result)
                sampled_server_data['tool_results'] = sampled_tool_results
            
            sampled_data[server_name] = sampled_server_data
        
        if total_original_logs > 0:
            reduction_pct = ((total_original_logs - total_sampled_logs) / total_original_logs * 100)
            print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Smart sampling complete: {total_original_logs} → {total_sampled_logs} logs ({reduction_pct:.1f}% reduction)")
        
        return sampled_data
    
    def _sample_logs_short_timeframe(self, logs: list) -> tuple[list, dict]:
        """Sample logs for short timeframes (<48h): First 15 + Last 15 per action type"""
        from collections import defaultdict
        
        # Group by action type
        logs_by_action = defaultdict(list)
        for log in logs:
            action = log.get('action', 'Unknown')
            logs_by_action[action].append(log)
        
        sampled_logs = []
        action_samples = {}
        
        for action, action_logs in logs_by_action.items():
            count = len(action_logs)
            
            if count <= 30:
                # If 30 or fewer, keep all
                sampled_logs.extend(action_logs)
                action_samples[action] = {'original': count, 'sampled': count, 'method': 'all'}
            else:
                # Take first 15 and last 15
                sampled = action_logs[:15] + action_logs[-15:]
                sampled_logs.extend(sampled)
                action_samples[action] = {'original': count, 'sampled': 30, 'method': 'first_15_last_15'}
        
        metadata = {
            'strategy': 'short_timeframe',
            'total_original': len(logs),
            'total_sampled': len(sampled_logs),
            'action_breakdown': action_samples
        }
        
        return sampled_logs, metadata
    
    def _sample_logs_long_timeframe(self, logs: list, timeframe_hours: float) -> tuple[list, dict]:
        """Sample logs for long timeframes (≥48h): Stratified temporal sampling across time buckets"""
        from datetime import datetime as dt, timedelta
        from collections import defaultdict
        
        # Determine bucket size based on timeframe
        timeframe_days = timeframe_hours / 24
        
        if timeframe_days <= 10:
            bucket_hours = 24  # 1 bucket per day
            samples_per_bucket = 3
        elif timeframe_days <= 30:
            bucket_hours = 48  # 1 bucket per 2 days
            samples_per_bucket = 3
        else:
            bucket_hours = 168  # 1 bucket per week
            samples_per_bucket = 3
        
        # Parse timestamps and group by action + time bucket
        logs_by_action_bucket = defaultdict(lambda: defaultdict(list))
        
        for log in logs:
            action = log.get('action', 'Unknown')
            
            # Parse timestamp (Check Point format: "2025-10-13T11:59:31Z")
            time_str = log.get('time', '')
            try:
                log_time = dt.fromisoformat(time_str.replace('Z', '+00:00'))
                # Create bucket key (floor to bucket_hours)
                bucket_key = int(log_time.timestamp() // (bucket_hours * 3600))
                logs_by_action_bucket[action][bucket_key].append(log)
            except:
                # If timestamp parsing fails, put in bucket 0
                logs_by_action_bucket[action][0].append(log)
        
        sampled_logs = []
        action_samples = {}
        
        for action, buckets in logs_by_action_bucket.items():
            action_total = sum(len(bucket_logs) for bucket_logs in buckets.values())
            action_sampled = []
            
            # Sample from each bucket
            for bucket_key in sorted(buckets.keys()):
                bucket_logs = buckets[bucket_key]
                bucket_count = len(bucket_logs)
                
                if bucket_count <= samples_per_bucket:
                    # If bucket has few logs, take all
                    action_sampled.extend(bucket_logs)
                else:
                    # Evenly sample across bucket
                    indices = [int(i * bucket_count / samples_per_bucket) for i in range(samples_per_bucket)]
                    action_sampled.extend([bucket_logs[i] for i in indices])
            
            # Always include first and last log of this action
            all_action_logs = [log for bucket_logs in buckets.values() for log in bucket_logs]
            if all_action_logs and all_action_logs[0] not in action_sampled:
                action_sampled.insert(0, all_action_logs[0])
            if all_action_logs and all_action_logs[-1] not in action_sampled:
                action_sampled.append(all_action_logs[-1])
            
            sampled_logs.extend(action_sampled)
            action_samples[action] = {
                'original': action_total,
                'sampled': len(action_sampled),
                'buckets': len(buckets),
                'method': f'stratified_{int(bucket_hours)}h_buckets'
            }
        
        metadata = {
            'strategy': 'long_timeframe_stratified',
            'total_original': len(logs),
            'total_sampled': len(sampled_logs),
            'bucket_size_hours': bucket_hours,
            'samples_per_bucket': samples_per_bucket,
            'action_breakdown': action_samples
        }
        
        return sampled_logs, metadata
    
    def _filter_log_fields(self, data_collected: Dict[str, Any]) -> Dict[str, Any]:
        """Filter log data to remove Check Point metadata and reduce token usage
        
        Keeps comprehensive security fields (~190+ fields based on SK144192), removes only useless metadata.
        Expanded field list preserves critical context for threat analysis:
        - Authentication/Identity (user_group, auth_method, identity_type, machine names)
        - Application Control (application_name, application_id, app_sig_name, user_agent, referer)
        - Threat/IPS (attack_name, attack_id, cvss, bot_name, matched_patterns, indicators, packet_capture)
        - Policy hierarchy (access_rule_number, matched_rules, blade identifier, layer names)
        - DNS analysis (dns_query, requested_hostname, query_name, dns_type, dns_response)
        - Hostname identification (hostname, fqdn, source/destination hostnames)
        - Endpoint Security (endpoint_name, endpoint_id, compliance_status)
        - VPN details (encryption_failure, peer_gateway, community)
        - Drop/rejection reasons (reason, message, description)
        - Geographic/location data (country, city, source/dest location)
        - Client/OS information (source_os, destination_os, client details)
        - Web filtering (categories, matched_categories, HTTP details)
        - Email/Anti-Bot/AV fields for comprehensive analysis
        
        Expected token reduction: ~60-70% while preserving valuable context
        
        Args:
            data_collected: Raw data from MCP servers
            
        Returns:
            Filtered data with only essential security fields
        """
        # Smart filtering: Keep essential fields + ANY security-related fields
        # Only filter out truly useless metadata
        
        # Always keep these core fields (exact names from Check Point logs)
        ALWAYS_KEEP = {
            # Core connection
            'time', 'src', 'dst', 'service', 's_port', 'action', 'proto',
            'origin', 'product', 'layer_name', 'rule', 'policy_name',
            
            # NAT
            'xlatesrc', 'xlatedst', 'xlatesport', 'xlatedport',
            
            # Identity/Application  
            'user', 'application',
            
            # Application Control blade fields (CRITICAL for troubleshooting app-level issues)
            'appi_name', 'app_desc', 'app_id', 'app_sig_name', 'app_category', 
            'app_properties', 'app_risk', 'matched_category',
            
            # Objects (for show commands)
            'name', 'type', 'uid', 'rule-number', 'enabled',
            'source', 'destination', 'track', 'comments',
            'original-source', 'original-destination', 
            'translated-source', 'translated-destination'
        }
        
        # Keywords that indicate security-relevant fields - keep ANY field containing these
        SECURITY_KEYWORDS = {
            'attack', 'threat', 'malware', 'virus', 'bot', 'ips', 
            'severity', 'protection', 'cve', 'confidence',
            'dns', 'url', 'file', 'hash', 'verdict', 'scan',
            'reason', 'reject', 'drop', 'blade',
            'vpn', 'encryption', 'dlp', 'nat'
        }
        
        # Fields to ALWAYS remove (truly useless metadata)
        ALWAYS_REMOVE = {
            'uid', 'rule_uid', 'layer_uid', 'sequencenum', 'logid',
            'db_tag', 'id_generated_by_indexer', 'context_num',
            'orig_log_server', 'orig_log_server_attr', 'marker',
            '__interface', 'calc_desc', 'id', 'icon', 'color', 'domain',
            'meta-info', 'available-actions', 'tags'
        }
        
        def should_keep_field(field_name: str) -> bool:
            """Determine if a field should be kept based on smart rules"""
            field_lower = field_name.lower()
            
            # Always keep core fields
            if field_name in ALWAYS_KEEP:
                return True
            
            # Always remove useless metadata
            if field_name in ALWAYS_REMOVE:
                return False
            
            # Keep if contains security keywords
            if any(keyword in field_lower for keyword in SECURITY_KEYWORDS):
                return True
            
            # Keep if looks like important data (not internal metadata)
            if not field_name.startswith('_') and not field_name.endswith('_attr'):
                return True
            
            return False
        
        print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] _filter_log_fields: Starting log field filtering...")
        print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] data_collected has {len(data_collected)} servers: {list(data_collected.keys())}")
        filtered_data = {}
        total_logs_filtered = 0
        
        for server_name, server_data in data_collected.items():
            if not isinstance(server_data, dict):
                filtered_data[server_name] = server_data
                continue
            
            print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Server '{server_name}' has keys: {list(server_data.keys())}")
                
            filtered_server_data = {}
            
            for key, value in server_data.items():
                # Filter log data in 'tool_results' (actual MCP response location)
                if key == 'tool_results' and isinstance(value, list):
                    print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Found 'tool_results' array with {len(value)} tools in {server_name}")
                    filtered_tool_results = []
                    
                    for tool_idx, tool_result in enumerate(value):
                        if isinstance(tool_result, dict) and 'result' in tool_result:
                            tool_name = tool_result.get('tool', f'tool_{tool_idx}')
                            result = tool_result['result']
                            
                            # Look for 'content' array inside result
                            if isinstance(result, dict) and 'content' in result and isinstance(result['content'], list):
                                print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Tool '{tool_name}' has content array with {len(result['content'])} items")
                                filtered_content = []
                                
                                for idx, item in enumerate(result['content']):
                                    if isinstance(item, dict) and item.get('type') == 'text':
                                        text_str = item.get('text', '')
                                        
                                        # Handle both string (JSON) and dict (already parsed by MCP client)
                                        if isinstance(text_str, dict):
                                            # Already parsed (e.g., plain text wrapped by MCP client)
                                            text_data = text_str
                                            print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Text already dict (plain text or pre-parsed), keys: {list(text_data.keys())}")
                                        elif isinstance(text_str, str):
                                            print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Processing text item {idx}, length: {len(text_str)} chars")
                                            # Parse JSON from text field
                                            try:
                                                text_data = json.loads(text_str)
                                            except (json.JSONDecodeError, KeyError) as e:
                                                # Keep item as-is if parsing fails
                                                print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Failed to parse JSON: {e}")
                                                filtered_content.append(item)
                                                continue
                                        else:
                                            # Unknown type, skip
                                            filtered_content.append(item)
                                            continue
                                        
                                        # Continue with text_data processing
                                        try:
                                            
                                            # Handle both dict and list responses
                                            if isinstance(text_data, dict):
                                                print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Parsed JSON dict, keys: {list(text_data.keys())}")
                                            elif isinstance(text_data, list):
                                                print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Parsed JSON list, length: {len(text_data)}")
                                            
                                            # UNIVERSAL FILTERING: Filter ALL array fields containing dict items
                                            # This catches logs, objects, rules, sandbox_results, interfaces, connections, etc.
                                            if isinstance(text_data, dict):
                                                for field, value in list(text_data.items()):
                                                    # Check if it's an array with dict items (potential metadata bloat)
                                                    if isinstance(value, list) and len(value) > 0:
                                                        # Check if first item is a dict with fields (not a simple value)
                                                        first_item = value[0] if value else None
                                                        if isinstance(first_item, dict) and len(first_item) > 0:
                                                            original_count = len(value)
                                                            print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Filtering array '{field}': {original_count} items")
                                                            
                                                            # Filter each item to keep only essential fields
                                                            filtered_items = []
                                                            sample_original_fields = 0
                                                            sample_filtered_fields = 0
                                                            
                                                            filtered_log_count = 0
                                                            for idx, item in enumerate(value):
                                                                if isinstance(item, dict):
                                                                    # STEP 1: Check if this log is relevant for security analysis
                                                                    # Skip entire log if it's noise (control logs, policy updates, etc.)
                                                                    if field == 'logs' and not self._is_relevant_security_log(item):
                                                                        filtered_log_count += 1
                                                                        continue  # Skip this irrelevant log entirely
                                                                    
                                                                    if sample_original_fields == 0:
                                                                        sample_original_fields = len(item)
                                                                        # DEBUG: Show actual fields in first item
                                                                        print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] DEBUG: First item in '{field}' has fields: {list(item.keys())}")
                                                                    
                                                                    # STEP 2: Smart field filtering: Keep fields based on should_keep_field logic
                                                                    filtered_item = {k: v for k, v in item.items() if should_keep_field(k)}
                                                                    
                                                                    # DEBUG: Show what was filtered out from first item
                                                                    if idx == 0 and len(item) > 0:
                                                                        removed_fields = [k for k in item.keys() if not should_keep_field(k)]
                                                                        if removed_fields:
                                                                            print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Removed metadata fields: {removed_fields}")
                                                                    
                                                                    if sample_filtered_fields == 0 and filtered_item:
                                                                        sample_filtered_fields = len(filtered_item)
                                                                    if filtered_item:
                                                                        filtered_items.append(filtered_item)
                                                                else:
                                                                    # Keep non-dict items as-is
                                                                    filtered_items.append(item)
                                                            
                                                            text_data[field] = filtered_items
                                                            total_logs_filtered += len(filtered_items)
                                                            if filtered_log_count > 0:
                                                                print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] 🗑️ Filtered out {filtered_log_count} irrelevant logs (control/policy updates)")
                                                            print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Filtered '{field}': kept {len(filtered_items)}/{original_count} items, reduced fields from ~{sample_original_fields} to ~{sample_filtered_fields}")
                                            
                                            # Re-serialize filtered data back to JSON string
                                            filtered_content.append({
                                                'type': 'text',
                                                'text': json.dumps(text_data)
                                            })
                                        except (json.JSONDecodeError, KeyError) as e:
                                            # Keep item as-is if parsing fails
                                            print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Failed to parse JSON: {e}")
                                            filtered_content.append(item)
                                    else:
                                        # Keep non-text items as-is
                                        filtered_content.append(item)
                                
                                # Update result with filtered content
                                filtered_result = {**result, 'content': filtered_content}
                                filtered_tool_results.append({**tool_result, 'result': filtered_result})
                            else:
                                # No content to filter, keep tool result as-is
                                filtered_tool_results.append(tool_result)
                        else:
                            # Keep tool result as-is if structure unexpected
                            filtered_tool_results.append(tool_result)
                    
                    filtered_server_data[key] = filtered_tool_results
                else:
                    # Keep only useful metadata, skip wasteful MCP server info
                    # KEEP: discovered_resources (useful for follow-up queries), api_errors (debugging)
                    # SKIP: package, data_type, available_tools, server_name (redundant/internal metadata)
                    if key in ['discovered_resources', 'api_errors']:
                        filtered_server_data[key] = value
            
            filtered_data[server_name] = filtered_server_data
        
        print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] _filter_log_fields: Complete! Filtered {total_logs_filtered} total log/object items")
        return filtered_data
    
    def analyze_iterative_troubleshooting(self, plan: Dict[str, Any], execution_results: Dict[str, Any], security_model: Optional[str] = None, max_iterations: int = 4) -> Tuple[str, str]:
        """Iterative troubleshooting with smart escalation and context summarization
        
        Args:
            plan: The execution plan
            execution_results: Initial results (logs + rulebase)
            security_model: Model to use for analysis
            max_iterations: Maximum troubleshooting iterations (default: 4)
            
        Returns:
            Tuple of (final_analysis, model_used)
        """
        print(f"[QueryOrchestrator] [{ datetime.now().strftime('%H:%M:%S.%f')[:-3]}] 🔄 Starting iterative troubleshooting (max {max_iterations} iterations)")
        
        user_query = plan.get('user_query', '')
        iteration_history = []
        current_data = execution_results.get('data_collected', {})
        model_name = self.ollama_client.security_model  # Default model name for fallback
        
        for iteration in range(1, max_iterations + 1):
            print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] 🔍 Iteration {iteration}/{max_iterations}")
            
            # Build context for this iteration
            if iteration == 1:
                # First iteration: Full data (logs + rulebase)
                context_data = current_data
                iteration_context = "ITERATION 1 - INITIAL ANALYSIS (Logs + Firewall Rulebase)"
            else:
                # Subsequent iterations: Summary + new data only
                context_data = self._build_summarized_context(iteration_history, current_data)
                iteration_context = f"ITERATION {iteration} - DEEP DIVE ANALYSIS"
            
            # Build iterative analysis prompt
            analysis_prompt = self._build_iterative_prompt(
                user_query=user_query,
                iteration=iteration,
                max_iterations=max_iterations,
                context_data=context_data,
                iteration_history=iteration_history
            )
            
            # Get LLM analysis for this iteration
            client, model_name = self._get_client_for_model(security_model) if security_model else (self.ollama_client, self.ollama_client.security_model)
            
            try:
                response = client.chat(
                    model=model_name,
                    messages=[{
                        "role": "user",
                        "content": analysis_prompt
                    }],
                    temperature=0.1  # Low temperature for deterministic troubleshooting
                )
                
                # Parse structured response
                analysis_result = self._parse_iterative_response(response)
                
                # Store iteration in history
                iteration_history.append({
                    "iteration": iteration,
                    "findings": analysis_result.get("findings", ""),
                    "data_analyzed": list(context_data.keys()) if isinstance(context_data, dict) else []
                })
                
                # Check if diagnosis is complete
                if analysis_result.get("root_cause_determined", False):
                    print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] ✅ Root cause determined in iteration {iteration}")
                    final_report = self._build_final_troubleshooting_report(iteration_history, analysis_result)
                    return (final_report, security_model or f"Ollama: {model_name}")
                
                # Check if LLM requests more data
                next_steps = analysis_result.get("next_steps", {})
                if next_steps.get("action") == "request_data":
                    data_needed = next_steps.get("data_needed", "")
                    commands = next_steps.get("specific_commands", [])
                    
                    print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] 📊 LLM requests: {data_needed}")
                    print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] 🔧 Commands: {commands}")
                    
                    # Collect requested data
                    new_data = self._collect_additional_data(data_needed, commands, plan)
                    if new_data:
                        current_data = new_data  # Replace with new data for next iteration
                    else:
                        # No new data available - finalize with current findings
                        print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] ⚠️ Requested data not available, finalizing with current findings")
                        final_report = self._build_final_troubleshooting_report(iteration_history, analysis_result)
                        return (final_report, security_model or f"Ollama: {model_name}")
                else:
                    # LLM doesn't need more data - finalize
                    print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] ✅ Analysis complete, no additional data needed")
                    final_report = self._build_final_troubleshooting_report(iteration_history, analysis_result)
                    return (final_report, security_model or f"Ollama: {model_name}")
                    
            except Exception as e:
                print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] ❌ Error in iteration {iteration}: {e}")
                # Fallback to standard analysis
                return self.analyze_with_model(plan, execution_results, security_model)
        
        # Max iterations reached - finalize with current findings
        print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] ⚠️ Max iterations ({max_iterations}) reached")
        final_report = self._build_final_troubleshooting_report(iteration_history, {
            "findings": "Analysis reached maximum iteration limit",
            "recommendations": "Consider narrowing the scope or providing more specific criteria"
        })
        return (final_report, security_model or f"Ollama: {model_name}")
    
    def _build_summarized_context(self, iteration_history: list, new_data: Dict[str, Any]) -> Dict[str, Any]:
        """Build summarized context for subsequent iterations to avoid truncation"""
        summary = {
            "previous_findings_summary": [],
            "new_data": new_data
        }
        
        for iter_data in iteration_history:
            summary["previous_findings_summary"].append({
                "iteration": iter_data["iteration"],
                "findings": iter_data["findings"][:500],  # Limit to 500 chars
                "data_sources": iter_data["data_analyzed"]
            })
        
        return summary
    
    def _build_iterative_prompt(self, user_query: str, iteration: int, max_iterations: int, context_data: Dict[str, Any], iteration_history: list) -> str:
        """Build analysis prompt for iterative troubleshooting"""
        
        # Build previous findings section
        previous_findings = ""
        if iteration_history:
            previous_findings = "\n\n## PREVIOUS FINDINGS:\n"
            for iter_data in iteration_history:
                previous_findings += f"\n**Iteration {iter_data['iteration']}:**\n{iter_data['findings']}\n"
        
        prompt = f"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║          🔧 ITERATIVE TROUBLESHOOTING - ITERATION {iteration}/{max_iterations} 🔧               ║
╚═══════════════════════════════════════════════════════════════════════════════╝

USER QUERY: "{user_query}"
{previous_findings}

## CURRENT DATA AVAILABLE:
{json.dumps(context_data, indent=2)}

## YOUR TASK:
Analyze the data and provide a structured response in this EXACT JSON format:

{{
  "findings": "What you discovered in this iteration (be specific, cite evidence)",
  "root_cause_determined": true/false,
  "root_cause": "The definitive root cause if determined, otherwise null",
  "next_steps": {{
    "action": "request_data" or "finalize",
    "data_needed": "routing_info" or "gateway_diagnostics" or "packet_capture" or null,
    "specific_commands": ["fw tab -t connections", "cpstat fw"] or [],
    "reason": "Why you need this additional data"
  }},
  "recommendations": "Actionable steps to resolve the issue"
}}

## ESCALATION LOGIC:
- **Iteration 1**: Analyze logs + firewall rules. If cause is clear (policy drop) → set root_cause_determined=true
- **Iteration 2+**: If logs show accepted but failing → request routing_info or gateway_diagnostics
- **Only escalate** if current data is insufficient for diagnosis

## RULES:
1. Set root_cause_determined=true ONLY when you have definitive evidence
2. If you need more data, specify EXACTLY what commands to run
3. If {iteration} == {max_iterations}, you MUST finalize with current findings
4. Cite specific log entries, rule numbers, or metrics in your findings

RESPOND WITH VALID JSON ONLY (no markdown, no explanations outside JSON):
"""
        return prompt
    
    def _parse_iterative_response(self, response: str) -> Dict[str, Any]:
        """Parse LLM's structured JSON response"""
        try:
            # Extract JSON from response (handle markdown code blocks)
            import re
            json_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', response, re.DOTALL)
            if json_match:
                json_str = json_match.group(1)
            else:
                # Try to find raw JSON
                json_match = re.search(r'\{.*\}', response, re.DOTALL)
                json_str = json_match.group(0) if json_match else response
            
            return json.loads(json_str)
        except json.JSONDecodeError as e:
            print(f"[QueryOrchestrator] Failed to parse iterative response: {e}")
            # Return safe fallback
            return {
                "findings": response[:1000],  # Use first 1000 chars as findings
                "root_cause_determined": False,
                "next_steps": {"action": "finalize"}
            }
    
    def _collect_additional_data(self, data_needed: str, commands: list, plan: Dict[str, Any]) -> Dict[str, Any]:
        """Collect additional data based on LLM's request"""
        print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Collecting additional data: {data_needed}")
        
        if not self.gateway_script_executor:
            print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Gateway script executor not available")
            return {}
        
        # Map data_needed to MCP server queries
        additional_results = {}
        
        if data_needed == "gateway_diagnostics" and commands:
            # Execute gateway commands
            run_script_items = [f"run_script:{cmd}" for cmd in commands]
            plan_copy = plan.copy()
            plan_copy["data_to_fetch"] = run_script_items
            
            # Execute via MCP client
            exec_results = self.execute_plan(plan_copy, user_query=plan.get("user_query"))
            additional_results = exec_results.get("data_collected", {})
        
        elif data_needed == "routing_info":
            # Get routing table, interfaces
            commands = ["netstat -rn", "ifconfig -a", "ip route show"]
            run_script_items = [f"run_script:{cmd}" for cmd in commands]
            plan_copy = plan.copy()
            plan_copy["data_to_fetch"] = run_script_items
            
            exec_results = self.execute_plan(plan_copy, user_query=plan.get("user_query"))
            additional_results = exec_results.get("data_collected", {})
        
        return additional_results
    
    def _build_final_troubleshooting_report(self, iteration_history: list, final_result: Dict[str, Any]) -> str:
        """Build comprehensive troubleshooting report from all iterations"""
        
        report = "# Troubleshooting Analysis Report\n\n"
        
        # Add iteration summary
        report += "## Analysis Process:\n"
        for iter_data in iteration_history:
            report += f"\n### Iteration {iter_data['iteration']}:\n"
            report += f"**Data Sources**: {', '.join(iter_data['data_analyzed'])}\n\n"
            report += f"**Findings**: {iter_data['findings']}\n"
        
        # Add final diagnosis
        report += "\n## Final Diagnosis:\n\n"
        if final_result.get("root_cause_determined"):
            report += f"**Root Cause**: {final_result.get('root_cause', 'See findings above')}\n\n"
        else:
            report += "**Status**: Analysis completed with available data\n\n"
        
        report += f"**Findings**: {final_result.get('findings', 'See iteration details above')}\n\n"
        
        # Add recommendations
        if final_result.get("recommendations"):
            report += f"## Recommendations:\n\n{final_result['recommendations']}\n"
        
        return report
    
    def analyze_with_model(self, plan: Dict[str, Any], execution_results: Dict[str, Any], security_model: Optional[str] = None) -> Tuple[str, str]:
        """Send execution results to the appropriate model for final analysis
        
        Args:
            plan: The execution plan
            execution_results: Results from querying MCP servers
            security_model: Model to use for security analysis (format: "Provider: model_name")
            
        Returns:
            Tuple of (analysis_text, model_used)
        """
        
        analysis_type = plan.get("analysis_type", "general_query")
        
        # Always use the user-selected security_model if provided
        # This respects the user's OpenRouter/Ollama model choice
        if security_model:
            final_model = security_model
        else:
            # Fallback to Ollama if no model specified
            # Use security model for security-related tasks
            if analysis_type in ["security_risk_analysis", "security_investigation", "threat_assessment"]:
                final_model = f"Ollama: {self.ollama_client.security_model}"
            else:
                final_model = f"Ollama: {self.ollama_client.general_model}"
        
        print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] analyze_with_model using: '{final_model}'")
        
        # Build context from execution results - filter log fields to reduce tokens
        data_collected = execution_results.get('data_collected', {})
        
        # Extract timeframe from session context or default to 24h
        timeframe_hours = 24.0
        if self.session_context.get('last_timeframe'):
            timeframe_str = self.session_context.get('last_timeframe', 'last-24-hours')
            # Parse timeframe string (e.g., "last-7-days", "last-30-days", "last-72-hours", "6-hours")
            try:
                import re
                # Extract numeric value from timeframe string
                match = re.search(r'(\d+)', timeframe_str)
                if match:
                    numeric_value = float(match.group(1))
                    if 'hour' in timeframe_str:
                        timeframe_hours = numeric_value
                    elif 'day' in timeframe_str:
                        timeframe_hours = numeric_value * 24
                    else:
                        print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] ⚠️ Unknown timeframe unit in '{timeframe_str}', defaulting to 24h")
                        timeframe_hours = 24.0
                else:
                    print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] ⚠️ No numeric value in timeframe '{timeframe_str}', defaulting to 24h")
                    timeframe_hours = 24.0
            except Exception as e:
                print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] ⚠️ Failed to parse timeframe '{timeframe_str}': {e}, defaulting to 24h")
                timeframe_hours = 24.0
        
        # Apply intelligent temporal log sampling to reduce volume while preserving analysis coherence
        data_collected = self._apply_smart_log_sampling(data_collected, timeframe_hours=timeframe_hours)
        
        # Apply intelligent log field filtering to reduce token usage while preserving valuable security information
        data_collected = self._filter_log_fields(data_collected)
        
        # Remove duplicate data across MCP servers
        data_collected = self._remove_duplicate_data(data_collected)
        
        # DEBUG LOGGING: Analyze for duplicate data (should be 0 after deduplication)
        duplicate_analysis = self._analyze_duplicate_data(data_collected)
        
        # DEBUG LOGGING: Write filtered data to file for analysis
        debug_file_path = "./logs/llm_input_debug.json"
        try:
            import os
            os.makedirs("./logs", exist_ok=True)
            with open(debug_file_path, 'w') as f:
                json.dump({
                    "timestamp": datetime.now().isoformat(),
                    "filtered_data": data_collected,
                    "metadata": {
                        "servers_count": len(data_collected),
                        "servers": list(data_collected.keys())
                    },
                    "duplicate_analysis": duplicate_analysis
                }, f, indent=2)
            print(f"[DEBUG] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Written filtered data to {debug_file_path}")
            if duplicate_analysis.get("duplicates_found"):
                print(f"[DEBUG] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] ⚠️ DUPLICATES DETECTED: {duplicate_analysis['summary']}")
        except Exception as e:
            print(f"[DEBUG] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Failed to write debug file: {e}")
        
        # Extract discovered resources for investigation capabilities note (don't duplicate in context)
        has_discovered_resources = any('discovered_resources' in server_data for server_data in data_collected.values())
        
        # PREPROCESS FIREWALL RULES: Convert double-escaped JSON to human-readable markdown tables
        # This makes it much easier for the LLM to analyze specific rules
        data_collected_formatted = self._format_firewall_rules_for_llm(data_collected)
        
        # Convert MCP data to JSON - firewall rules now formatted as readable markdown
        data_json = json.dumps(data_collected_formatted, indent=2)
        
        # DEBUG: Log data size before building context
        print(f"[DEBUG] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Data JSON size: {len(data_json):,} chars (~{len(data_json)//4:,} tokens)")
        
        # Check if there are errors or missing data
        errors = execution_results.get('errors', [])
        warnings = execution_results.get('warnings', [])
        servers_queried = execution_results.get('servers_queried', [])
        
        # Build helpful context about data availability
        missing_servers = [err.split("'")[1] for err in errors if "not active" in err]
        has_data = bool(data_collected and any(data_collected.values()))
        
        # Format warnings for display
        warnings_text = ""
        if warnings:
            warnings_text = f"\nWarnings:\n" + "\n".join([f"- {w}" for w in warnings])
        
        context = f"""You are analyzing Check Point security platform data to answer the user's question.

Data from MCP Servers:
{data_json}

Servers Queried: {', '.join(servers_queried)}
Errors: {', '.join(errors) if errors else 'None'}{warnings_text}

"""
        
        # Build evidence-first analysis prompt with anti-hallucination safeguards
        user_query = plan.get('user_query', 'N/A')
        
        # Check if context was truncated
        truncation_warning = ""
        if warnings and any("truncation" in w.lower() or "truncated" in w.lower() for w in warnings):
            truncation_warning = "\n⚠️ IMPORTANT: Some data was truncated to fit the model. If evidence is missing, report that limitation instead of making assumptions."
        
        # BUILD DATA SOURCE CONTEXT (Gap 1 - HIGH priority improvement)
        # Explain to LLM what types of data sources are in the results
        data_source_context = ""
        run_script_commands = []
        if self.gateway_script_executor:
            run_script_commands = [item for item in plan.get("data_to_fetch", []) 
                                  if isinstance(item, str) and item.startswith("run_script:")]
            if run_script_commands:
                cmd_list = ', '.join([cmd.replace('run_script:', '') for cmd in run_script_commands[:3]])
                if len(run_script_commands) > 3:
                    cmd_list += f"... (+{len(run_script_commands)-3} more)"
                
                data_source_context = f"""
📊 DATA SOURCE TYPES IN RESULTS:
- **Primary Data Sources**: management-logs (comprehensive traffic/threat logs), quantum-management (policy/config data)
- **Supplemental Diagnostics**: {len(run_script_commands)} gateway CLI command(s) - {cmd_list}
  → These are real-time gateway snapshots providing ADDITIONAL context to primary data
  → Prioritize primary log/policy data for analysis, use diagnostics for supplemental insights only

"""
        
        # BUILD DIAGNOSTIC COMMAND LEGEND (Gap 2 - MEDIUM priority improvement)
        # Help LLM understand what each diagnostic command provides
        command_legend_text = ""
        if run_script_commands:
            command_legend = {
                'cphaprob state': 'Cluster HA state (Active/Standby)',
                'cphaprob stat': 'Cluster member states',
                'cphaprob -a if': 'Monitored cluster interfaces',
                'cphaprob list': 'Cluster failover history',
                'fwaccel stat': 'SecureXL acceleration status',
                'fwaccel6 stat': 'SecureXL IPv6 acceleration',
                'fwaccel stats -p': 'SecureXL F2F violations',
                'fw stat': 'Firewall policy enforcement status',
                'fw ver': 'Firewall version and hotfixes',
                'fw ctl pstat': 'Policy server connection statistics',
                'fw ctl conntab': 'Current connection table',
                'fw tab -t connections': 'Connection table details',
                'cpview -p': 'Complete system performance metrics',
                'cpview -m': 'Memory-specific performance metrics',
                'cpstat os -f all': 'Complete OS statistics',
                'cpstat fw -f all': 'Firewall blade statistics',
                'cpstat ha': 'HA state and statistics',
                'cpstat vpn': 'VPN daemon statistics',
                'top -b -n 1': 'Process CPU/memory snapshot',
                'ps aux': 'Running processes list',
                'free -h': 'Memory usage (human-readable)',
                'df -h': 'Disk space usage',
                'ifconfig -a': 'Network interface details',
                'netstat -rn': 'Routing table',
                'vpn tu tlist': 'Active VPN tunnels',
                'cpwd_admin list': 'Check Point daemon status',
                'cpinfo -y all': 'Comprehensive diagnostic bundle',
                'iostat -x': 'Extended I/O statistics',
                'mpstat -P ALL': 'Per-CPU core utilization',
                'vmstat': 'Virtual memory statistics',
                'fw log': 'Firewall log viewer',
                'fw lslogs': 'Available log files'
            }
            
            matched_commands = []
            for cmd in run_script_commands:
                cmd_clean = cmd.replace('run_script:', '').strip()
                # Try exact match first
                if cmd_clean in command_legend:
                    matched_commands.append(f"  • {cmd_clean}: {command_legend[cmd_clean]}")
                else:
                    # Try partial match for commands with arguments
                    for base_cmd, description in command_legend.items():
                        if cmd_clean.startswith(base_cmd):
                            matched_commands.append(f"  • {cmd_clean}: {description}")
                            break
            
            if matched_commands:
                command_legend_text = "\n🔍 DIAGNOSTIC COMMAND REFERENCE:\n" + "\n".join(matched_commands) + "\n"
        
        # Detect query intent to provide appropriate analysis context
        task_type_header = ""
        
        # Use shared robust troubleshooting detection (single source of truth)
        is_troubleshooting = self._detect_troubleshooting_intent(user_query)
        
        if is_troubleshooting:
            # CRITICAL: Make troubleshooting intent EXTREMELY EXPLICIT at the very top
            task_type_header = """
╔═══════════════════════════════════════════════════════════════════════════════╗
║                  🔧 CONNECTIVITY TROUBLESHOOTING & ROOT CAUSE ANALYSIS 🔧      ║
╚═══════════════════════════════════════════════════════════════════════════════╝

TASK OBJECTIVE:
• Diagnose network connectivity issues and identify the root cause
• Analyze security policy enforcement to understand WHY traffic was dropped/blocked
• Correlate logs with firewall rulebase to determine the enforcement chain
• Focus on connectivity resolution, not general threat hunting

YOUR ROLE: Network troubleshooting engineer with security policy expertise
TASK: Determine why connections failed and what security controls enforced the action

"""
        
        # Add troubleshooting-specific analysis guidance
        troubleshooting_analysis_rules = ""
        if is_troubleshooting:
            troubleshooting_analysis_rules = """
TROUBLESHOOTING ROOT CAUSE ANALYSIS REQUIREMENTS:

1. TRAFFIC FLOW ANALYSIS (START HERE - OBVIOUS CHECKS):
   ✓ Was connection attempted? Identify source/destination IPs, ports, protocol
   ✓ **CRITICAL: Filter logs by action - Focus on Drop/Block/Reject actions FIRST for connectivity issues**
     - Ignore Accept logs initially - they show working traffic, not the problem
     - Only analyze Accept logs if no drops found, or for temporal comparison
   ✓ What happened to the traffic? (Accepted, Dropped, Blocked, Rejected, Timeout, Reset)
   ✓ Check NAT translations (source/destination IP/port modifications)
   ✓ Identify connection outcomes and patterns

2. SECURITY POLICY ENFORCEMENT ANALYSIS - MANDATORY STEP-BY-STEP WORKFLOW:
   
   **🚨 FOLLOW THESE STEPS EXACTLY IN ORDER - DO NOT SKIP ANY STEP 🚨**
   
   **STEP 1: Extract ONLY the DROP/BLOCK/REJECT logs from the data**
   - Go through the logs and create a list containing ONLY logs where action=Drop, action=Block, or action=Reject
   - IGNORE all logs where action=Accept (these show working traffic, not the problem)
   - Write down how many Drop logs you found
   
   **STEP 2: Extract the rule number from those DROP logs**
   - Look at the 'rule' field in the DROP logs you extracted in Step 1
   - Write down which rule number(s) appear in the DROP logs
   - Example: If DROP logs show rule=1, then rule 1 is dropping traffic
   - Example: If DROP logs show rule=4, then rule 4 is dropping traffic
   - **ONLY use the rule number from DROP logs, NOT from Accept logs**
   
   **STEP 3: Find that rule in the ACCESS RULEBASE (FIREWALL RULES)**
   - The data contains both ACCESS RULEBASE and NAT RULEBASE
   - **ACCESS RULEBASE** is labeled "═══ ACCESS RULEBASE (FIREWALL RULES) ═══"
   - **NAT RULEBASE** is labeled "═══ NAT RULEBASE ═══" - IGNORE this one
   - Find the rule with the rule-number that matches the DROP log rule number from Step 2
   - Example: If Step 2 found rule=1 in DROP logs, find rule-number: 1 in ACCESS RULEBASE
   
   **STEP 4: Analyze WHY that rule dropped the traffic**
   - Look at the rule's source, destination, and service fields
   - Service categories like 'Spyware / Malicious Sites' mean the destination IP is categorized as malicious
   - Explain: "Destination IP X.X.X.X is blocked because it's categorized as [category] by Check Point"
   
   **STEP 5: Verify the action from LOG data**
   - The ACCESS RULEBASE action field shows "Policy Targets" (MCP server bug)
   - Use the LOG action field (Drop/Accept/Reject) as the source of truth
   ✓ Which security blade enforced the action? (Firewall, Application Control, IPS, URL Filtering, etc.)
   ✓ WHY was traffic dropped/blocked? Check rule's source, destination, service fields AND service categories
     **IMPORTANT: Service categories like 'Spyware / Malicious Sites' are DESTINATION-based blocking rules**
     **If rule service = 'Spyware / Malicious Sites' AND traffic dropped → Destination IP is categorized as malicious/spyware**
     **Explain this clearly: "Destination IP X.X.X.X is blocked because it's categorized as [category] by Check Point Threat Intelligence"**
   ✓ WHY was traffic dropped by policy?
     - Rule configuration (source, destination, service, action)
     - Security blade enforcement (IPS signature, App Control policy, URL category, IP reputation)
     - Threat prevention profiles
   ✓ Is this expected security enforcement or misconfiguration?
   
   **🚨 CRITICAL OUTPUT REQUIREMENT 🚨**
   ✓ **YOU MUST display the DROP rule from ACCESS RULEBASE in your response**
   
   **EXACT STEPS TO FOLLOW:**
   1. Identify which rule number appears in the DROP logs (from Step 2 above)
   2. Find that EXACT rule number in the ACCESS RULEBASE (FIREWALL RULES) section
   3. Copy the table header AND that rule's row from the ACCESS RULEBASE
   4. Display it in your response
   
   **EXAMPLES:**
   - If DROP logs show rule=1 → Display rule 1 from ACCESS RULEBASE
   - If DROP logs show rule=2 → Display rule 2 from ACCESS RULEBASE
   - DO NOT display Accept rules (they're not causing the problem)
   - DO NOT use NAT rulebase (it doesn't control Drop/Accept)
   
   **FORMAT:**
   ```
   **Matching Firewall Rule (Rule X - CAUSED THE DROP):**
   [Copy the exact table header and rule row from ACCESS RULEBASE (FIREWALL RULES) section]
   
   Note: Action=Drop from log data (rulebase shows "Policy Targets" due to MCP bug)
   ```
   
   ✓ **This rule display is MANDATORY - without it, the admin cannot see why traffic was blocked**

3. NETWORK-LEVEL ROOT CAUSES (IF POLICY IS NOT THE ISSUE):
   ✓ Routing problems:
     - Asymmetric routing (packets arriving on wrong interface)
     - Missing or incorrect routes
     - Route conflicts or loops
   ✓ Interface issues:
     - Interface down/degraded
     - VLAN misconfigurations
     - MTU mismatches causing fragmentation
     - Duplex/speed mismatches
   ✓ NAT/topology issues:
     - NAT pool exhaustion
     - Overlapping NAT configurations
     - Incorrect topology/anti-spoofing settings
   ✓ Network connectivity:
     - ARP failures
     - MAC address issues
     - Physical connectivity problems

4. GATEWAY/APPLIANCE LEVEL ROOT CAUSES (ESCALATE HERE IF NEEDED):
   ✓ Gateway resource issues:
     - Connection table full
     - Memory/CPU exhaustion
     - Kernel memory allocation failures
   ✓ Gateway configuration problems:
     - ClusterXL/HA state issues (split-brain, failover problems)
     - SecureXL/CoreXL offload issues
     - VPN domain/topology misconfigurations
   ✓ Software/firmware issues:
     - Known bugs in current version (sk articles)
     - Corrupted security policy
     - Service/daemon failures
   ✓ Performance bottlenecks:
     - Packet drops due to overload
     - F2F (fail-to-forward) violations
     - Interface saturation

5. TROUBLESHOOTING ESCALATION PATH:
   Step 1: Check logs for obvious drops/blocks (START HERE)
   Step 2: Correlate with firewall rules and blade enforcement
   Step 3: If accepted but not working → Check routing, NAT, topology
   Step 4: If intermittent → Check gateway resources, HA state, performance
   Step 5: If persistent and unexplained → Run gateway diagnostics:
     - Connection table analysis (fw tab -t connections)
     - Kernel debug (fw ctl zdebug + drop)
     - Packet captures (tcpdump on gateway)
     - Interface statistics (cpstat, ifconfig)
     - Resource monitoring (cpview, top, free)

6. TEMPORAL ANALYSIS (CRITICAL - CHECK TIMESTAMPS TO DETERMINE IF ISSUE IS RESOLVED):
   ✓ **STEP 1: Compare timestamps of Drop vs Accept logs**:
     - Find the LAST/MOST RECENT timestamp in Drop logs
     - Find the LAST/MOST RECENT timestamp in Accept logs
     - If most recent Accept timestamp > most recent Drop timestamp → Issue is RESOLVED
   
   ✓ **STEP 2: Identify the current state (what's happening NOW)**:
     - **RESOLVED**: Most recent logs are Accepts → "Traffic is NOW working (as of <timestamp>)"
       Example: Drop logs end at 10:33, Accept logs continue until 12:43 → Traffic restored at 10:33+
     - **ONGOING**: Most recent logs are Drops → "Traffic is STILL being dropped (as of <timestamp>)"
     - **INTERMITTENT**: Recent logs show both → "Traffic is unstable, alternating between working and failing"
   
   ✓ **STEP 3: Explain what changed over time**:
     - Group logs by rule number AND action AND time period
     - Example: "Earlier (00:05-10:33) → rule 1 dropped all traffic (27 drops)" 
               "Later (10:33-12:43) → rule 4 accepts traffic (29 accepts)"
     - **CRITICAL: If different rules at different times → State changed → Issue likely RESOLVED**
   
   ✓ **STEP 4: Report findings with clear past vs present distinction**:
     - "**PAST STATE** (00:05-10:33): Rule 1 dropped traffic to X.X.X.X - destination categorized as malicious"
     - "**CURRENT STATE** (10:33-12:43): Rule 4 now accepts same traffic - explicit allow rule matched"
     - "**CONCLUSION**: ✅ **Issue was RESOLVED** - traffic was blocked earlier but is **FULLY WORKING NOW** (last successful connection at 12:43)"
   
   ✓ **STEP 5: If issue is resolved, explain what likely fixed it**:
     - Policy change/update between timeframes
     - Destination IP reputation change
     - Firewall rule modification
     - Network topology change

7. REPORTING REQUIREMENTS:
   ✓ Always cite specific evidence from logs, rulebase, and diagnostics
   ✓ Report the complete diagnosis chain with supporting data
   ✓ If no traffic found: "No traffic found for specified IPs/timeframe"
   ✓ **🚨 MANDATORY: You MUST display the DROP rule from ACCESS RULEBASE in your response 🚨**
   
   **STEP-BY-STEP RULE DISPLAY PROCESS:**
   
   STEP A: Filter logs for action=Drop/Block/Reject ONLY
   STEP B: Extract the 'rule' field value from those DROP logs (e.g., if logs show rule: 1, then it's rule 1)
   STEP C: Go to the ACCESS RULEBASE (FIREWALL RULES) section in the data above
   STEP D: Find the rule with rule-number matching the value from Step B
   STEP E: Copy that rule's table header and row
   STEP F: Display it in your response
   
   **CRITICAL RULES:**
   - Use ONLY the rule number from DROP logs, NOT Accept logs
   - Use ONLY the ACCESS RULEBASE, NOT NAT rulebase
   - Display the EXACT rule that appears in DROP logs
   
   **EXAMPLE - If DROP logs show rule=1:**
   ```
   **Matching Firewall Rule (Rule 1 - CAUSED THE DROP):**
   | No. | Name | Source | Destination | Service | Action | Track |
   |-----|------|--------|-------------|---------|--------|-------|
   | 1 | - | sisaverkko | Any | Spyware / Malicious Sites | Drop | Log |
   
   Note: Action=Drop from log data (rulebase shows "Policy Targets" due to MCP bug)
   ```
   
   **Without this rule display, the admin cannot understand why traffic was blocked!**
   ✓ If network-level: Show routing/interface/NAT evidence
   ✓ If gateway-level: Include resource/HA/performance metrics
   ✓ Provide actionable recommendations with specific commands or config changes

TROUBLESHOOTING SCOPE: Full stack analysis from application → policy → network → gateway
ESCALATION: Start simple (logs/rules), escalate to complex (network/gateway) only when needed
AVOID: Speculating without evidence, jumping to conclusions before checking basics

"""
        
        # Build anti-hallucination rules - CLEAN VERSION for troubleshooting (no security language)
        if is_troubleshooting:
            anti_hallucination_rules = f"""CRITICAL INSTRUCTIONS - EVIDENCE-ONLY REPORTING:
1. **Report Only What Exists in Data**: Only report findings that are explicitly present in the provided data above
   - Never invent IPs, timestamps, rule numbers, or any other details
   - If no connectivity issues found, state "No connectivity issues detected in the available logs"
   - If data is incomplete or missing, acknowledge the limitation

2. **Citation Required**: For any finding, reference the actual data:
   - Quote specific field values (e.g., "action: Drop", "rule: 5")
   - Include actual timestamps from the logs
   - Show real IP addresses from the data
   - If a field is absent, do not assume its value

3. **Valid Outcomes**: 
   - No issues found → Report "No connectivity issues detected in the available logs"
   - Missing data → Report "Unable to analyze [specific aspect] due to missing/truncated data"
   - Normal traffic → Report "All connections appear normal"{truncation_warning}"""
        else:
            # Security-focused anti-hallucination rules (original version)
            anti_hallucination_rules = f"""CRITICAL INSTRUCTIONS - ANTI-HALLUCINATION RULES:
1. **Evidence-Only Reporting**: Only report findings that are explicitly present in the provided data above
   - Never invent IPs, timestamps, attack names, or any other details
   - If no threats/issues are found in the data, state "No suspicious activity detected" or "No issues found"
   - If data is incomplete or missing, acknowledge the limitation

2. **Citation Required**: For any security finding, reference the actual data:
   - Quote specific field values (e.g., "attack_name: SQL Injection")
   - Include actual timestamps from the logs
   - Show real IP addresses from the data
   - If a field is absent, do not assume its value

3. **Valid Outcomes**: 
   - Security query with no threats → Report "No suspicious activity detected in the available logs"
   - Missing data → Report "Unable to analyze [specific aspect] due to missing/truncated data"
   - Clean logs → Report "All activity appears normal"{truncation_warning}"""
        
        # Build contextual preamble with key information
        servers_summary = ', '.join(servers_queried) if servers_queried else 'None'
        contextual_preamble = f"""
════════════════════════════════════════════════════════════════════════════════
                            ANALYSIS CONTEXT
════════════════════════════════════════════════════════════════════════════════

USER QUESTION: {user_query}

DATA SOURCES AVAILABLE:
• MCP Servers Queried: {servers_summary}
• Errors: {', '.join(errors) if errors else 'None'}
{warnings_text}

NOTE: The rulebase data below has been pre-formatted as markdown tables for easy analysis.

**IMPORTANT - RULEBASE TYPES:**
• **ACCESS RULEBASE (FIREWALL RULES)** - Security policy rules that control Drop/Accept traffic
  → Use THIS rulebase when analyzing firewall drops/blocks from logs
  → Rule numbers in logs refer to ACCESS RULEBASE rule numbers

• **NAT RULEBASE** - Network address translation rules only
  → DO NOT use for firewall policy analysis
  → NAT rules don't control Drop/Accept actions
"""
        
        # Build structured response template
        structured_response_template = """
════════════════════════════════════════════════════════════════════════════════
                         REQUIRED RESPONSE FORMAT
════════════════════════════════════════════════════════════════════════════════

You MUST structure your response using the following sections:

## 1. EXECUTIVE SUMMARY
Provide a 2-3 sentence summary of the key finding.

## 2. SPECIFIC FINDINGS
For EACH relevant finding, you MUST provide:
• **Rule Number**: The exact rule-number from the firewall rulebase
• **Rule Name**: The name of the rule
• **Action**: What the rule does (Accept, Drop, Reject, etc.)
• **Matched Services/Applications**: Specific services or applications affected
• **Evidence**: Quote the exact log entries or rule configuration
• **Impact**: How this affects the user's question

Example format:
**Finding 1: Rule 5 blocks Skype traffic**
- Rule Number: 5
- Rule Name: Block_Social_Media
- Action: Drop
- Matched Services: Skype for Business, Microsoft Teams
- Evidence: Log entry shows "action: Drop, rule: 5, service: Skype for Business"
- Impact: This explains why users cannot access Skype

## 3. ROOT CAUSE ANALYSIS
Explain WHY the issue occurred based on the specific rules/logs/diagnostics.
Reference actual configuration values from the data.

## 4. RECOMMENDATIONS
Provide actionable steps with specific details:
• Exact rule numbers to modify
• Specific configuration changes needed
• Commands to run (if applicable)
"""
        
        analysis_prompt = f"""{task_type_header}{contextual_preamble}
{data_source_context}{command_legend_text}{troubleshooting_analysis_rules}
{anti_hallucination_rules}

{structured_response_template}

CRITICAL REQUIREMENTS:
✓ You MUST reference specific rule numbers, actions, and services in your findings
✓ You MUST quote actual evidence from the logs/rulebase data
✓ You MUST use the structured format above - generic responses will be rejected
✓ If no issues found, state clearly: "No issues detected in the available data"
✓ Display object names WITHOUT UUIDs (use human-readable names only)

INVESTIGATION CAPABILITIES:
{'Discovered resources in the data above are available for further investigation if needed.' if has_discovered_resources else 'You can request investigation using available MCP servers and tools if additional data is needed.'}

Now analyze the data above and provide your structured response following the REQUIRED RESPONSE FORMAT."""
        
        # Determine which client to use based on model prefix
        if isinstance(final_model, str) and (":" in final_model):
            client, model_name = self._get_client_for_model(final_model)
            print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Client type: {client.__class__.__name__}, Model: {model_name}")
        else:
            client = self.ollama_client
            model_name = final_model
            print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Using Ollama client (no prefix detected), Model: {model_name}")
        
        # FINAL UUID CLEANUP PASS - Remove CheckPoint UIDs from context
        # Be conservative to avoid redacting legitimate data
        import re
        
        # Pattern 1: Standard hyphenated UUIDs (8-4-4-4-12) - most common UUID format
        hyphenated_uuid_pattern = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
        context = re.sub(hyphenated_uuid_pattern, '<UUID>', context, flags=re.IGNORECASE)
        
        # Pattern 2: Check Point specific UID fields (only when explicitly labeled as UID)
        # This catches "uid": "abc123..." or "rule_uid": "abc123..." patterns
        uid_field_pattern = r'("(?:rule_)?uid"\s*:\s*"[0-9a-f]{20,}")'
        context = re.sub(uid_field_pattern, r'"uid": "<UUID>"', context, flags=re.IGNORECASE)
        
        # DEBUG LOGGING: Write full LLM context to file for analysis
        debug_context_file = "./logs/llm_full_context.txt"
        try:
            with open(debug_context_file, 'w') as f:
                f.write("="*80 + "\n")
                f.write("FULL CONTEXT SENT TO LLM\n")
                f.write(f"Timestamp: {datetime.now().isoformat()}\n")
                f.write(f"Model: {final_model}\n")
                f.write("="*80 + "\n\n")
                f.write("CONTEXT:\n")
                f.write("-"*80 + "\n")
                f.write(context)
                f.write("\n" + "-"*80 + "\n\n")
                f.write("ANALYSIS PROMPT:\n")
                f.write("-"*80 + "\n")
                f.write(analysis_prompt)
                f.write("\n" + "-"*80 + "\n\n")
                f.write(f"Estimated size: {len(context)} chars context + {len(analysis_prompt)} chars prompt = {len(context) + len(analysis_prompt)} total chars\n")
                f.write(f"Estimated tokens: ~{(len(context) + len(analysis_prompt))//4:,}\n")
            print(f"[DEBUG] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Written full LLM context to {debug_context_file}")
        except Exception as e:
            print(f"[DEBUG] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Failed to write context debug file: {e}")
        
        # Context management for LLM
        # Estimate token count of the LLM prompt context string
        estimated_tokens = len(context) // 4
        
        # Determine analysis type
        is_log_analysis = analysis_type in ["log_analysis", "security_investigation", "threat_assessment", "security_risk_analysis"]
        
        # Get model's maximum context window
        model_context_limit = 200000  # Default for Claude 3.5 Sonnet
        if hasattr(client, 'get_model_context_window'):
            model_context_limit = client.get_model_context_window(model_name)
        
        # Reserve space for response
        # OpenRouter responses are capped at 8K, so we can be more generous with input
        # Use 90% for input, 10% for output (output is capped at 8K anyway for OpenRouter)
        max_input_tokens = int(model_context_limit * 0.9)
        
        print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Analysis type: {'log/threat' if is_log_analysis else 'standard'}")
        print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Model context limit: {model_context_limit:,} tokens (max input: {max_input_tokens:,})")
        print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Current data size: ~{estimated_tokens:,} tokens")
        
        # Check if truncation is required
        truncation_needed = estimated_tokens > max_input_tokens
        metadata_summary = None
        user_warning = None  # Store warning to show user
        
        if truncation_needed:
            print(f"[WARNING] Data exceeds model capacity: {estimated_tokens:,} > {max_input_tokens:,} tokens")
            
            # Calculate excess percentage
            excess_pct = int(((estimated_tokens - max_input_tokens) / max_input_tokens) * 100)
            
            # Prepare user warning - inform but DON'T truncate (user requirement: send data as-is)
            user_warning = f"""
⚠️ **LARGE DATA WARNING** ⚠️

Your query returned **{estimated_tokens:,} tokens** of data, which exceeds the model's recommended capacity of **{max_input_tokens:,} tokens** by {excess_pct}%.

**The data will be sent as-is to the LLM.** The model may:
- Process it successfully (some models handle overflow gracefully)
- Truncate from the beginning automatically (keeping recent logs)
- Return an error requiring you to narrow the query

**To reduce data size, please:**
- Narrow your time range (e.g., "last 24 hours" instead of "last week")
- Filter by specific gateway, IP, or criteria
- Query specific threat types or security blades
- Break analysis into smaller time windows

---
"""
            
            print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Large data warning prepared - sending data as-is per user requirement (no truncation)")
        
        # Generate final analysis with low temperature for precise formatting
        # max_tokens is auto-calculated based on model's context window for OpenRouter
        # Ollama will use explicit value
        max_tokens_arg = None if client.__class__.__name__ == 'OpenRouterClient' else 4000
        
        try:
            response = client.generate_response(
                prompt=analysis_prompt,
                model=model_name,
                context=context,
                temperature=0.1,  # Very low temperature to ensure strict format compliance
                max_tokens=max_tokens_arg  # Auto-calculated for OpenRouter, explicit for Ollama
            )
        except Exception as api_error:
            # Catch API errors and show them to user
            error_msg = str(api_error)
            print(f"[QueryOrchestrator] API Error during analysis: {error_msg}")
            analysis_text = f"""⚠️ **API Error**

{error_msg}

**What happened:**
The AI model failed to analyze your query due to an API issue.

**Next steps:**
- If this is a credit/billing issue, resolve it with your provider
- If this is a rate limit, wait a moment and try again
- Consider switching to a different AI model (Ollama/OpenRouter) in Settings
- Check that your API keys are valid in Settings"""
            return analysis_text, final_model
        
        if response:
            analysis_text = response
        else:
            # Provide helpful error message when LLM fails
            analysis_text = """Failed to generate analysis. This can happen due to:

1. **Large data volume**: The query returned too much data for the AI model to process
2. **Model limitations**: The selected model may have issues with this type of query
3. **API issues**: Temporary connectivity or service problems

**Suggested actions:**
- Try a more specific query (e.g., "show rules for gateway X" instead of "show all rules")
- Use a different AI model (switch between Ollama and OpenRouter in settings)
- Break your question into smaller parts
- Check the console logs for detailed error information"""
        
        # Prepend user warning if truncation occurred
        if user_warning:
            analysis_text = user_warning + "\n" + analysis_text
            print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] User warning prepended to analysis response")
        
        return (analysis_text, final_model)
    
    def _build_capabilities_description(self) -> str:
        """Build a description of all MCP server capabilities"""
        desc_lines = []
        
        for server_type, capability in self.MCP_CAPABILITIES.items():
            caps = ", ".join(capability.capabilities)
            data = ", ".join(capability.data_types)
            tools = ", ".join(capability.tools) if capability.tools else "auto-detect"
            desc_lines.append(
                f"- {server_type} ({capability.package}): "
                f"Capabilities: [{caps}] | Data Types: [{data}] | Tools: [{tools}]"
            )
        
        return "\n".join(desc_lines)
    
    def _create_fallback_plan(self, user_query: str) -> Dict[str, Any]:
        """Create a basic fallback plan if JSON parsing fails"""
        
        # Simple keyword-based fallback
        query_lower = user_query.lower()
        
        required_servers = []
        analysis_type = "general_query"
        
        # Detect server types based on keywords - be specific!
        # Policy/rule queries → management ONLY (not logs)
        if any(word in query_lower for word in ["policy", "rule", "rulebase", "firewall config", "access control"]):
            required_servers.append("quantum-management")
            analysis_type = "policy_review"
        # Log/traffic queries → logs ONLY (unless already have management)
        elif any(word in query_lower for word in ["log", "connection", "traffic", "audit trail"]):
            required_servers.append("management-logs")
            analysis_type = "log_analysis"
        # Threat queries
        elif any(word in query_lower for word in ["threat", "malware", "attack", "ips"]):
            required_servers.append("threat-prevention")
            analysis_type = "threat_assessment"
        # Gateway queries
        elif any(word in query_lower for word in ["gateway", "interface", "routing"]):
            required_servers.append("quantum-gw-cli")
            analysis_type = "troubleshooting"
        
        # Detect analysis type
        if any(word in query_lower for word in ["risk", "vulnerability", "breach", "security analysis"]):
            analysis_type = "security_risk_analysis"
        elif any(word in query_lower for word in ["troubleshoot", "debug", "issue", "problem", "error"]):
            analysis_type = "troubleshooting"
        
        return {
            "understanding": f"Fallback analysis of: {user_query}",
            "required_servers": required_servers if required_servers else ["quantum-management"],
            "data_to_fetch": ["status", "configuration", "logs"],
            "analysis_type": analysis_type,
            "execution_steps": [
                {"step": 1, "action": f"Query {', '.join(required_servers) if required_servers else 'available servers'}"},
                {"step": 2, "action": "Analyze with selected security model"}
            ],
            "expected_output": "Analysis based on available data",
            "user_query": user_query  # For session context caching
        }
    
    def orchestrate_query(self, user_query: str, planner_model: Optional[str] = None, security_model: Optional[str] = None, user_parameter_selections: Optional[Dict[str, str]] = None, progress_callback=None) -> Dict[str, Any]:
        """Main orchestration method - creates plan, executes it, and returns analysis
        
        Args:
            user_query: The user's query
            planner_model: Model to use for planning (format: "Provider: model_name")
            security_model: Model to use for security analysis (format: "Provider: model_name")
            user_parameter_selections: User-selected parameter values for ambiguous parameters
            progress_callback: Optional callback function(message: str, state: str) for progress updates
        """
        self.progress_callback = progress_callback
        
        # Step 1: Create execution plan using specified planner model
        if self.progress_callback:
            self.progress_callback("🧠 Analyzing your request...")
        
        plan = self.create_execution_plan(user_query, planner_model)
        
        # Step 2: Execute the plan (query MCP servers)
        # Pass user_query explicitly to ensure session context works
        if self.progress_callback:
            servers = plan.get('required_servers', [])
            if servers:
                self.progress_callback(f"🔧 Executing plan on {len(servers)} server(s)...")
            else:
                self.progress_callback("🔧 Executing plan...")
        
        execution_results = self.execute_plan(plan, user_parameter_selections, user_query)
        
        # Check if execution needs user input for parameters
        if execution_results.get("needs_user_input"):
            return {
                "needs_user_input": True,
                "parameter_options": execution_results.get("parameter_options", {}),
                "execution_plan": plan,
                "execution_results": execution_results
            }
        
        # Step 2.5: Validate results and try fallback if needed
        query_type = plan.get('query_type', 'UNKNOWN')
        is_valid, invalid_reason = self._validate_execution_results(execution_results, query_type)
        
        if not is_valid:
            print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Primary execution returned no data: {invalid_reason}")
            
            # Try fallback classification
            fallback_classification = self._get_fallback_classification(query_type, user_query)
            
            if fallback_classification:
                fallback_query_type, fallback_allowed, fallback_forbidden, fallback_instructions = fallback_classification
                print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Trying fallback classification: {fallback_query_type}")
                
                if self.progress_callback:
                    self.progress_callback(f"🔄 No data found, trying alternative sources...")
                
                # Create new plan with fallback classification
                fallback_plan = plan.copy()
                fallback_plan['query_type'] = fallback_query_type
                fallback_plan['required_servers'] = fallback_allowed
                fallback_plan['fallback_attempt'] = True
                fallback_plan['original_query_type'] = query_type
                
                # Re-execute with fallback servers
                execution_results = self.execute_plan(fallback_plan, user_parameter_selections, user_query)
                
                # Update plan to reflect fallback was used
                plan = fallback_plan
                
                # Add warning about fallback
                execution_results.setdefault('warnings', []).append(
                    f"Primary {query_type} query returned no data. Used fallback: {fallback_query_type}"
                )
        
        # Step 3: Analyze results with appropriate model
        if self.progress_callback:
            self.progress_callback("🔍 Analyzing results...")
        
        # Check if this is a troubleshooting query - use iterative analysis
        is_troubleshooting = self._detect_troubleshooting_intent(user_query)
        
        if is_troubleshooting:
            print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Using iterative troubleshooting analysis")
            final_analysis, model_used = self.analyze_iterative_troubleshooting(plan, execution_results, security_model)
        else:
            final_analysis, model_used = self.analyze_with_model(plan, execution_results, security_model)
        
        if self.progress_callback:
            self.progress_callback("✅ Analysis complete", state="complete")
        
        # Return complete orchestration result
        return {
            "user_query": user_query,
            "execution_plan": plan,
            "execution_results": execution_results,
            "final_analysis": final_analysis,
            "model_used": model_used
        }
