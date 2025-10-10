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
            data_types=["policies", "rules", "network objects", "hosts", "gateways"]
        ),
        "management-logs": MCPServerCapability(
            server_type="management-logs",
            package="@chkp/management-logs-mcp",
            capabilities=[
                "connection logs", "audit logs", "log analysis",
                "traffic patterns", "connection history"
            ],
            data_types=["connection logs", "audit logs", "traffic data"]
        ),
        "threat-prevention": MCPServerCapability(
            server_type="threat-prevention",
            package="@chkp/threat-prevention-mcp",
            capabilities=[
                "threat policies", "IPS profiles", "anti-bot protection",
                "threat indicators", "IOC feeds"
            ],
            data_types=["threat policies", "IPS signatures", "IOC data"]
        ),
        "https-inspection": MCPServerCapability(
            server_type="https-inspection",
            package="@chkp/https-inspection-mcp",
            capabilities=[
                "HTTPS inspection policies", "SSL/TLS inspection",
                "certificate management", "inspection exceptions"
            ],
            data_types=["HTTPS policies", "certificates", "inspection rules"]
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
        
        # Session context for conversational caching
        self.session_context = {
            "last_gateway": None,
            "last_query_time": None,
            "session_timeout_minutes": 10
        }
    
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
    
    def _update_session_context(self, user_query: str, plan: Optional[Dict[str, Any]] = None):
        """Update session context with gateway name from plan or query
        
        Args:
            user_query: User's natural language query
            plan: Optional execution plan from Stage 2 (preferred source for gateway extraction)
        """
        self.session_context["last_query_time"] = datetime.now()
        
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
        
        # Build MCP capabilities summary
        capabilities_summary = []
        for server_name, capability in self.MCP_CAPABILITIES.items():
            capabilities_summary.append(f"- {server_name}: {', '.join(capability.capabilities[:3])}")
        
        intent_prompt = f"""You are an expert at understanding user intent for CheckPoint security infrastructure queries.

Available MCP Server Capabilities:
{chr(10).join(capabilities_summary)}

User Query: "{user_query}"

Analyze this query and extract the user's true intent. Return a JSON object with this structure:
{{
    "task_type": "One of: log_analysis, security_investigation, troubleshooting, policy_review, network_analysis, threat_assessment, general_info",
    "primary_goal": "What the user wants to achieve (1 sentence)",
    "data_requirements": {{
        "data_types": ["list of data types needed: logs, policies, configs, threat_data, network_topology, etc."],
        "time_scope": "real-time, historical, specific_period, or not_applicable",
        "specific_period": "if time_scope is specific_period, specify: last_hour, today, yesterday, last_24_hours, this_week, this_month, last_7_days, last_30_days, all_time, or custom",
        "filters": ["any specific filters mentioned: IP addresses, users, applications, etc."]
    }},
    "expected_outcome": "What format/type of answer user expects (summary, detailed_report, troubleshooting_steps, etc.)",
    "urgency": "routine, important, or critical",
    "context_clues": ["Any implicit requirements or context from the query"],
    "file_path": "Extract file path if mentioned (e.g., '/tmp/threat_emulation/abc_file.exe' or null if none)"
}}

IMPORTANT:
1. Focus ONLY on understanding WHAT the user wants, not HOW to get it
2. Be specific about task_type - log_analysis is for analyzing logs/traffic, security_investigation is for active threats, threat_assessment is for file/malware analysis
3. Extract all time-related information accurately
4. Extract file paths from query (look for patterns like /tmp/, /path/to/, or [Uploaded file: ... at PATH])
5. Identify any implicit requirements (e.g., "unusual patterns" implies comparison/baseline analysis)
6. Return ONLY valid JSON, no other text

Intent Analysis:"""

        # Use planner model for intent analysis
        if planner_model:
            client, model_name = self._get_client_for_model(planner_model)
        else:
            client = self.ollama_client
            model_name = self.ollama_client.general_model
        
        response = client.generate_response(
            prompt=intent_prompt,
            model=model_name,
            temperature=0.2  # Very low temperature for precise intent extraction
        )
        
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
        
        # Get list of active servers
        active_server_names = self.mcp_manager.get_active_servers()
        active_server_types = active_server_names
        
        # Extract key information from intent
        task_type = intent.get('task_type', 'general_info')
        primary_goal = intent.get('primary_goal', user_query)
        data_requirements = intent.get('data_requirements', {})
        data_types = data_requirements.get('data_types', [])
        time_scope = data_requirements.get('time_scope', 'not_applicable')
        specific_period = data_requirements.get('specific_period', '')
        filters = data_requirements.get('filters', [])
        file_path = intent.get('file_path', None)
        
        # Add gateway script executor instructions if enabled
        gateway_executor_instructions = ""
        if self.gateway_script_executor:
            from services.gateway_script_executor import GATEWAY_EXECUTOR_LLM_PROMPT
            gateway_executor_instructions = f"\n\n{GATEWAY_EXECUTOR_LLM_PROMPT}"
        
        planning_prompt = f"""You are a technical planner for CheckPoint MCP servers. Your job is to create a precise execution plan based on user intent.

Available MCP Servers and Their Capabilities:
{capabilities_desc}

Currently Active Servers: {', '.join(active_server_types) if active_server_types else 'None'}{gateway_executor_instructions}

USER INTENT ANALYSIS (from Stage 1):
- Task Type: {task_type}
- Primary Goal: {primary_goal}
- Required Data Types: {', '.join(data_types)}
- Time Scope: {time_scope}
{f"- Specific Period: {specific_period}" if specific_period else ""}
{f"- Filters: {', '.join(filters)}" if filters else ""}
{f"- File Path: {file_path}" if file_path else ""}

Original User Query: "{user_query}"

Based on this intent analysis, create a JSON execution plan with this structure:
{{
    "understanding": "{primary_goal}",
    "required_servers": ["server names that can provide the required data types"],
    "data_to_fetch": ["specific data points matching the intent requirements"],
    "analysis_type": "{task_type}",
    "time_parameters": {{
        "time_scope": "{time_scope}",
        "specific_period": "{specific_period if specific_period else 'not_applicable'}"
    }},
    "execution_steps": [
        {{"step": 1, "action": "Query relevant servers for required data", "server": "server-name"}},
        {{"step": 2, "action": "Analyze data according to task type"}}
    ],
    "expected_output": "Format matching user's expectations"
}}

CRITICAL RULES FOR MCP SERVER SELECTION:
1. Match data_types from intent to server capabilities:
   - logs, traffic_data, connection_data → "management-logs"
   - policies, rules, firewall_config → "quantum-management"  
   - threat_data, IPS, IOC → "threat-prevention"
   - HTTPS_policies, certificates → "https-inspection"
   - gateway_diagnostics, interface_status → "quantum-gw-cli"
   - malware_analysis, file_sandboxing → "threat-emulation"
   - URL/IP/file_reputation → "reputation-service"

2. TASK-SPECIFIC SERVER RULES (CRITICAL):
   - policy_review task → ONLY use "quantum-management" (policies/rules stored here, NOT in logs)
   - log_analysis task → ONLY use "management-logs" (for analyzing historical connections/traffic)
   - security_investigation → MAY use BOTH if correlating policy with actual traffic
   - troubleshooting → quantum-management for config, management-logs for traffic patterns
   
3. Server names (use EXACTLY these):
   quantum-management, management-logs, threat-prevention, https-inspection, 
   harmony-sase, reputation-service, quantum-gw-cli, quantum-gw-connection-analysis,
   threat-emulation, quantum-gaia, spark-management

4. IMPORTANT - Rulebase Distinction:
   - "rulebase", "firewall rules", "access rules", "security rules" → ALWAYS fetch ACCESS CONTROL rules (NOT NAT)
   - "NAT rules", "NAT policy", "NAT rulebase" → fetch NAT rules ONLY when explicitly mentioned
   - Default: When user says "show rules" or "rulebase" without qualification → ACCESS CONTROL rules
   - In data_to_fetch, specify "access_control_rules" or "nat_rules" clearly

4. Time parameters: If specific_period is provided, include it in data_to_fetch for time-sensitive queries

5. File paths: If file_path is provided from intent, MUST include it as the FIRST item in data_to_fetch array (this enables auto-parameter filling for threat-emulation tools)

6. Gateway Identification (CRITICAL for session caching):
   - If user query mentions a specific gateway/firewall name (e.g., "cp-gw", "main-fw", "edge-gateway"), MUST include as first item in data_to_fetch: "gateway_identifier:<gateway-name>"
   - Examples: "show logs from cp-gw" → data_to_fetch: ["gateway_identifier:cp-gw", ...]
   - Examples: "traffic on main-fw" → data_to_fetch: ["gateway_identifier:main-fw", ...]
   - This enables session context caching for follow-up queries
   - Extract the actual gateway NAME from the query, not time expressions like "last" or "this"

7. Return ONLY valid JSON, no other text

Technical Execution Plan:"""

        # Use specified planner model or default to ollama general model
        if planner_model:
            client, model_name = self._get_client_for_model(planner_model)
        else:
            client = self.ollama_client
            model_name = self.ollama_client.general_model
        
        # Use appropriate client for planning
        response = client.generate_response(
            prompt=planning_prompt,
            model=model_name,
            temperature=0.3  # Low temperature for more structured output
        )
        
        if not response:
            return {
                "error": "Failed to create execution plan",
                "understanding": "Could not analyze query",
                "required_servers": [],
                "execution_steps": []
            }
        
        # Parse JSON response
        try:
            # Extract JSON from response (in case there's extra text)
            json_start = response.find('{')
            json_end = response.rfind('}') + 1
            if json_start >= 0 and json_end > json_start:
                json_str = response[json_start:json_end]
                plan = json.loads(json_str)
                # CRITICAL: Inject user_query into plan for session context caching
                plan['user_query'] = user_query
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
        self._update_session_context(query_text, plan)  # Pass plan for LLM-based gateway extraction
        
        # Apply session context to data_to_fetch (inject cached gateway if applicable)
        data_to_fetch = self._apply_session_context(plan.get("data_to_fetch", []), query_text)
        
        # Check for run_script commands if executor is enabled
        if self.gateway_script_executor:
            run_script_commands = [item for item in data_to_fetch if isinstance(item, str) and item.startswith("run_script:")]
            if run_script_commands:
                print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Found {len(run_script_commands)} run_script commands - using Gateway Script Executor")
                
                # Extract gateway name from plan or session context
                gateway_name = self._extract_gateway_from_plan(plan) or self.session_context.get("cached_gateway_name")
                
                # If no gateway specified AND quantum-management is active, query it first to discover gateways
                if not gateway_name and 'quantum-management' in required_servers:
                    print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] No gateway specified, discovering gateways from quantum-management...")
                    # Quick query to discover gateways
                    try:
                        from services.mcp_client_simple import query_mcp_server_async
                        import asyncio
                        import json as json_module
                        
                        # Prepare server config
                        mgmt_server_config = all_servers.get('quantum-management', {})
                        mgmt_env = mgmt_server_config.get('env', {})
                        
                        # Query quantum-management for gateways (package_name, env_vars, data_points)
                        discover_result = asyncio.run(query_mcp_server_async(
                            '@chkp/quantum-management-mcp',
                            mgmt_env,
                            ['show_gateways_and_servers']
                        ))
                        
                        if discover_result and 'content' in discover_result:
                            for item in discover_result['content']:
                                if item.get('type') == 'text':
                                    try:
                                        gw_data = json_module.loads(item['text'])
                                        if isinstance(gw_data, dict) and 'objects' in gw_data:
                                            gateways = [obj['name'] for obj in gw_data['objects'] if obj.get('type') == 'simple-gateway']
                                            if gateways:
                                                gateway_name = gateways[0]
                                                print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Discovered and using gateway: {gateway_name}")
                                                break
                                    except Exception as parse_error:
                                        print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Parse error: {parse_error}")
                    except Exception as e:
                        print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Gateway discovery failed: {e}")
                
                if not gateway_name:
                    results["errors"].append("Gateway Script Executor: No gateway specified. Please include gateway name in your query (e.g., 'Show version on cp-gw')")
                else:
                    # Execute each run_script command
                    for cmd_item in run_script_commands:
                        command = cmd_item.replace("run_script:", "").strip()
                        print(f"[QueryOrchestrator] Executing via executor: '{command}' on gateway '{gateway_name}'")
                        
                        exec_result = self.gateway_script_executor.execute_command(gateway_name, command)
                        
                        if exec_result['success']:
                            if 'gateway_script_executor' not in results["data_collected"]:
                                results["data_collected"]['gateway_script_executor'] = []
                            results["data_collected"]['gateway_script_executor'].append({
                                'command': command,
                                'output': exec_result['output'],
                                'gateway': gateway_name
                            })
                            results["servers_queried"].append("gateway-script-executor")
                        else:
                            results["errors"].append(f"Gateway Script Executor: {exec_result['error']}")
                
                # Remove run_script items from data_to_fetch so they're not sent to regular MCP servers
                data_to_fetch = [item for item in data_to_fetch if not (isinstance(item, str) and item.startswith("run_script:"))]
                
                # If all commands were run_script and none remain, we can skip MCP server queries
                if not data_to_fetch and not required_servers:
                    return results
        
        # PARALLEL EXECUTION: Query all required servers simultaneously
        import asyncio
        
        # Create coroutines for all servers
        async def run_parallel_queries():
            tasks = []
            server_task_map = {}
            
            for server_name in required_servers:
                if server_name in all_servers:
                    task = self._query_mcp_server_async(server_name, data_to_fetch, user_parameter_selections, query_text)
                    tasks.append(task)
                    server_task_map[len(tasks) - 1] = server_name
                else:
                    results["errors"].append(f"Required server '{server_name}' is not configured. Please add it in MCP Servers page.")
            
            # Only run gather if we have tasks (safety check for alignment)
            if tasks:
                return await asyncio.gather(*tasks, return_exceptions=True), server_task_map
            else:
                return [], {}
        
        # Execute all server queries in parallel
        if required_servers:
            print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Executing {len([s for s in required_servers if s in all_servers])} MCP server queries in PARALLEL...")
            
            # Streamlit-compatible async execution: check for existing event loop
            try:
                # Try to get the running event loop (Streamlit/async contexts)
                loop = asyncio.get_running_loop()
                # If we have a running loop, we need to use nest_asyncio or run in executor
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    future = executor.submit(asyncio.run, run_parallel_queries())
                    parallel_results, server_task_map = future.result()
            except RuntimeError:
                # No running event loop, safe to use asyncio.run()
                parallel_results, server_task_map = asyncio.run(run_parallel_queries())
            
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
            results = await query_mcp_server_async(package_name, env_vars, data_points, user_parameter_selections, True, user_query)
            
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
        """Aggressively truncate content for final size reduction"""
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
    
    def _filter_log_fields(self, data_collected: Dict[str, Any]) -> Dict[str, Any]:
        """Filter log data to remove Check Point metadata and reduce token usage
        
        Keeps essential security fields, removes internal metadata.
        Expected token reduction: ~70% (850 tokens/log → 250 tokens/log)
        
        Args:
            data_collected: Raw data from MCP servers
            
        Returns:
            Filtered data with only essential fields
        """
        # Essential fields to keep
        ESSENTIAL_FIELDS = {
            # Core connection data
            'time', 'date', 'src', 'source', 'dst', 'destination', 'service', 'service_id',
            's_port', 'd_port', 'proto', 'action',
            
            # Blade/Origin info
            'origin', 'product', 'blade_name', 'log_id',
            
            # Policy context
            'rule', 'rule_uid', 'rule_name', 'layer_name', 'layer_uid', 'match_id', 'policy',
            
            # NAT information
            'xlatesrc', 'xlatedst', 'xlatesport', 'xlatedport', 'nat_addtnl_rulenum', 'nat_rulenum',
            
            # User/Application - CRITICAL for identity tracking
            'user', 'src_user_name', 'dst_user_name', 'username', 'identity',
            'application', 'app_category', 'app_risk',
            
            # Traffic details
            'bytes', 'sent_bytes', 'received_bytes', 'packets', 'duration', 'conn_direction',
            
            # Threat information
            'attack', 'attack_info', 'severity', 'confidence_level', 'protection_name',
            'malware_action', 'threat_prevention_action',
            
            # VPN specific
            'vpn_feature_name', 'peer_gateway', 'encryption_method', 'community',
            
            # HTTPS Inspection
            'site_name', 'resource', 'method', 'https_inspection_action',
            
            # Audit logs - CRITICAL
            'administrator',
            
            # Object/Gateway metadata - CRITICAL for name-to-IP mapping
            'name',  # Friendly name (e.g., "HR-Server" instead of raw IP)
            'ipv4-address', 'ipv6-address'  # IP addresses for mapping
        }
        
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
                                        print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Processing text item {idx}, length: {len(text_str)} chars")
                                        # Parse JSON from text field
                                        try:
                                            text_data = json.loads(text_str)
                                            
                                            # Handle both dict and list responses
                                            if isinstance(text_data, dict):
                                                print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Parsed JSON dict, keys: {list(text_data.keys())}")
                                            elif isinstance(text_data, list):
                                                print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Parsed JSON list, length: {len(text_data)}")
                                            
                                            # Filter log/object arrays in the parsed JSON (only for dicts)
                                            if isinstance(text_data, dict):
                                                for field in ['logs', 'objects', 'gateways', 'servers', 'hosts', 'networks']:
                                                    if field in text_data and isinstance(text_data[field], list):
                                                        original_count = len(text_data[field])
                                                        print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Filtering {field}: {original_count} items")
                                                        # Filter each log/object to keep only essential fields
                                                        filtered_items = []
                                                        sample_original_fields = 0
                                                        sample_filtered_fields = 0
                                                        for log_item in text_data[field]:
                                                            if isinstance(log_item, dict):
                                                                if sample_original_fields == 0:
                                                                    sample_original_fields = len(log_item)
                                                                filtered_item = {k: v for k, v in log_item.items() if k in ESSENTIAL_FIELDS}
                                                                if sample_filtered_fields == 0 and filtered_item:
                                                                    sample_filtered_fields = len(filtered_item)
                                                                if filtered_item:
                                                                    filtered_items.append(filtered_item)
                                                            else:
                                                                filtered_items.append(log_item)
                                                        text_data[field] = filtered_items
                                                        total_logs_filtered += len(filtered_items)
                                                        print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Filtered {field}: kept {len(filtered_items)} items, reduced fields from ~{sample_original_fields} to ~{sample_filtered_fields}")
                                            
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
                    # Keep other metadata (package, data_type, discovered_resources, etc.)
                    filtered_server_data[key] = value
            
            filtered_data[server_name] = filtered_server_data
        
        print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] _filter_log_fields: Complete! Filtered {total_logs_filtered} total log/object items")
        return filtered_data
    
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
        
        # Apply log field filtering to reduce token usage by ~70%
        data_collected = self._filter_log_fields(data_collected)
        
        # Extract discovered resources for better context
        discovered_resources_summary = {}
        for server_name, server_data in data_collected.items():
            if 'discovered_resources' in server_data:
                discovered_resources_summary[server_name] = server_data['discovered_resources']
        
        # Convert MCP data to JSON (no reduction yet - keep full data)
        data_json = json.dumps(data_collected, indent=2)
        
        # Format discovered resources for LLM
        resources_text = ""
        if discovered_resources_summary:
            resources_text = "\n\nDiscovered Resources (Available for Use):\n"
            for server, resources in discovered_resources_summary.items():
                resources_text += f"\n{server}:\n"
                for tool_name, items in resources.items():
                    resources_text += f"  {tool_name}: {len(items)} items\n"
                    # Show first 5 items as examples
                    for item in items[:5]:
                        resources_text += f"    - {item.get('type', 'unknown')}: {item.get('name', 'N/A')}\n"
                    if len(items) > 5:
                        resources_text += f"    ... and {len(items) - 5} more\n"
        
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
        
        context = f"""Execution Plan: {plan.get('understanding', 'N/A')}

Data Collected from MCP Servers:
{data_json}

Servers Queried: {', '.join(servers_queried)}
Errors: {', '.join(errors) if errors else 'None'}{warnings_text}{resources_text}

---

## CRITICAL - ABSOLUTE PROHIBITION ON DATA FABRICATION

---

YOU MUST NEVER:
✗ Invent statistics, numbers, IP addresses, or any data not present in the Data Collected section above
✗ Make up placeholder data like "100,000 connections" or "192.168.1.100" if not in actual results
✗ Fabricate traffic summaries, log counts, or security findings that don't exist in the data
✗ Pretend API calls succeeded when they failed with errors
✗ Create fictional analysis from missing data

YOU MUST ALWAYS:
✓ Only analyze data that actually exists in the "Data Collected from MCP Servers" section above
✓ If a tool failed with "CheckPoint API error" or "missing parameter", explicitly state that tool failed
✓ If data is missing or unavailable, clearly say "Data not available" - never invent it
✓ If you cannot fully answer the question with available data, be honest about limitations
✓ Base every statistic, IP address, and finding on actual data from the results above

HANDLING ERRORS:
- If tools failed, list which specific tools failed and why (e.g., "show_logs failed: missing parameter")
- If NO useful data was collected, say "No data available to analyze" - do not make up results
- If SOME data exists but is limited, analyze what's there and clearly state what's missing

USING DISCOVERED RESOURCES:
- If discovered resources are shown above, inform the user about what resources are available (gateways, policy packages, etc.)
- Suggest specific follow-up queries using the discovered resource names (e.g., "show me policy 'Standard' rules")
- Guide users on how to query specific resources they see in the discovery results

---

## CRITICAL - OUTPUT FORMATTING REQUIREMENTS (APPLIES TO ALL RESPONSES)

---

OBJECT DISPLAY RULES - ABSOLUTELY CRITICAL:

When you see CheckPoint objects in the data, they may contain BOTH "uid" and "name" fields like this:
{{"uid": "40ff1fb1-a84e-4179-9b7b-590450450022", "name": "All_Internet"}}

YOU MUST:
✓ Extract and display ONLY the "name" field value: "All_Internet"
✓ Use CheckPoint standard names: "Any", "Internet", "All_Internet", "Original"
✓ Use object names like: "wifi-192.168.1.15", "nat-81.197.113.204", "tcp-9053"
✓ Use plain IP addresses when that's the name: "192.168.1.15"
✓ Use network names when available: "Internal_Network", "DMZ"

YOU MUST NEVER:
✗ Display the "uid" field - IGNORE IT COMPLETELY
✗ Display UUIDs (those long hex strings like "40ff1fb1-a84e-4179-9b7b-590450450022")
✗ Show patterns like "uuid (name)" - extract the name only
✗ Show any alphanumeric string that looks like "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

If data contains: {{"uid": "c32bd5f2...", "name": "wifi-192.168.1.15"}}
Display: "wifi-192.168.1.15" (name field ONLY)

FIREWALL RULE FORMATTING - MANDATORY MARKDOWN TABLE STRUCTURE:

YOU MUST format rules as markdown tables to match Check Point's GUI structure.

For Access/Firewall Rules - Use this EXACT markdown table format:

| No. | Name | Source | Destination | Service | Action | Track |
|-----|------|--------|-------------|---------|--------|-------|
| 1 | [rule-name] | [source] | [destination] | [service] | [action] | Log |
| 2 | [rule-name] | [source] | [destination] | [service] | [action] | Log |

EXAMPLE Access/Firewall Rule Table:

| No. | Name | Source | Destination | Service | Action | Track |
|-----|------|--------|-------------|---------|--------|-------|
| 1 | Unnamed Rule | sisaverkko | Any | Botnets, Critical Risk, Phishing, Spyware | Inform | Log |
| 2 | Unnamed Rule | All_Internet | cp-gw, sisaverkko | Botnets, Spyware | Drop | Log |
| 3 | Unnamed Rule | All_Internet | cp-gw, wifi-192.168.1.15 | tcp-9030, tcp-9053 | Accept | Log |
| 4 | Unnamed Rule | sisaverkko | All_Internet | Any | Accept | Log |
| 9 | Cleanup rule | Any | Any | Any | Drop | Log |

For NAT Rules - Use this EXACT markdown table format:

| No. | Name | Original Source | Translated Source | Original Dest | Translated Dest | Original Service | Translated Service |
|-----|------|-----------------|-------------------|---------------|-----------------|------------------|--------------------|
| 1 | [rule-name] | [orig-src] | [trans-src] | [orig-dest] | [trans-dest] | [orig-svc] | [trans-svc] |

EXAMPLE NAT Rule Table:

| No. | Name | Original Source | Translated Source | Original Dest | Translated Dest | Original Service | Translated Service |
|-----|------|-----------------|-------------------|---------------|-----------------|------------------|--------------------|
| 1 | Port Forward SSH | nat-81.197.113.204 | wifi-192.168.1.15 | Original | Original | tcp-22 | Original |
| 2 | Automatic Office Mode | CP_default_Office_Mode_addresses_pool | wifi-192.168.1.15 | Original | Original | Original | Original |

For HTTPS Inspection Rules - Use this EXACT markdown table format:

| No. | Name | Source | Destination | Service | Site Category | Action | Track |
|-----|------|--------|-------------|---------|---------------|--------|-------|
| 1 | [rule-name] | [source] | [destination] | [service] | [site-categories] | [action] | Log |

EXAMPLE HTTPS Inspection Rule Table:

| No. | Name | Source | Destination | Service | Site Category | Action | Track |
|-----|------|--------|-------------|---------|---------------|--------|-------|
| 1 | Predefined Rule | Any | Internet | HTTPS default services | Critical Risk, High Risk | Inspect | Log |
| 2 | Bypass Internal | Internal_Network | Internal_Network | HTTPS | Any | Bypass | Log |

NOTE: Site Category column may contain URL filtering categories like "Critical Risk", "High Risk", "Phishing", "Social Networking", etc.

CRITICAL FORMATTING RULES FOR ALL RULE TABLES:
✓ ALWAYS use markdown table format with | separators
✓ Include header row and separator row (|-----|-----|)
✓ One rule per table row
✓ Keep columns aligned for readability
✓ Display object names ONLY (e.g., "wifi-192.168.1.15", "All_Internet", "tcp-9053")
✓ For multiple services/objects in same cell, use comma separation
✗ NEVER display UIDs/UUIDs (those long hex strings like "40ff1fb1-a84e-4179-9b7b-590450450022")
✗ NEVER use multi-line text format - ONLY markdown tables for rules

This markdown table format applies to ALL rule displays regardless of analysis type (NAT, Access, Firewall, Threat Prevention, Application Control, etc.).
"""
        
        # Create appropriate prompt based on query intent detection
        user_query = plan.get('user_query', 'N/A')
        query_lower = user_query.lower()
        
        # Intent detection using keyword patterns
        
        # 1. Compliance & Audit
        if any(kw in query_lower for kw in ['audit', 'compliance', 'policy change', 'who changed', 'who accessed', 'failed login', 'failed access', 'admin action', 'change history', 'pci', 'hipaa', 'sox', 'gdpr']):
            analysis_prompt = f"""You are a Check Point compliance auditor analyzing security audit data.

User Query: {user_query}

Based on the audit logs and management data, provide:

1. **Audit Summary**:
   - Total events/changes in the time period
   - Admin users involved
   - Systems or policies affected
   - Timeline of key activities

2. **Change Details**:
   - Specific policy/config changes made
   - Who made each change and when
   - Before/after states if available
   - Authorization/approval status

3. **Access Patterns**:
   - Failed vs successful access attempts
   - Unusual access times or locations
   - Privileged account usage
   - Suspicious admin activity

4. **Compliance Status**:
   - Regulatory requirement coverage
   - Gaps or violations identified
   - Evidence for audit trail
   - Recommendations for compliance

Be specific with timestamps, usernames, and exact changes made."""

        # 2. Policy Optimization
        elif any(kw in query_lower for kw in ['unused', 'optimize', 'rule base', 'consolidate', 'permissive rule', 'any any', 'shadowed rule', 'redundant', 'cleanup', 'rule hit', 'overly permissive', 'inconsistent', 'compare polic']):
            analysis_prompt = f"""You are a Check Point firewall optimization specialist analyzing rule base efficiency across your gateway infrastructure.

User Query: {user_query}

Based on the policy data and rule statistics, provide:

1. **Rule Base Analysis** (per gateway if multiple):
   - Total number of rules analyzed across all gateways
   - Rules with zero hits (unused) - specify which gateways
   - Overly permissive rules (any/any/any) - list affected gateways
   - Shadowed or redundant rules

2. **Optimization Opportunities**:
   - Rules that can be consolidated across gateways
   - Duplicate or overlapping rules between gateways
   - Gateway-specific vs shared policy recommendations
   - Rules that can be removed safely

3. **Cross-Gateway Consistency**:
   - Policy inconsistencies between gateways
   - Security level variations across sites
   - Best practice violations by gateway

4. **Action Plan**:
   - Specific rule numbers to modify/remove per gateway
   - Standardization recommendations
   - Priority order for fleet-wide cleanup
   - Testing recommendations

Provide gateway names, rule numbers, specific IPs/services, and exact recommendations."""

        # 3. Capacity Planning & Performance
        elif any(kw in query_lower for kw in ['bandwidth', 'capacity', 'performance', 'top consumer', 'utilization', 'trend', 'forecast', 'peak', 'connection table', 'resource', 'which gateway', 'highest usage']):
            analysis_prompt = f"""You are a Check Point capacity planning analyst assessing network performance across your gateway infrastructure.

User Query: {user_query}

Based on the performance metrics and traffic data, provide:

1. **Resource Utilization** (break down by gateway if multiple):
   - Bandwidth usage statistics per gateway
   - Connection table utilization by location
   - Peak vs average usage across the fleet
   - Trend analysis (growing/stable/declining) by site

2. **Top Consumers**:
   - Top gateways by bandwidth consumption
   - Top IPs/users by bandwidth (across all sites)
   - Top applications by traffic (fleet-wide)
   - Specific numbers and percentages

3. **Capacity Assessment**:
   - Which gateways are approaching limits
   - Projected growth rates per location
   - When each gateway will reach capacity
   - Bottleneck identification across infrastructure

4. **Recommendations**:
   - Capacity upgrade priorities by gateway
   - Traffic optimization opportunities
   - Load balancing suggestions between sites
   - Monitoring improvements

Include specific metrics, gateway names, percentages, and time-based trends."""

        # 4. User/Application Behavior
        elif any(kw in query_lower for kw in ['user behavior', 'top user', 'baseline', 'anomaly', 'unusual behavior', 'shadow it', 'app usage', 'user activity', 'application usage', 'applications are']):
            analysis_prompt = f"""You are a Check Point user behavior analyst examining network activity patterns.

User Query: {user_query}

Based on user and application traffic data, provide:

1. **User Activity Summary**:
   - Top users by traffic/connections
   - Unusual user behavior detected
   - User access patterns
   - Off-hours activity

2. **Application Analysis**:
   - Most used applications
   - Unauthorized/shadow IT apps
   - Application bandwidth consumption
   - Application security risks

3. **Baseline Comparison**:
   - Normal vs current behavior
   - Statistical anomalies detected
   - Deviation from baseline
   - Contextual analysis

4. **Risk Assessment**:
   - High-risk user behaviors
   - Unauthorized application usage
   - Data exfiltration indicators
   - Recommended investigations

Be specific with usernames, applications, and behavioral metrics."""

        # 5. Incident Response & Forensics
        elif any(kw in query_lower for kw in ['incident', 'attack', 'breach', 'compromise', 'forensic', 'timeline', 'lateral movement', 'exfiltration', 'investigate', 'trace', 'reconstruct']):
            analysis_prompt = f"""You are a Check Point incident response analyst conducting security forensics.

User Query: {user_query}

Based on the security event data, provide a forensic analysis:

1. **Incident Timeline**:
   - Chronological sequence of events
   - Initial compromise indicators
   - Attack progression stages
   - Key timestamps and actions

2. **Attack Analysis**:
   - Attack vectors used
   - Systems/accounts compromised
   - Lateral movement patterns
   - Data exfiltration attempts

3. **Evidence Collection**:
   - Malicious IPs and indicators
   - Compromised credentials
   - Attack signatures matched
   - Log evidence for each finding

4. **Remediation & Recovery**:
   - Immediate containment actions
   - Systems requiring investigation
   - Evidence preservation steps
   - Post-incident hardening

Provide detailed timeline, specific IPs/hosts, and complete attack chain."""

        # 6. Security Posture Assessment
        elif any(kw in query_lower for kw in ['posture', 'exposure', 'exposed', 'internet facing', 'vulnerability', 'best practice', 'security gap', 'protection gap', 'risk assessment', 'hardening', 'security check', 'compare security', 'which gateway']):
            analysis_prompt = f"""You are a Check Point security architect assessing security posture across your gateway infrastructure.

User Query: {user_query}

Based on the configuration and topology data, provide:

1. **Exposure Analysis** (per gateway if multiple):
   - Internet-facing services/ports by gateway
   - Public IP exposure across the fleet
   - Inbound access points per location
   - Attack surface comparison between gateways

2. **Configuration Review**:
   - Security best practice violations by gateway
   - Weak or missing protections per site
   - SSL/TLS policy inconsistencies
   - NAT and routing security gaps

3. **Gap Identification**:
   - Missing security controls (specify which gateways)
   - Unprotected traffic flows across infrastructure
   - Incomplete threat prevention coverage
   - Policy coverage gaps by location

4. **Fleet-Wide Risk Assessment**:
   - Which gateways have the highest risk exposure
   - Security maturity comparison across sites
   - Standardization opportunities
   - Priority remediation by gateway

5. **Hardening Recommendations**:
   - Gateway-specific configuration improvements
   - Fleet-wide security control additions
   - Priority remediation items with gateway names
   - Implementation guidance

Be specific with gateway names, service names, ports, and exact configuration recommendations."""

        # 7. Troubleshooting (MUST come before log analysis due to "connection" keyword conflict)
        elif any(kw in query_lower for kw in ['troubleshoot', 'debug', 'fix', 'problem', 'issue', 'error', "can't", "cannot connect", 'why can', 'interface', 'routing', 'gateway status', 'network interface']) or analysis_type == "troubleshooting":
            analysis_prompt = f"""You are a Check Point network engineer troubleshooting connectivity issues using comprehensive diagnostics.

User Query: {user_query}

Analyze diagnostic data from Gateway CLI, Connection Analysis, GAIA interfaces, and logs to provide:

1. **Problem Identification**:
   - What's not working (be specific)
   - Symptoms observed in the data
   - Affected connections, services, or interfaces

2. **Root Cause Analysis**:
   - Likely cause based on logs/configs
   - Policy rules blocking traffic
   - Routing or NAT issues
   - Interface status problems (from GAIA)
   - Gateway-level diagnostics (from CLI)
   - Connection-specific debug logs

3. **Step-by-Step Solution**:
   - Immediate fixes to try
   - Policy or config changes needed
   - Interface configuration adjustments
   - Gateway commands to run
   - Verification steps

4. **Prevention**:
   - How to avoid this issue
   - Monitoring recommendations
   - Network configuration best practices

Be technical and specific with gateway names, interface IDs, rule numbers, IPs, ports, and exact commands."""

        # 8a. NAT Policy/Rule Review (only when explicitly requested)
        elif any(kw in query_lower for kw in ['nat rule', 'nat policy', 'show nat', 'nat rulebase', 'show my nat', 'current nat']):
            analysis_prompt = f"""You are a Check Point firewall administrator reviewing NAT policies.

User Query: {user_query}

Based on the NAT policy data collected from Check Point Management, provide a clear, well-formatted presentation of the NAT rules:

1. **NAT Rule Summary**:
   - Total number of NAT rules found
   - Policy package name
   - Automatic vs manual rules

2. **NAT Rule Details**:
   - Use the structured format specified in the global formatting requirements above
   - Show rule numbers and names clearly
   - Indicate if translation is "Original" (no change)
   - Highlight automatic NAT rules

3. **Key Observations**:
   - Important NAT implications
   - Potential conflicts
   - Recommendations

Remember: Follow the global formatting requirements for object names and rule display. DO NOT expect or request log data unless logs were specifically queried."""

        # 8b. General Policy Review (comprehensive - both Access and NAT)
        elif any(kw in query_lower for kw in ['analyze policy', 'review policy', 'current policy', 'firewall policy', 'my policy', 'policy analysis', 'policy review']):
            analysis_prompt = f"""You are a Check Point firewall administrator conducting a comprehensive policy review.

User Query: {user_query}

Based on the policy data from Check Point Management, provide a structured analysis:

1. **Policy Summary**:
   - Policy package name
   - Total number of Access Control rules  
   - Total number of NAT rules (manual + automatic)
   - Zero-hits analysis status

2. **ACCESS RULEBASE** (MANDATORY):
   Present ALL access control rules using this EXACT 7-column table format:
   
   | No. | Name | Source | Destination | Service | Action | Track |
   
   Follow the global formatting requirements - object names without UUIDs.

3. **NAT RULEBASE** (MANDATORY):
   Present ALL NAT rules using this EXACT 8-column table format:
   
   | No. | Name | Original Source | Translated Source | Original Dest | Translated Dest | Original Service | Translated Service |
   
   Follow the global formatting requirements. Indicate automatic rules if present.

4. **Key Observations**:
   - Security implications
   - Overly permissive rules
   - Recommendations

CRITICAL: You MUST display BOTH access and NAT rulebases in markdown tables. This is a complete policy review."""

        # 8c. Access Control / Firewall Rule Review (default for "rulebase")
        elif any(kw in query_lower for kw in ['access rule', 'firewall rule', 'rulebase', 'show rule', 'list rule', 'what rule', 'policy package', 'security rule', 'access control', 'show my rule', 'current rule']):
            analysis_prompt = f"""You are a Check Point firewall administrator reviewing security policies and rules.

User Query: {user_query}

Based on the policy data collected from Check Point Management, provide a clear, well-formatted presentation of the rules:

1. **Rule Summary**:
   - Total number of rules found
   - Rule types (NAT, Access, etc.)
   - Policy package name

2. **Rule Details**:
   - Use the structured format specified in the global formatting requirements above
   - Show rule numbers and names clearly
   - Indicate if NAT translation is "Original" (no change)

3. **Key Observations**:
   - Important security implications
   - Overly permissive rules (if any)
   - Gaps or recommendations

Remember: Follow the global formatting requirements for object names and rule display. DO NOT expect or request log data unless logs were specifically queried."""

        # 9. Log/Traffic Analysis
        elif any(kw in query_lower for kw in ['log', 'traffic', 'connection', 'activity', 'audit trail', 'session']):
            analysis_prompt = f"""You are a Check Point network security administrator analyzing firewall data from multiple sources.

User Query: {user_query}

⚠️ CRITICAL: If you see a "COMPLETE DATA SUMMARY" section in the context, USE THOSE EXACT COUNTS for your analysis. The summary contains the full statistics from ALL logs before truncation. Never rely on counting sample data below the summary - always use the summary's precise totals.

Based on the collected data (Management Logs, Gateway CLI, Connection Analysis), provide:

1. **Traffic Summary** (if log data available):
   - Total connections/sessions analyzed (USE EXACT COUNT FROM DATA SUMMARY if present)
   - Top source and destination IPs
   - Most common ports and protocols
   - Blocked vs allowed traffic ratio

2. **Anomalies and Patterns**:
   - Unusual connection patterns detected
   - Suspicious port usage or protocols
   - Geographic anomalies (unexpected countries)
   - Time-based patterns (off-hours activity)

3. **Security Events** (if available):
   - IPS/threat prevention hits (USE EXACT COUNT FROM DATA SUMMARY if present)
   - High-severity alerts
   - Blocked threats by type
   - Attack patterns observed
   - SSL/TLS inspection findings

4. **Actionable Insights**:
   - Specific IPs or hosts requiring attention
   - Recommended policy adjustments
   - Investigation priorities

ALWAYS report exact counts when a DATA SUMMARY is available. Be specific with numbers, IPs, and concrete findings."""

        # 9. Threat Hunting
        elif analysis_type == "security_risk_analysis" or any(kw in query_lower for kw in ['reputation', 'malware', 'sandbox', 'emulation', 'url reputation', 'ip reputation', 'file reputation', 'check url', 'check ip', 'analyze file']):
            analysis_prompt = f"""You are a Check Point security analyst investigating threats using multiple intelligence sources.

User Query: {user_query}

⚠️ CRITICAL: If you see a "COMPLETE DATA SUMMARY" section in the context, USE THOSE EXACT COUNTS for your analysis. The summary contains full statistics from ALL threat logs before truncation. Always use the summary's precise totals, never count sample data.

Based on threat intelligence (Threat Prevention, Reputation Service, Threat Emulation, HTTPS Inspection), provide:

1. **Threat Summary**:
   - Active threats detected (USE EXACT COUNT FROM DATA SUMMARY if present)
   - Severity levels (Critical/High/Medium/Low) with exact counts
   - Attack types observed (by blade/category with counts)
   - Affected systems or networks

2. **Indicators of Compromise (IOCs)**:
   - Malicious IPs, URLs, or file hashes (from Reputation Service)
   - Known attack signatures matched
   - Bot/DDoS activity detected
   - SSL/TLS-based threats (HTTPS Inspection)
   - Malware analysis results (Threat Emulation sandbox)

3. **Impact Assessment**:
   - Systems or data at risk
   - Current protection status
   - Gaps in coverage

4. **Immediate Actions**:
   - Specific threats to block
   - Policy changes needed (including HTTPS inspection policies)
   - Investigation steps
   - Files requiring sandboxing

ALWAYS report exact event counts when a DATA SUMMARY is available. Focus on actionable intelligence with specific IOCs and evidence."""

        # 10. General/Fallback (including SASE, Spark, and other specialized queries)
        else:
            # Detect if this is a SASE or Spark Management query
            is_sase = any(kw in query_lower for kw in ['sase', 'harmony sase', 'cloud security', 'ztna', 'casb'])
            is_spark = any(kw in query_lower for kw in ['spark', 'msp', 'quantum spark', 'customer appliance'])
            
            if is_sase:
                analysis_prompt = f"""You are a Check Point Harmony SASE administrator analyzing cloud security configurations.

User Query: {user_query}

IMPORTANT: Check the context above for errors. If the harmony-sase server is not active:
- Inform the user that Harmony SASE MCP server is not configured or activated
- Explain that they need to go to the MCP Servers page and configure the harmony-sase server
- Describe what Harmony SASE provides (ZTNA, CASB, cloud security) so they understand the value

If Harmony SASE data IS available, provide:

1. **SASE Configuration Summary**:
   - Current SASE policies and settings
   - Zero Trust Network Access (ZTNA) configurations
   - Cloud Application Security Broker (CASB) policies
   - Remote access configurations

2. **Security Posture**:
   - Active security policies
   - User access patterns
   - Application controls
   - Data protection status

3. **Recommendations**:
   - Configuration improvements
   - Policy optimization opportunities
   - Security enhancements

Be specific with policy names and configuration details."""
            
            elif is_spark:
                analysis_prompt = f"""You are an MSP administrator managing Quantum Spark appliances for customers.

User Query: {user_query}

IMPORTANT: Check the context above for errors. If the spark-management server is not active:
- Inform the user that Quantum Spark Management MCP server is not configured or activated
- Explain that they need to go to the MCP Servers page and configure the spark-management server
- Describe what Spark Management provides (MSP customer appliance management) so they understand the value

If Spark Management data IS available, provide:

1. **Appliance Overview**:
   - Spark appliances under management
   - Customer deployments
   - Appliance health and status
   - Version information

2. **Management Insights**:
   - Configuration status by customer
   - Security posture across customers
   - Update and maintenance requirements
   - Performance metrics

3. **MSP Recommendations**:
   - Customer-specific actions needed
   - Fleet-wide improvements
   - Service delivery enhancements

Be specific with customer names, appliance IDs, and actionable recommendations."""
            
            else:
                analysis_prompt = f"""You are a Check Point administrator responding to this query:

"{user_query}"

Based on data from available Check Point services (Management, Logs, Threat Prevention, HTTPS Inspection, Reputation, Gateway CLI, GAIA, Connection Analysis, Threat Emulation, SASE, Spark), provide:

1. **Direct Answer**: Address the user's specific question
2. **Key Data Points**: Highlight relevant information from the collected data
3. **Context**: Explain what the data shows and which services provided it
4. **Recommendations**: Suggest next steps or actions if applicable

Be concise and focus on what's actually in the data. If the data doesn't fully answer the question, clearly state what's available and what additional data might be needed."""
        
        # Determine which client to use based on model prefix
        if isinstance(final_model, str) and (":" in final_model):
            client, model_name = self._get_client_for_model(final_model)
            print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Client type: {client.__class__.__name__}, Model: {model_name}")
        else:
            client = self.ollama_client
            model_name = final_model
            print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Using Ollama client (no prefix detected), Model: {model_name}")
        
        # FINAL UUID CLEANUP PASS - Aggressively remove ALL CheckPoint UID variants from context
        # This ensures the LLM never sees UIDs even if cleaning missed some
        import re
        
        # Pattern 1: Standard hyphenated UUIDs (8-4-4-4-12)
        hyphenated_uuid_pattern = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
        context = re.sub(hyphenated_uuid_pattern, '<REDACTED>', context, flags=re.IGNORECASE)
        
        # Pattern 2: Non-hyphenated 32-character hex strings (CheckPoint UID variant)
        # Must not be part of a longer hex string, and must be standalone
        non_hyphenated_uuid_pattern = r'\b[0-9a-f]{32}\b'
        context = re.sub(non_hyphenated_uuid_pattern, '<REDACTED>', context, flags=re.IGNORECASE)
        
        # Pattern 3: Catch any remaining suspicious long hex strings (28+ chars)
        long_hex_pattern = r'\b[0-9a-f]{28,}\b'
        context = re.sub(long_hex_pattern, '<REDACTED>', context, flags=re.IGNORECASE)
        
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
            
            if is_log_analysis:
                # Extract metadata for aggregated summary
                metadata_summary = self._extract_log_metadata(data_collected)
                
                # Prepare user warning message
                data_loss_pct = int(((estimated_tokens - max_input_tokens) / estimated_tokens) * 100)
                user_warning = f"""
⚠️ **DATA TRUNCATION NOTICE** ⚠️

Your query returned **{estimated_tokens:,} tokens** of data, which exceeds the model's capacity of **{max_input_tokens:,} tokens**.

**Approximately {data_loss_pct}% of the detailed log data will be truncated.**

**To get full field-level analysis, please:**
- Narrow your time range (e.g., "last 24 hours" instead of "last week")
- Filter by specific gateway or source IP
- Query specific threat types or blades
- Break your analysis into smaller time windows

**Current Analysis Mode: AGGREGATED METADATA ONLY**
The analysis below is based on statistical aggregation (counts, distributions) rather than complete field-level detail (individual IPs, ports, timestamps).

---
"""
                # Add metadata to context for LLM (but not full warning - we'll show that to user separately)
                context = (metadata_summary or "") + "\n\n" + context
                
                # Truncate context to fit model
                max_chars = max_input_tokens * 4
                if len(context) > max_chars:
                    keep_start = int(max_chars * 0.6)
                    keep_end = int(max_chars * 0.2)
                    context = context[:keep_start] + f"\n\n... [Log details truncated - {data_loss_pct}% of data omitted] ...\n\n" + context[-keep_end:]
                    print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Context truncated from ~{estimated_tokens:,} to ~{len(context) // 4:,} tokens")
            else:
                # Standard analysis truncation
                data_loss_pct = int(((estimated_tokens - max_input_tokens) / estimated_tokens) * 100)
                user_warning = f"""
⚠️ **DATA TRUNCATION NOTICE** ⚠️

Your query returned **{estimated_tokens:,} tokens** of data, which exceeds the model's capacity of **{max_input_tokens:,} tokens**.

**Approximately {data_loss_pct}% of the data will be truncated.**

**To get complete analysis, please:**
- Narrow your query scope (specific gateways, objects, or rules)
- Break your question into smaller parts
- Filter by specific criteria

---
"""
                max_chars = max_input_tokens * 4
                if len(context) > max_chars:
                    keep_start = int(max_chars * 0.6)
                    keep_end = int(max_chars * 0.2)
                    truncation_msg = f"\n\n... [Data truncated - {data_loss_pct}% omitted to fit model limits] ...\n\n"
                    context = context[:keep_start] + truncation_msg + context[-keep_end:]
                    print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Context truncated from ~{estimated_tokens:,} to ~{len(context) // 4:,} tokens")
        
        # Generate final analysis with low temperature for precise formatting
        # max_tokens is auto-calculated based on model's context window for OpenRouter
        # Ollama will use explicit value
        max_tokens_arg = None if client.__class__.__name__ == 'OpenRouterClient' else 4000
        
        response = client.generate_response(
            prompt=analysis_prompt,
            model=model_name,
            context=context,
            temperature=0.1,  # Very low temperature to ensure strict format compliance
            max_tokens=max_tokens_arg  # Auto-calculated for OpenRouter, explicit for Ollama
        )
        
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
            desc_lines.append(
                f"- {server_type} ({capability.package}): "
                f"Capabilities: [{caps}] | Data Types: [{data}]"
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
    
    def orchestrate_query(self, user_query: str, planner_model: Optional[str] = None, security_model: Optional[str] = None, user_parameter_selections: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """Main orchestration method - creates plan, executes it, and returns analysis
        
        Args:
            user_query: The user's query
            planner_model: Model to use for planning (format: "Provider: model_name")
            security_model: Model to use for security analysis (format: "Provider: model_name")
            user_parameter_selections: User-selected parameter values for ambiguous parameters
        """
        
        # Step 1: Create execution plan using specified planner model
        plan = self.create_execution_plan(user_query, planner_model)
        
        # Step 2: Execute the plan (query MCP servers)
        # Pass user_query explicitly to ensure session context works
        execution_results = self.execute_plan(plan, user_parameter_selections, user_query)
        
        # Check if execution needs user input for parameters
        if execution_results.get("needs_user_input"):
            return {
                "needs_user_input": True,
                "parameter_options": execution_results.get("parameter_options", {}),
                "execution_plan": plan,
                "execution_results": execution_results
            }
        
        # Step 3: Analyze results with appropriate model
        final_analysis, model_used = self.analyze_with_model(plan, execution_results, security_model)
        
        # Return complete orchestration result
        return {
            "user_query": user_query,
            "execution_plan": plan,
            "execution_results": execution_results,
            "final_analysis": final_analysis,
            "model_used": model_used
        }
