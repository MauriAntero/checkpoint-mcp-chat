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
        
        # Network context service for topology awareness
        from services.network_context_service import NetworkContextService
        self.network_context_service = NetworkContextService(mcp_manager)
        
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
        
        intent_prompt = f"""You are analyzing a Check Point security platform query to understand what the user needs.

Available Capabilities:
{capabilities_desc}
{network_context_text}
User Query: "{user_query}"

Return a JSON object describing the user's intent:
{{
    "task_type": "log_analysis | security_investigation | troubleshooting | policy_review | network_analysis | threat_assessment | general_info",
    "primary_goal": "What the user wants to achieve",
    "data_requirements": {{
        "data_types": ["logs | policies | configs | threat_data | network_topology | etc."],
        "time_scope": "real-time | historical | specific_period | not_applicable",
        "specific_period": "last_hour | today | yesterday | last_24_hours | this_week | this_month | last_7_days | last_30_days | all_time | custom",
        "filters": ["IP addresses | users | applications | etc."]
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
        
        planning_prompt = f"""You are creating a technical plan to retrieve data from Check Point security platform MCP servers.

Available MCP Servers:
{capabilities_desc}
{network_context_text}
Active Servers: {', '.join(active_server_types) if active_server_types else 'None'}{gateway_executor_instructions}

User Intent:
- Task: {task_type}
- Goal: {primary_goal}
- Data Needed: {', '.join(data_types)}
- Time Scope: {time_scope} {f"({specific_period})" if specific_period else ""}
{f"- Filters: {', '.join(filters)}" if filters else ""}
{f"- File Path: {file_path}" if file_path else ""}

User Query: "{user_query}"

Return a JSON execution plan:
{{
    "understanding": "{primary_goal}",
    "required_servers": ["server names to query"],
    "data_to_fetch": ["specific data points to retrieve"],
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
            'traffic', 'connection', 'connections', 'session', 'sessions', 'flow', 'flows',
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
                                        print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Processing text item {idx}, length: {len(text_str)} chars")
                                        # Parse JSON from text field
                                        try:
                                            text_data = json.loads(text_str)
                                            
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
                                                            
                                                            for idx, item in enumerate(value):
                                                                if isinstance(item, dict):
                                                                    if sample_original_fields == 0:
                                                                        sample_original_fields = len(item)
                                                                        # DEBUG: Show actual fields in first item
                                                                        print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] DEBUG: First item in '{field}' has fields: {list(item.keys())}")
                                                                    
                                                                    # Smart filtering: Keep fields based on should_keep_field logic
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
                                                            print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Filtered '{field}': kept {len(filtered_items)} items, reduced fields from ~{sample_original_fields} to ~{sample_filtered_fields}")
                                            
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
        
        # Apply intelligent log field filtering to reduce token usage while preserving valuable security information
        data_collected = self._filter_log_fields(data_collected)
        
        # Extract discovered resources for investigation capabilities note (don't duplicate in context)
        has_discovered_resources = any('discovered_resources' in server_data for server_data in data_collected.values())
        
        # Convert MCP data to JSON - discovered_resources already included here, no need to duplicate
        data_json = json.dumps(data_collected, indent=2)
        
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
        
        analysis_prompt = f"""User Query: {user_query}

CRITICAL INSTRUCTIONS - ANTI-HALLUCINATION RULES:
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
   - Clean logs → Report "All activity appears normal"{truncation_warning}

FORMATTING REQUIREMENTS:
- Display object names WITHOUT UUIDs (use human-readable names only)
- Format firewall/NAT rules as markdown tables matching Check Point GUI structure:
  * Access Control Rules: | No. | Name | Source | Destination | Service | Action | Track |
  * NAT Rules: | No. | Name | Original Source | Translated Source | Original Dest | Translated Dest | Original Service | Translated Service |
- Use exact counts from data summaries when available
- Show specific values from the actual data (IPs, hostnames, rule numbers, timestamps)

INVESTIGATION CAPABILITIES:
{'Discovered resources in the data above are available for further investigation if needed.' if has_discovered_resources else 'You can request investigation using available MCP servers and tools if additional data is needed.'}

Analyze the provided data and answer the user's question based solely on what is present in the data."""
        
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
            
            # Calculate truncation percentage
            data_loss_pct = int(((estimated_tokens - max_input_tokens) / estimated_tokens) * 100)
            
            # Prepare user warning (same for all query types)
            user_warning = f"""
⚠️ **DATA TRUNCATION NOTICE** ⚠️

Your query returned **{estimated_tokens:,} tokens** of data, which exceeds the model's capacity of **{max_input_tokens:,} tokens**.

**Approximately {data_loss_pct}% of the data will be excluded to fit the model.**

The AI will analyze the available data (most recent logs and critical information are prioritized).

**To analyze ALL data, please:**
- Narrow your time range (e.g., "last 24 hours" instead of "last week")
- Filter by specific gateway, IP, or criteria
- Break your analysis into smaller time windows
- Query specific threat types or security blades

---
"""
            
            # Truncate context to fit model (prioritize recent data = end of logs)
            max_chars = max_input_tokens * 4
            if len(context) > max_chars:
                keep_start = int(max_chars * 0.3)  # Keep less from start
                keep_end = int(max_chars * 0.7)    # Keep more from end (recent logs)
                truncation_msg = f"\n\n... [Older logs truncated - showing most recent {data_loss_pct}% of data] ...\n\n"
                context = context[:keep_start] + truncation_msg + context[-keep_end:]
                print(f"[QueryOrchestrator] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Context truncated from ~{estimated_tokens:,} to ~{len(context) // 4:,} tokens (prioritized recent data)")
        
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
        
        # Step 3: Analyze results with appropriate model
        if self.progress_callback:
            self.progress_callback("🔍 Analyzing results...")
        
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
