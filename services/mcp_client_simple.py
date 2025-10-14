"""Simplified MCP Client that works with existing subprocess management"""

import os
import re
import json
import asyncio
import time
import random
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from services.gateway_directory import GatewayDirectory

# Module-level gateway directory instance (loads from disk cache)
_gateway_directory = None

def _get_gateway_directory():
    """Get or create gateway directory instance (singleton pattern)"""
    global _gateway_directory
    if _gateway_directory is None:
        _gateway_directory = GatewayDirectory()
    return _gateway_directory

# Module-level cache for discovered resources (access layers, packages, etc.)
# Keyed by MCP server package name to avoid cross-contamination
_discovered_resources_cache = {}

def _ts():
    """Return timestamp string for debug logging"""
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]

@dataclass
class MCPTool:
    """Represents an MCP tool exposed by a server"""
    name: str
    description: str
    input_schema: Dict[str, Any]

async def call_tool_with_retry(
    session: ClientSession,
    tool_name: str,
    arguments: Dict[str, Any],
    max_retries: int = 3,
    initial_delay: float = 1.0,
    max_delay: float = 10.0
):
    """
    Call MCP tool with exponential backoff retry logic for API rate limiting.
    
    Args:
        session: MCP client session
        tool_name: Name of the tool to call
        arguments: Tool arguments
        max_retries: Maximum number of retry attempts (default 3)
        initial_delay: Initial delay in seconds before first retry (default 1.0)
        max_delay: Maximum delay between retries (default 10.0)
    
    Returns:
        Tool result from successful call
        
    Raises:
        Exception: If all retries are exhausted
    """
    last_exception = None
    
    for attempt in range(max_retries + 1):  # +1 for initial attempt
        try:
            result = await session.call_tool(tool_name, arguments=arguments)
            
            # Check if response contains rate limit error (Check Point MCP servers embed errors in response)
            # CRITICAL: Only check error/metadata fields, NOT data payloads to avoid false positives
            is_rate_limit_in_response = False
            result_str = str(result).lower()  # Initialize early for error messages
            
            # Try to parse response structure to check only error fields
            try:
                # Extract text content if it's an MCP response
                if hasattr(result, 'content') and isinstance(result.content, list):
                    for item in result.content:
                        if isinstance(item, dict) and 'text' in item:
                            text = item['text']
                            try:
                                data = json.loads(text)
                                # Check ONLY error/message/status fields, NOT data arrays like "logs"
                                error_fields = {
                                    k: v for k, v in data.items() 
                                    if k.lower() in ['error', 'message', 'errors', 'status', 'code', 'error_message']
                                }
                                if error_fields:
                                    error_str = str(error_fields).lower()
                                    is_rate_limit_in_response = (
                                        'err_too_many_requests' in error_str or
                                        'too many requests' in error_str or
                                        'quota exceeded' in error_str or
                                        '429' in error_str or
                                        'rate limit exceeded' in error_str or
                                        ('rate' in error_str and 'limit' in error_str)
                                    )
                                    if is_rate_limit_in_response:
                                        break
                            except json.JSONDecodeError:
                                pass  # Not JSON, skip structured check
            except Exception:
                pass  # Fallback to string check if structured parsing fails
            
            # No structured rate limit found - check if this is a successful response with data
            # If response has "logs" or "objects" array, it's valid data, not an error
            if not is_rate_limit_in_response:
                has_data = (
                    '"logs":' in result_str or 
                    '"objects":' in result_str or
                    '"gateways":' in result_str
                )
                
                # Only check for rate limits if no data arrays present (likely an error response)
                if not has_data:
                    is_rate_limit_in_response = (
                        'err_too_many_requests' in result_str or
                        'too many requests' in result_str or
                        'quota exceeded' in result_str or
                        'rate limit exceeded' in result_str
                    )
            
            if is_rate_limit_in_response:
                # Rate limit error embedded in response - treat as exception
                error_msg = f"Rate limit error in response: {result_str[:200]}"
                last_exception = Exception(error_msg)
                
                if attempt < max_retries:
                    # Calculate exponential backoff with jitter
                    delay = min(initial_delay * (2 ** attempt), max_delay)
                    jitter = random.uniform(0, delay * 0.1)  # Add 10% jitter
                    total_delay = delay + jitter
                    
                    print(f"[MCP_DEBUG] [{_ts()}] ⏳ Rate limit detected in response for {tool_name} (attempt {attempt + 1}/{max_retries + 1}). Retrying in {total_delay:.2f}s...")
                    await asyncio.sleep(total_delay)
                    continue  # Try again
                else:
                    # All retries exhausted
                    print(f"[MCP_DEBUG] [{_ts()}] ✗ All {max_retries + 1} attempts failed for {tool_name} due to rate limiting")
                    raise last_exception
            
            # Success - log if it was a retry
            if attempt > 0:
                print(f"[MCP_DEBUG] [{_ts()}] ✓ Retry successful for {tool_name} on attempt {attempt + 1}")
            
            return result
            
        except Exception as e:
            last_exception = e
            error_msg = str(e).lower()
            
            # Check if it's a rate limit error in exception
            is_rate_limit = any(phrase in error_msg for phrase in [
                'too many requests',
                'rate limit',
                '429',
                'throttle',
                'quota exceeded'
            ])
            
            # Only retry on rate limit errors or temporary failures
            if not is_rate_limit and attempt == 0:
                # Not a rate limit error - fail immediately
                raise
            
            if attempt < max_retries:
                # Calculate exponential backoff with jitter
                delay = min(initial_delay * (2 ** attempt), max_delay)
                jitter = random.uniform(0, delay * 0.1)  # Add 10% jitter
                total_delay = delay + jitter
                
                print(f"[MCP_DEBUG] [{_ts()}] ⏳ Rate limit hit for {tool_name} (attempt {attempt + 1}/{max_retries + 1}). Retrying in {total_delay:.2f}s...")
                await asyncio.sleep(total_delay)
            else:
                # All retries exhausted
                print(f"[MCP_DEBUG] [{_ts()}] ✗ All {max_retries + 1} attempts failed for {tool_name}: {last_exception}")
                raise last_exception

def clean_uuids_from_data(obj: Any, parent_key: str = None) -> Any:
    """Remove UUIDs from CheckPoint object data, keeping only readable names
    
    Handles multiple CheckPoint data formats:
    1. Objects with uid/name fields: {"uid": "xxx", "name": "yyy"} -> "yyy"
    2. Strings with "uuid (name)" pattern -> "name"  
    3. Standalone UUID strings -> removed/replaced with placeholder
    
    CRITICAL FIXES:
    - Preserves action field intrinsic name (Drop/Accept) without dictionary lookups
    - Preserves site-category embedded names to avoid duplicates
    
    Args:
        obj: Any data structure (dict, list, str, etc.)
        parent_key: Key from parent dict (for context-aware processing)
        
    Returns:
        Cleaned version with UUIDs removed and names extracted
    """
    # UUID pattern: 8-4-4-4-12 hex digits
    uuid_pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    uuid_with_name_pattern = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\s*\(\s*([^)]+)\s*\)'
    
    if isinstance(obj, dict):
        # CRITICAL DATA FIELDS that must be preserved (rulebase, logs, objects, etc.)
        # Container fields - if present, preserve the entire dict structure
        container_fields = {
            'rulebase', 'objects-dictionary', 'logs', 'objects', 
            'gateways', 'servers', 'nat-rulebase', 'access-rulebase'
        }
        
        # STEP 1: Check for container fields FIRST (highest priority)
        if any(field in obj for field in container_fields):
            # This is a complex container object - preserve all fields
            return {key: clean_uuids_from_data(value, key) for key, value in obj.items()}
        
        # STEP 2: Check for rule objects (BEFORE uid/name checks)
        # Rule objects can be identified by specific field combinations OR rule-identifying fields
        # This catches rules regardless of whether they have 'name' field or not
        
        # Access Control Rule indicators
        is_access_rule = (
            ('source' in obj and 'destination' in obj and ('service' in obj or 'services' in obj)) or
            ('type' in obj and obj.get('type') == 'access-rule') or
            ('rule-number' in obj and 'action' in obj)  # Fallback: rule-number + action = definitely a rule
        )
        
        # NAT Rule indicators
        is_nat_rule = (
            (('original-source' in obj or 'original-destination' in obj) or
             ('translated-source' in obj or 'translated-destination' in obj)) or
            ('type' in obj and obj.get('type') == 'nat-rule')
        )
        
        # HTTPS Inspection Rule indicators
        is_https_rule = (
            ('type' in obj and obj.get('type') == 'https-rule') or
            ('site-category' in obj and 'blade' in obj)
        )
        
        if is_access_rule or is_nat_rule or is_https_rule:
            # This is a firewall, NAT, or HTTPS rule - preserve ALL fields
            return {key: clean_uuids_from_data(value, key) for key, value in obj.items()}
        
        # STEP 3: SPECIAL HANDLING for action and site-category objects
        # These fields have embedded names that must be preserved WITHOUT dictionary lookups
        if parent_key in ['action', 'site-category']:
            # Check if this is an action/category object with embedded name
            if 'name' in obj:
                # Return the intrinsic name directly, ignore UID
                print(f"[SANITIZER_DEBUG] Preserving {parent_key} name: {obj['name']}")
                return obj['name']
            # If no name field but has uid, preserve it for debugging
            elif 'uid' in obj:
                uid_val = obj['uid']
                if isinstance(uid_val, str) and re.match(uuid_pattern, uid_val, flags=re.IGNORECASE):
                    print(f"[SANITIZER_DEBUG] Converting {parent_key} UID to ref: {uid_val[:8]}")
                    return f"<{parent_key}-{uid_val[:8]}>"
                return uid_val
        
        # STEP 4: Now check uid/name combinations for simple objects
        if 'uid' in obj and 'name' in obj:
            # Simple object with uid/name (host, network, service) - collapse to name
            if parent_key in ['action', 'site-category']:
                print(f"[SANITIZER_DEBUG] WARNING: {parent_key} object reached step 4 with name={obj['name']}")
            return obj['name']
        
        # If dict has 'uid' but no 'name', try to use uid as fallback (but clean it)
        elif 'uid' in obj and 'name' not in obj:
            uid_val = obj['uid']
            # If it's a UUID, return a placeholder or the uid itself
            if isinstance(uid_val, str) and re.match(uuid_pattern, uid_val, flags=re.IGNORECASE):
                return f"<object-{uid_val[:8]}>"  # Use first 8 chars as identifier
            return uid_val
        
        # Otherwise, recursively clean all values in the dict
        else:
            return {key: clean_uuids_from_data(value, key) for key, value in obj.items()}
    
    elif isinstance(obj, str):
        # Pattern 1: "uuid (name)" -> extract name
        cleaned = re.sub(uuid_with_name_pattern, r'\1', obj, flags=re.IGNORECASE)
        
        # Pattern 2: standalone UUID -> remove or replace
        if re.match(uuid_pattern, cleaned, flags=re.IGNORECASE):
            return f"<uuid-{cleaned[:8]}>"  # Keep first 8 chars for reference
        
        return cleaned
    
    elif isinstance(obj, list):
        # For lists, preserve parent_key context (e.g., action array, site-category array)
        return [clean_uuids_from_data(item, parent_key) for item in obj]
    
    else:
        return obj

def extract_uuid_mappings(obj: Any, mappings: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """Extract UUID->name mappings from objects-dictionary BEFORE cleaning
    
    Recursively searches for objects-dictionary arrays and extracts 
    UUID fragment -> name mappings for later resolution.
    
    Args:
        obj: Raw data structure (before clean_uuids_from_data)
        mappings: Accumulator dict for mappings
        
    Returns:
        Dict mapping UUID fragments (first 8 chars) to object names
    """
    if mappings is None:
        mappings = {}
    
    if isinstance(obj, dict):
        # Found objects-dictionary - extract mappings
        if 'objects-dictionary' in obj:
            objects_dict = obj.get('objects-dictionary', [])
            if isinstance(objects_dict, list):
                for item in objects_dict:
                    if isinstance(item, dict) and 'uid' in item and 'name' in item:
                        uid = item['uid']
                        name = item['name']
                        # Extract first 8 chars of UUID as fragment (normalize to lowercase)
                        if isinstance(uid, str) and len(uid) >= 8:
                            uuid_fragment = uid[:8].lower()  # Normalize to lowercase for consistent lookups
                            mappings[uuid_fragment] = name
        
        # Recursively search all dict values
        for value in obj.values():
            extract_uuid_mappings(value, mappings)
    
    elif isinstance(obj, list):
        for item in obj:
            extract_uuid_mappings(item, mappings)
    
    return mappings

def resolve_uuid_references(obj: Any, uuid_mapping: Dict[str, str]) -> Any:
    """Resolve UUID references to actual object names using extracted mappings
    
    Converts UUID strings like '<uuid-4ca1fc95>' to actual names like 'Any'
    using the pre-extracted UUID->name mappings.
    
    Args:
        obj: Data structure with UUID references (after clean_uuids_from_data)
        uuid_mapping: Dict mapping UUID fragments to names
        
    Returns:
        Data with UUID references resolved to names
    """
    if isinstance(obj, dict):
        resolved = {}
        for key, value in obj.items():
            resolved[key] = resolve_uuid_references(value, uuid_mapping)
        return resolved
    
    elif isinstance(obj, str):
        # Check if this is a UUID reference like '<uuid-4ca1fc95>'
        uuid_ref_pattern = r'<uuid-([0-9a-f]{8})>'
        match = re.match(uuid_ref_pattern, obj, flags=re.IGNORECASE)
        if match:
            uuid_fragment = match.group(1).lower()
            # Try to find matching name in mapping
            resolved_name = uuid_mapping.get(uuid_fragment)
            if resolved_name:
                return resolved_name
            # If no mapping found, keep the UUID reference
            return obj
        return obj
    
    elif isinstance(obj, list):
        return [resolve_uuid_references(item, uuid_mapping) for item in obj]
    
    else:
        return obj

def convert_to_dict(obj: Any) -> Any:
    """Convert MCP objects to JSON-serializable dictionaries
    
    Args:
        obj: Any object (TextContent, ImageContent, dict, list, etc.)
        
    Returns:
        JSON-serializable version of the object
    """
    if obj is None:
        return None
    
    # Handle dataclasses and objects with __dict__
    if hasattr(obj, '__dict__') and not isinstance(obj, (str, int, float, bool)):
        result = {}
        for key, value in obj.__dict__.items():
            if not key.startswith('_'):  # Skip private attributes
                result[key] = convert_to_dict(value)
        return result
    
    # Handle lists
    elif isinstance(obj, list):
        return [convert_to_dict(item) for item in obj]
    
    # Handle dictionaries
    elif isinstance(obj, dict):
        return {key: convert_to_dict(value) for key, value in obj.items()}
    
    # Handle tuples
    elif isinstance(obj, tuple):
        return [convert_to_dict(item) for item in obj]
    
    # Primitive types are already serializable
    else:
        return obj

def extract_resource_identifiers(tool_name: str, content: Any) -> List[Dict[str, str]]:
    """Extract resource identifiers (names, UIDs) from discovery tool results
    
    Args:
        tool_name: Name of the discovery tool
        content: Tool result content (can be text, dict, or list)
        
    Returns:
        List of resource identifiers with their types
    """
    resources = []
    
    def extract_from_object(obj: Dict, depth: int = 0) -> None:
        """Helper to recursively extract identifiers from objects and nested structures"""
        if not isinstance(obj, dict) or depth > 5:  # Prevent infinite recursion
            return
        
        # Check if this object itself has identifiers to extract
        has_identifier = False
        if 'name' in obj:
            # Determine type based PRIMARILY on object properties (not tool name)
            resource_type = 'resource'  # Default type
            
            # Priority 1: Use object's own type field (most reliable)
            if 'type' in obj:
                obj_type = obj.get('type', '').lower()
                # Map CheckPoint API types to our internal types
                if obj_type == 'package':
                    resource_type = 'policy-package'
                elif 'gateway' in obj_type or 'cluster' in obj_type:
                    resource_type = 'gateway'
                elif 'access-layer' in obj_type or obj_type == 'access-layer':
                    resource_type = 'access-layer'
                elif 'https-layer' in obj_type or obj_type == 'https-layer':
                    resource_type = 'https-layer'
                else:
                    resource_type = obj_type
            elif 'object-type' in obj:
                resource_type = obj.get('object-type', 'object')
            # Priority 2: Infer from tool name (fallback only)
            elif 'show-gateways' in tool_name or 'gateways-and-servers' in tool_name:
                resource_type = 'gateway'
            elif 'show-access-layers' in tool_name or 'access-layers' in tool_name:
                resource_type = 'access-layer'
            elif 'show-https-layers' in tool_name or 'https-layers' in tool_name:
                resource_type = 'https-layer'
            
            resources.append({
                'type': resource_type,
                'name': obj.get('name'),
                'uid': obj.get('uid', ''),
                'ipv4-address': obj.get('ipv4-address', '')
            })
            has_identifier = True
            
            # EXTRACT POLICY PACKAGES FROM GATEWAYS
            # CheckPoint gateways contain installed policy package information
            if resource_type == 'gateway' or 'gateway' in str(obj.get('type', '')).lower():
                # Look for policy package in various fields
                policy_fields = ['policy', 'installed-policy', 'access-policy', 'threat-policy']
                for field in policy_fields:
                    if field in obj and isinstance(obj[field], dict):
                        pkg = obj[field]
                        if 'name' in pkg:
                            resources.append({
                                'type': 'policy-package',
                                'name': pkg.get('name'),
                                'uid': pkg.get('uid', ''),
                                'ipv4-address': ''
                            })
                            print(f"[MCP_DEBUG] [{_ts()}] ✓ Discovered policy package '{pkg.get('name')}' from gateway '{obj.get('name')}'")
                
                # Also check for array of policies
                if 'policies' in obj and isinstance(obj['policies'], list):
                    for pkg in obj['policies']:
                        if isinstance(pkg, dict) and 'name' in pkg:
                            resources.append({
                                'type': 'policy-package',
                                'name': pkg.get('name'),
                                'uid': pkg.get('uid', ''),
                                'ipv4-address': ''
                            })
                            print(f"[MCP_DEBUG] [{_ts()}] ✓ Discovered policy package '{pkg.get('name')}' from gateway '{obj.get('name')}'")
        
        # Recursively check nested arrays (like "packages": [...], "objects": [...], "gateways": [...])
        for key, value in obj.items():
            if isinstance(value, list):
                # Found an array - traverse it
                for item in value:
                    if isinstance(item, dict):
                        extract_from_object(item, depth + 1)
            elif isinstance(value, dict) and not has_identifier:
                # Nested dict - traverse it (but only if we haven't already extracted from this level)
                extract_from_object(value, depth + 1)
    
    try:
        import re
        import json as json_module
        
        # Handle different content types
        if isinstance(content, dict):
            # Already a dict - extract recursively
            extract_from_object(content, depth=0)
        elif isinstance(content, list):
            for item in content:
                if isinstance(item, dict):
                    # Check if it's a text content item
                    if 'text' in item:
                        text = item['text']
                        # Try to parse JSON objects from text
                        json_pattern = r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}'
                        matches = re.findall(json_pattern, text)
                        for match in matches:
                            try:
                                obj = json_module.loads(match)
                                extract_from_object(obj, depth=0)
                            except json_module.JSONDecodeError:
                                continue
                    else:
                        # Direct object in list
                        extract_from_object(item, depth=0)
                elif isinstance(item, list):
                    # Nested list
                    for subitem in item:
                        if isinstance(subitem, dict):
                            extract_from_object(subitem, depth=0)
        
        # Remove duplicates based on name+type
        seen = set()
        unique_resources = []
        for r in resources:
            key = f"{r.get('type')}:{r.get('name')}"
            if key not in seen:
                seen.add(key)
                unique_resources.append(r)
        
        print(f"[MCP_DEBUG] [{_ts()}] Extracted {len(unique_resources)} unique resources from {tool_name}")
        return unique_resources
        
    except Exception as e:
        print(f"[MCP_DEBUG] [{_ts()}] Error extracting resources: {e}")
        import traceback
        traceback.print_exc()
        return []

async def query_mcp_server_async(package_name: str, env_vars: Dict[str, str], 
                                  data_points: List[str], user_parameter_selections: Optional[Dict[str, str]] = None,
                                  discovery_mode: bool = True, user_query: str = "", 
                                  call_all_tools: bool = False, session_gateway: Optional[str] = None) -> Dict[str, Any]:
    """Query an MCP server for data (async version)
    
    Args:
        package_name: NPM package name (e.g., '@chkp/management-logs-mcp')
        env_vars: Environment variables for authentication
        data_points: List of data points to fetch (used for tool selection)
        user_parameter_selections: User-selected values for ambiguous parameters
        discovery_mode: If True, first discover available resources before querying
        user_query: Original user query string for context
        call_all_tools: If True, bypass scoring and call ALL available tools (override mode)
        session_gateway: Gateway name from session context (preferred for target_gateway)
        
    Returns:
        Dict containing tools and their results
    """
    global _discovered_resources_cache
    
    try:
        print(f"\n[MCP_DEBUG] ========== Starting MCP Query ==========")
        print(f"[MCP_DEBUG] [{_ts()}] Package: {package_name}")
        print(f"[MCP_DEBUG] [{_ts()}] Data points requested: {data_points}")
        
        # Log environment variables (mask sensitive data)
        env_keys = list(env_vars.keys()) if env_vars else []
        print(f"[MCP_DEBUG] [{_ts()}] Environment variables provided: {env_keys}")
        
        # Merge environment variables with os.environ to preserve PATH and other essentials
        # This ensures npx can be found and executed
        merged_env = {**os.environ, **(env_vars or {})}
        print(f"[MCP_DEBUG] [{_ts()}] Merged environment has {len(merged_env)} variables")
        print(f"[MCP_DEBUG] [{_ts()}] PATH in merged env: {'Yes' if 'PATH' in merged_env else 'No'}")
        
        # Create server parameters
        print(f"[MCP_DEBUG] [{_ts()}] Creating StdioServerParameters...")
        server_params = StdioServerParameters(
            command="npx",
            args=[package_name],
            env=merged_env
        )
        print(f"[MCP_DEBUG] [{_ts()}] Server params created: command=npx, args={package_name}")
        
        # Connect to server
        print(f"[MCP_DEBUG] [{_ts()}] Attempting to connect to MCP server via stdio...")
        async with stdio_client(server_params) as (read, write):
            print(f"[MCP_DEBUG] [{_ts()}] ✓ Connected to MCP server successfully")
            async with ClientSession(read, write) as session:
                # Initialize the session
                print(f"[MCP_DEBUG] [{_ts()}] Initializing MCP session...")
                init_result = await session.initialize()
                print(f"[MCP_DEBUG] [{_ts()}] ✓ Session initialized successfully")
                print(f"[MCP_DEBUG] [{_ts()}] Server info: {init_result}")
                
                # List available tools
                print(f"[MCP_DEBUG] [{_ts()}] Requesting list of available tools...")
                tools_result = await session.list_tools()
                print(f"[MCP_DEBUG] [{_ts()}] ✓ Received {len(tools_result.tools)} tools from server")
                
                results = {
                    "package": package_name,
                    "data_type": "tools",
                    "available_tools": [],
                    "tool_results": []
                }
                
                # Store available tools info
                for idx, tool in enumerate(tools_result.tools):
                    print(f"[MCP_DEBUG] [{_ts()}] Tool {idx+1}: {tool.name} - {tool.description or 'No description'}")
                    results["available_tools"].append({
                        "name": tool.name,
                        "description": tool.description or "",
                        "input_schema": tool.inputSchema
                    })
                    # Special logging for show_logs to understand its schema
                    if tool.name == 'show_logs':
                        print(f"[MCP_DEBUG] [{_ts()}] *** SHOW_LOGS SCHEMA ***")
                        print(f"[MCP_DEBUG] [{_ts()}] Full inputSchema: {json.dumps(tool.inputSchema, indent=2)}")
                
                # Phase 1: Discovery - identify and call discovery tools first
                discovered_resources = {}
                if discovery_mode:
                    print(f"[MCP_DEBUG] [{_ts()}] === Phase 1: Resource Discovery ===")
                    # Identify discovery tools (tools that list/show available resources)
                    # Normalize both hyphens and underscores for matching
                    # NOTE: show_objects is excluded here - it's called separately with proper filters below
                    discovery_keywords = ['show.gateways', 'list.packages', 'show.packages', 
                                         'list.policy.packages', 'show.access.layers', 'show.https.layers', 'init']
                    discovery_tools = [t for t in tools_result.tools 
                                      if any(kw in t.name.lower().replace('-', '.').replace('_', '.') for kw in discovery_keywords)]
                    
                    print(f"[MCP_DEBUG] [{_ts()}] Found {len(discovery_tools)} discovery tools: {[t.name for t in discovery_tools]}")
                    
                    # Call ALL discovery tools (no limit) to ensure we find policy packages, gateways, etc.
                    for tool in discovery_tools:
                        try:
                            print(f"[MCP_DEBUG] [{_ts()}] Discovery: Calling {tool.name}")
                            tool_result = await call_tool_with_retry(session, tool.name, arguments={})
                            content_serializable = convert_to_dict(tool_result.content)
                            
                            # Extract resource identifiers FIRST (needs uid/name structure intact)
                            resources = extract_resource_identifiers(tool.name, content_serializable)
                            
                            # Extract UUID mappings BEFORE cleaning
                            uuid_mappings = extract_uuid_mappings(content_serializable)
                            
                            # Clean UUIDs AFTER extraction
                            content_serializable = clean_uuids_from_data(content_serializable)
                            
                            # Resolve UUID references using extracted mappings
                            if uuid_mappings:
                                content_serializable = resolve_uuid_references(content_serializable, uuid_mappings)
                            
                            if resources:
                                discovered_resources[tool.name] = resources
                                print(f"[MCP_DEBUG] [{_ts()}] ✓ Discovered {len(resources)} resources from {tool.name}")
                                
                                # Cache access layers globally for reuse across queries (survives rate limiting)
                                if 'access' in tool.name.lower() and 'layer' in tool.name.lower():
                                    # Use unique server identifier to avoid cross-contamination
                                    server_id = env_vars.get('S1C_URL') or env_vars.get('MANAGEMENT_HOST') or 'unknown'
                                    cache_key = f"{server_id}:{package_name}:access_layers"
                                    _discovered_resources_cache[cache_key] = resources
                                    print(f"[MCP_DEBUG] [{_ts()}] 💾 Cached {len(resources)} access layers for server '{server_id}'")
                        except Exception as e:
                            print(f"[MCP_DEBUG] [{_ts()}] Discovery tool {tool.name} failed: {e}")
                    
                    # EXPLICIT POLICY PACKAGE DISCOVERY
                    # Call show_objects with type='package' to get policy packages
                    show_objects_tool = next((t for t in tools_result.tools if t.name == 'show_objects'), None)
                    if show_objects_tool:
                        try:
                            print(f"[MCP_DEBUG] [{_ts()}] Discovery: Calling show_objects with type='package' for policy packages")
                            tool_result = await call_tool_with_retry(session, 'show_objects', arguments={'type': 'package'})
                            content_serializable = convert_to_dict(tool_result.content)
                            
                            # Extract policy packages FIRST (needs uid/name structure intact)
                            resources = extract_resource_identifiers('show_packages', content_serializable)
                            
                            # Extract UUID mappings BEFORE cleaning
                            uuid_mappings = extract_uuid_mappings(content_serializable)
                            
                            # Clean UUIDs AFTER extraction
                            content_serializable = clean_uuids_from_data(content_serializable)
                            
                            # Resolve UUID references using extracted mappings
                            if uuid_mappings:
                                content_serializable = resolve_uuid_references(content_serializable, uuid_mappings)
                            
                            if resources:
                                discovered_resources['show_packages'] = resources
                                print(f"[MCP_DEBUG] [{_ts()}] ✓ Discovered {len(resources)} policy packages from show_objects(type='package')")
                        except Exception as e:
                            print(f"[MCP_DEBUG] [{_ts()}] show_objects(type='package') failed: {e}")
                    
                    results["discovered_resources"] = discovered_resources
                    print(f"[MCP_DEBUG] [{_ts()}] === Discovery Complete: {len(discovered_resources)} resource types found ===")
                
                # Phase 2: Targeted queries using discovered resources
                print(f"[MCP_DEBUG] [{_ts()}] === Phase 2: Targeted Queries ===")
                
                # Build a flat list of discovered resources for easy lookup
                all_discovered = []
                for tool_resources in discovered_resources.values():
                    all_discovered.extend(tool_resources)
                
                # Debug: Log all discovered resources to understand structure
                print(f"[MCP_DEBUG] [{_ts()}] All discovered resources ({len(all_discovered)}):")
                for idx, res in enumerate(all_discovered[:10]):  # Show first 10
                    print(f"[MCP_DEBUG] [{_ts()}]   {idx+1}. name={res.get('name')}, type={res.get('type')}, uid={res.get('uid')}")
                
                # Prepare tools with appropriate arguments
                tools_with_args = []
                parameter_options = {}  # Track parameters with multiple options
                
                # Check ALL tools to find ones we can call with discovered resources
                for tool in tools_result.tools:
                    schema = tool.inputSchema or {}
                    required = schema.get('required', [])
                    properties = schema.get('properties', {})
                    
                    args = {}
                    
                    # Check both required and optional parameters
                    # Many CheckPoint tools have "either/or" requirements that aren't enforced in schema
                    all_params = list(required) if required else []
                    optional_params = [p for p in properties.keys() if p not in all_params]
                    
                    if required:
                        print(f"[MCP_DEBUG] [{_ts()}] Tool '{tool.name}' required params: {required}")
                    
                    # Initialize gateways list for auto-construction logic (used later)
                    gateways = [r for r in all_discovered if r.get('type') == 'gateway']
                    
                    # REPUTATION SERVICE: Extract IOC parameters (URL, IP, hash) from user query FIRST
                    # This must happen before parameter checking loop
                    # Build search text from user_query and string data_points only (skip dicts)
                    string_data_points = [str(dp) for dp in data_points if isinstance(dp, str)]
                    search_text = f"{user_query} {' '.join(string_data_points)}"
                    
                    if 'url' in required:
                        # Extract URL from query - handles both with and without protocol
                        # First try URLs with protocol (http://example.com or https://example.com)
                        url_pattern_with_protocol = r'https?://[^\s<>"{}|\\^`\[\]]+'
                        url_match = re.search(url_pattern_with_protocol, search_text, re.IGNORECASE)
                        
                        if url_match:
                            args['url'] = url_match.group(0)
                            print(f"[MCP_DEBUG] [{_ts()}] Pre-extracted URL with protocol: {args['url']}")
                        else:
                            # Try domain patterns without protocol (www.example.com, checkpoint.com, example.xn--p1ai)
                            # Negative lookbehind (?<!@) ensures no @ before (avoids emails like user@domain.com)
                            # TLD validation: must contain at least one letter to exclude pure numeric TLDs and IPs
                            url_pattern_without_protocol = r'(?<!@)\b(?:www\.)?[a-zA-Z0-9](?:[-a-zA-Z0-9]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[-a-zA-Z0-9]*[a-zA-Z0-9])?)*\.([a-zA-Z0-9-]{2,63})(?:/[^\s]*)?\b'
                            domain_match = re.search(url_pattern_without_protocol, search_text, re.IGNORECASE)
                            
                            if domain_match:
                                # Validate TLD contains at least one letter (excludes .123, .456, etc.)
                                tld = domain_match.group(1)
                                if any(c.isalpha() for c in tld):
                                    # Prepend https:// for API compatibility
                                    extracted_domain = domain_match.group(0)
                                    args['url'] = f"https://{extracted_domain}"
                                    print(f"[MCP_DEBUG] [{_ts()}] Pre-extracted domain '{extracted_domain}', using URL: {args['url']}")
                    
                    if 'ip' in required:
                        # Extract IP address from query (IPv4)
                        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
                        ip_match = re.search(ip_pattern, search_text)
                        if ip_match:
                            args['ip'] = ip_match.group(0)
                            print(f"[MCP_DEBUG] [{_ts()}] Pre-extracted IP parameter: {args['ip']}")
                    
                    if 'hash' in required:
                        # Extract file hash from query (MD5: 32 hex, SHA-1: 40 hex, SHA-256: 64 hex)
                        hash_pattern = r'\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b'
                        hash_match = re.search(hash_pattern, search_text)
                        if hash_match:
                            args['hash'] = hash_match.group(0)
                            print(f"[MCP_DEBUG] [{_ts()}] Pre-extracted hash parameter: {args['hash']}")
                    
                    # Track if we've set a name-based identifier to avoid uid/name conflicts
                    has_name_identifier = False
                    skip_tool = False  # Flag to skip entire tool if required params can't be filled
                    
                    # Try to fill parameters from discovered resources (both required and useful optional ones)
                    params_to_check = all_params + [p for p in optional_params if p in ['name', 'uid', 'layer', 'package', 'policy-package', 'package-name', 'gateway', 'gateway-name']]
                    
                    for param in params_to_check:
                        print(f"[MCP_DEBUG] [{_ts()}] Checking param '{param}' for tool '{tool.name}'")
                        
                        # CONTEXT parameters: layer, package, policy-package, package-name
                        # These specify which policy package or layer to query
                        if param in ['policy-package', 'package-name', 'package']:
                            # PACKAGE PARAMETERS: Only use policy-package types (NOT access-layers)
                            # e.g., show_nat_rulebase needs 'package' = policy package name
                            packages = [r for r in all_discovered if r.get('type') in ['policy-package', 'package']]
                            print(f"[MCP_DEBUG] [{_ts()}]   Found {len(packages)} policy packages for param '{param}'")
                            
                            # If no policy packages discovered, check if this parameter is required
                            if not packages:
                                # If package is a REQUIRED parameter for this tool, skip the entire tool
                                if param in required:
                                    print(f"[MCP_DEBUG] [{_ts()}]   ⚠️ No policy packages discovered - skipping {tool.name} (required param)")
                                    print(f"[MCP_DEBUG] [{_ts()}]   Note: This MCP server version may not expose 'show-packages' tool")
                                    skip_tool = True
                                    break  # Exit param loop
                                else:
                                    # Package is optional - just skip filling this parameter
                                    print(f"[MCP_DEBUG] [{_ts()}]   No policy packages found - skipping optional '{param}' parameter for {tool.name}")
                                    continue  # Continue to next parameter
                            
                            if packages:
                                # Check if user has already selected a value
                                if user_parameter_selections and param in user_parameter_selections:
                                    args[param] = user_parameter_selections[param]
                                    print(f"[MCP_DEBUG] [{_ts()}] Using user-selected package '{args[param]}' for {tool.name}.{param}")
                                elif len(packages) > 1:
                                    # Multiple options - need user input
                                    if param not in parameter_options:
                                        parameter_options[param] = [
                                            {'value': p.get('name'), 'display': f"{p.get('name')} ({p.get('type', 'package')})"} 
                                            for p in packages
                                        ]
                                    print(f"[MCP_DEBUG] [{_ts()}] Multiple packages found ({len(packages)}) - need user selection for {tool.name}.{param}")
                                else:
                                    args[param] = packages[0].get('name')
                                    print(f"[MCP_DEBUG] [{_ts()}] Using discovered {packages[0].get('type')} '{args[param]}' for {tool.name}.{param}")
                        
                        elif param == 'layer':
                            # LAYER PARAMETER: Only use access-layer types (NOT policy-packages)
                            # e.g., show_access_rulebase needs 'layer' = access layer name
                            layers = [r for r in all_discovered if r.get('type') == 'access-layer']
                            print(f"[MCP_DEBUG] [{_ts()}]   Found {len(layers)} access layers for param '{param}'")
                            if layers:
                                # Check if user has already selected a value
                                if user_parameter_selections and param in user_parameter_selections:
                                    # Validate that the selected value exists in discovered resources
                                    selected_value = user_parameter_selections[param]
                                    layer_names = [l.get('name') for l in layers]
                                    if selected_value in layer_names:
                                        args[param] = selected_value
                                        print(f"[MCP_DEBUG] [{_ts()}] Using user-selected layer '{args[param]}' for {tool.name}.{param}")
                                    else:
                                        print(f"[MCP_DEBUG] [{_ts()}] ⚠️ User-selected '{selected_value}' not found in discovered layers {layer_names}, using first discovered layer instead")
                                        args[param] = layers[0].get('name')
                                        print(f"[MCP_DEBUG] [{_ts()}] Using discovered {layers[0].get('type')} '{args[param]}' for {tool.name}.{param}")
                                elif len(layers) > 1:
                                    # Multiple options - need user input
                                    if param not in parameter_options:
                                        parameter_options[param] = [
                                            {'value': l.get('name'), 'display': f"{l.get('name')} ({l.get('type', 'layer')})"} 
                                            for l in layers
                                        ]
                                    print(f"[MCP_DEBUG] [{_ts()}] Multiple layers found ({len(layers)}) - need user selection for {tool.name}.{param}")
                                else:
                                    args[param] = layers[0].get('name')
                                    print(f"[MCP_DEBUG] [{_ts()}] Using discovered {layers[0].get('type')} '{args[param]}' for {tool.name}.{param}")
                        
                        # RESOURCE identifier: name
                        # This identifies a specific resource (rule, object, gateway, etc.)
                        elif param == 'name':
                            # Special case: show_access_rulebase needs name/uid as the access-layer identifier
                            if tool.name == 'show_access_rulebase':
                                # Use access-layer name for this tool
                                access_layers = [r for r in all_discovered if r.get('type') == 'access-layer']
                                if access_layers:
                                    if user_parameter_selections and param in user_parameter_selections:
                                        # Validate that the selected value exists in discovered resources
                                        selected_value = user_parameter_selections[param]
                                        layer_names = [l.get('name') for l in access_layers]
                                        if selected_value in layer_names:
                                            args[param] = selected_value
                                            has_name_identifier = True
                                            print(f"[MCP_DEBUG] [{_ts()}] Using user-selected access-layer '{args[param]}' for {tool.name}.{param}")
                                        else:
                                            print(f"[MCP_DEBUG] [{_ts()}] ⚠️ User-selected '{selected_value}' not found in discovered layers {layer_names}, using first discovered layer instead")
                                            args[param] = access_layers[0].get('name')
                                            has_name_identifier = True
                                            print(f"[MCP_DEBUG] [{_ts()}] Using discovered access-layer '{args[param]}' for {tool.name}.{param}")
                                    elif len(access_layers) == 1:
                                        args[param] = access_layers[0].get('name')
                                        has_name_identifier = True
                                        print(f"[MCP_DEBUG] [{_ts()}] Using discovered access-layer '{args[param]}' for {tool.name}.{param}")
                                    else:
                                        print(f"[MCP_DEBUG] [{_ts()}] Multiple access-layers found - need user selection for {tool.name}.{param}")
                                else:
                                    # No access layers discovered - check cache from previous successful queries
                                    # Use same unique server identifier to avoid cross-contamination
                                    server_id = env_vars.get('S1C_URL') or env_vars.get('MANAGEMENT_HOST') or 'unknown'
                                    cache_key = f"{server_id}:{package_name}:access_layers"
                                    cached_layers = _discovered_resources_cache.get(cache_key, [])
                                    
                                    if cached_layers and len(cached_layers) == 1:
                                        # Use cached access layer ONLY when exactly 1 exists (preserve ambiguity handling)
                                        args[param] = cached_layers[0].get('name')
                                        has_name_identifier = True
                                        print(f"[MCP_DEBUG] [{_ts()}] 💾 Using CACHED access-layer '{args[param]}' for {tool.name}.{param} (current discovery failed)")
                                    elif cached_layers and len(cached_layers) > 1:
                                        # Multiple cached layers - require user selection (preserve ambiguity handling)
                                        skip_tool = True
                                        print(f"[MCP_DEBUG] [{_ts()}] Multiple CACHED access-layers found ({len(cached_layers)}) - need user selection for {tool.name}.{param}")
                                        print(f"[MCP_DEBUG] [{_ts()}] Skipping {tool.name} - ambiguous access layer")
                                    else:
                                        # No cache available - skip tool with clear error
                                        skip_tool = True
                                        error_msg = "Access layer discovery failed (likely API rate limiting) and no cached layers available. Cannot retrieve firewall rulebase without access layer name."
                                        print(f"[MCP_DEBUG] [{_ts()}] ⚠️ {error_msg}")
                                        print(f"[MCP_DEBUG] [{_ts()}] Skipping {tool.name} - missing required access layer")
                            # For other tools, don't auto-fill 'name' to avoid conflicts
                            elif user_parameter_selections and param in user_parameter_selections:
                                args[param] = user_parameter_selections[param]
                                has_name_identifier = True
                                print(f"[MCP_DEBUG] [{_ts()}] Using user-selected name '{args[param]}' for {tool.name}.{param}")
                            else:
                                print(f"[MCP_DEBUG] [{_ts()}] Skipping auto-fill for 'name' parameter (requires explicit specification)")
                        
                        elif param in ['uid']:
                            # CheckPoint APIs require EITHER name OR uid, not both
                            # Skip uid if we've already set a name-based identifier
                            if has_name_identifier:
                                print(f"[MCP_DEBUG] [{_ts()}] Skipping uid parameter (already have name-based identifier) for {tool.name}")
                                continue
                            
                            # Use any discovered UID only if no name was set
                            with_uid = [r for r in all_discovered if r.get('uid')]
                            if with_uid:
                                if user_parameter_selections and param in user_parameter_selections:
                                    args[param] = user_parameter_selections[param]
                                    print(f"[MCP_DEBUG] [{_ts()}] Using user-selected UID '{args[param]}' for {tool.name}.{param}")
                                # Don't auto-fill uid either to avoid conflicts
                                else:
                                    print(f"[MCP_DEBUG] [{_ts()}] Skipping auto-fill for 'uid' parameter (requires explicit specification)")
                        elif param in ['gateway', 'gateway-name']:
                            # Use pre-initialized gateways list
                            if gateways:
                                if user_parameter_selections and param in user_parameter_selections:
                                    args[param] = user_parameter_selections[param]
                                    print(f"[MCP_DEBUG] [{_ts()}] Using user-selected gateway '{args[param]}' for {tool.name}.{param}")
                                elif len(gateways) > 1:
                                    # Multiple options - need user input
                                    if param not in parameter_options:
                                        parameter_options[param] = [
                                            {'value': g.get('name'), 'display': f"{g.get('name')} ({g.get('type', 'gateway')})"} 
                                            for g in gateways
                                        ]
                                    print(f"[MCP_DEBUG] [{_ts()}] Multiple gateways found - need user selection for {tool.name}.{param}")
                                else:
                                    args[param] = gateways[0].get('name')
                                    print(f"[MCP_DEBUG] [{_ts()}] Using discovered gateway '{args[param]}' for {tool.name}.{param}")
                        
                    # ===== PARAMETER AUTO-CONSTRUCTION BASED ON MCP SERVER SOURCE CODE ANALYSIS =====
                    
                    # 1. MANAGEMENT-LOGS: show_logs/show_threat_logs with new-query parameter
                    if tool.name in ['show_logs', 'show_threat_logs'] and 'new-query' not in args:
                        time_frame = "last-7-days"
                        log_type = None
                        max_logs = 70  # With log field filtering: 10 pages × 70 logs = 700 logs (175K tokens)
                        
                        # Build search text from user_query and string data_points only (skip dicts)
                        string_data_points = [str(dp) for dp in data_points if isinstance(dp, str)]
                        search_text = f"{user_query} {' '.join(string_data_points)}".lower()
                        
                        # CRITICAL: Use user_query_lower for audit detection to prevent false positives from LLM-generated data_points
                        # (e.g., "all possible tools" → LLM adds "audit logs" to data_points → wrong log type)
                        user_query_lower = user_query.lower()
                        
                        # Time-frame detection (CheckPoint schema: last-7-days, last-hour, today, last-24-hours, 
                        # yesterday, this-week, this-month, last-30-days, all-time, custom)
                        # Use word boundaries to avoid false matches (e.g., "firewall logs" shouldn't match "all logs")
                        if re.search(r'\ball time\b', search_text) or 'all-time' in search_text:
                            time_frame = "all-time"
                        elif 'today' in search_text or 'from today' in search_text:
                            time_frame = "today"
                        elif 'yesterday' in search_text:
                            time_frame = "yesterday"
                        elif any(pattern in search_text for pattern in ['this week', 'current week']):
                            time_frame = "this-week"
                        elif any(pattern in search_text for pattern in ['this month', 'current month']):
                            time_frame = "this-month"
                        elif any(pattern in search_text for pattern in ['90 day', 'last 90 days', 'last-90-days', 'past 90 days', '90-day']):
                            time_frame = "all-time"  # CheckPoint doesn't have 90-day option, use all-time
                        elif any(pattern in search_text for pattern in ['30 day', 'last 30 days', 'last-30-days', 'past 30 days', 'last month', 'past month']):
                            time_frame = "last-30-days"
                        elif any(pattern in search_text for pattern in ['7 day', 'last 7 days', 'last-7-days', 'past 7 days', 'last week', 'past week']):
                            time_frame = "last-7-days"
                        # MCP server limitation: Only fixed time frames available are: last-hour, last-24-hours, last-7-days, last-30-days
                        # Variable frames (this-week, this-month) are unreliable (depend on current day of week/month)
                        # For 2-6 days: must use last-7-days (only fixed option in this range)
                        elif any(pattern in search_text for pattern in ['6 day', 'last 6 days', 'last-6-days', 'past 6 days', 
                                                                        '5 day', 'last 5 days', 'last-5-days', 'past 5 days',
                                                                        '4 day', 'last 4 days', 'last-4-days', 'past 4 days',
                                                                        '3 day', 'last 3 days', 'last-3-days', 'past 3 days',
                                                                        '2 day', 'last 2 days', 'last-2-days', 'past 2 days', '48 hour', 'last 48 hours']):
                            time_frame = "last-7-days"  # Only fixed time frame available (this-week is variable 1-7 days)
                        elif any(pattern in search_text for pattern in ['24 hour', 'last 24 hours', 'last-24-hours', 'past 24 hours']):
                            time_frame = "last-24-hours"
                        elif any(pattern in search_text for pattern in ['12 hour', 'last 12 hours', 'last-12-hours', 'past 12 hours']):
                            time_frame = "last-24-hours"  # MCP limitation: use 24h frame
                            args["_short_time_range"] = "12-hours"  # Internal flag for pagination control
                        elif any(pattern in search_text for pattern in ['6 hour', 'last 6 hours', 'last-6-hours', 'past 6 hours']):
                            time_frame = "last-24-hours"  # MCP limitation: use 24h frame
                            args["_short_time_range"] = "6-hours"  # Internal flag for pagination control
                        elif any(pattern in search_text for pattern in ['last hour', 'past hour', 'last 60 min']):
                            time_frame = "last-hour"
                        
                        # Log type detection (Check Point schema: 'logs' for connection/traffic, 'audit' for audit)
                        # ONLY check user_query to avoid false positives from LLM-generated data_points
                        if tool.name == 'show_logs':
                            log_type = "audit" if 'audit' in user_query_lower else "logs"
                            
                        # Generic traffic/connection logs are verbose - reduce page size
                        # Check if this is a generic traffic query (no specific blade filter)
                        if tool.name == 'show_logs' and any(kw in search_text for kw in ['traffic', 'connection']):
                            if not any(kw in search_text for kw in ['vpn', 'threat', 'https', 'ssl', 'tls', 'ips', 'malware']):
                                # Generic traffic query - reduce max_logs
                                max_logs = 50
                        
                        # Blade filter detection for security blade-specific logs
                        # CheckPoint Threat Prevention includes multiple security blades
                        # CRITICAL: CheckPoint API requires filter nested under filter.search-expression
                        blade_filter = None
                        
                        # CRITICAL STRATEGY: When user provides specific query filters (IPs, ports, domains, etc.), 
                        # they are investigating/troubleshooting and need ALL possible blade logs for comprehensive analysis.
                        # Only apply blade-specific filters when NO query filters are present (general queries).
                        
                        # Check if user provided specific query filters (IPs, ports, domains)
                        ip_pattern = r'\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
                        has_ip_filter = bool(re.search(ip_pattern, search_text))
                        has_port_filter = bool(re.search(r'\bport\s+(\d+)\b', search_text, re.IGNORECASE))
                        has_domain_filter = bool(re.search(r'\b(?:domain|url|website)[:=\s]+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b', search_text, re.IGNORECASE))
                        has_app_filter = bool(re.search(r'\bapplication[:=\s]+([a-zA-Z0-9_-]+)\b', search_text, re.IGNORECASE))
                        
                        has_query_filters = has_ip_filter or has_port_filter or has_domain_filter or has_app_filter
                        
                        # If user provided specific filters → Get ALL blade logs for comprehensive analysis
                        if has_query_filters:
                            blade_filter = (
                                'blade:"Firewall" OR blade:"Application Control" OR blade:"URL Filtering" OR '
                                'blade:"IPS" OR blade:"Threat Prevention" OR blade:"Anti-Bot" OR blade:"Anti-Virus" OR '
                                'blade:"Identity Awareness" OR blade:"HTTPS Inspection" OR blade:"Content Awareness" OR '
                                'blade:"DLP" OR blade:"Threat Emulation" OR '
                                'product_family:"Network" OR product_family:"Access" OR product_family:"Threat"'
                            )
                            filter_types = []
                            if has_ip_filter: filter_types.append("IP")
                            if has_port_filter: filter_types.append("port")
                            if has_domain_filter: filter_types.append("domain")
                            if has_app_filter: filter_types.append("application")
                            print(f"[MCP_DEBUG] [{_ts()}] 🔍 Query filters detected ({', '.join(filter_types)}) - applying comprehensive blade filter for ALL enforcement blades")
                        # VPN connection logs - DISTINGUISH client vs site-to-site
                        # VPN CLIENT connections → appear in regular traffic logs (no blade filter needed)
                        # VPN SITE-TO-SITE → appear in VPN blade logs (needs blade filter)
                        elif 'vpn client' in search_text or 'remote access vpn' in search_text:
                            # VPN client traffic appears in regular firewall logs - NO blade filter
                            # Just track connection data normally
                            print(f"[MCP_DEBUG] [{_ts()}] 🔍 VPN CLIENT query detected - using regular traffic logs (no VPN blade filter)")
                        elif any(kw in search_text for kw in ['vpn', 'vpn tunnel', 'vpn connection', 'site-to-site', 
                                                               'site to site', 's2s vpn', 'ipsec', 'ikev2', 'ikev1']):
                            # VPN site-to-site logs - filter by VPN blade
                            blade_filter = 'service:"VPN" OR service:"IKE" OR service:"ISAKMP" OR product:"VPN"'
                            # VPN traffic is typically lower volume - reduce max logs to prevent excessive pagination
                            max_logs = 50
                            print(f"[MCP_DEBUG] [{_ts()}] 🔍 VPN SITE-TO-SITE query detected - applying VPN blade filter")
                        # Threat Prevention umbrella - apply for both specific AND general threat keywords
                        # RESTORED broad keywords: suspicious, attack, malicious, threat - these indicate user wants THREAT DATA
                        elif any(kw in search_text for kw in ['suspicious', 'threat', 'attack', 'malicious', 'malware', 
                                                             'exploit', 'compromise', 'breach', 'infected', 'phishing', 
                                                             'botnet', 'ransomware', 'blocked threat', 'dropped attack',
                                                             'threat prevention', 'threat prevention logs', 
                                                             'ips attack', 'ips detection', 'intrusion prevention', 
                                                             'threat emulation', 'threat extraction', 'zero-phishing', 
                                                             'zero phishing', 'anti-bot', 'anti bot', 'bot protection',
                                                             'anti-virus', 'antivirus', 'av detection', 
                                                             'malware detection', 'malware scan']):
                            # Use OR logic to capture all threat-related blades
                            blade_filter = 'blade:"Threat Prevention" OR blade:"Anti-Bot" OR blade:"Anti-Virus" OR blade:"IPS" OR blade:"Threat Emulation"'
                            print(f"[MCP_DEBUG] [{_ts()}] 🎯 Threat query detected - applying blade filter for security events")
                        elif any(kw in search_text for kw in ['content awareness', 'content', 'dlp', 'data loss']):
                            blade_filter = 'blade:"Content Awareness"'
                        elif any(kw in search_text for kw in ['https inspection', 'ssl inspection', 'tls inspection']):
                            blade_filter = 'blade:"HTTPS Inspection"'
                        
                        # COMPREHENSIVE FILTER EXTRACTION FOR LOG QUERIES
                        # Extract multiple filter types from user query to build precise CheckPoint API filters
                        additional_filters = []
                        
                        # 1. IP ADDRESS EXTRACTION (connectivity/troubleshooting)
                        if any(kw in search_text for kw in ['connectivity', 'connection', 'issue', 'problem', 'fail', 'traffic', 'from', 'to', 'between']):
                            ip_pattern = r'\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
                            ips = re.findall(ip_pattern, search_text)
                            if ips:
                                ip_filter = None
                                
                                # DIRECTIONAL DETECTION: Check for "from X to Y" patterns
                                # Pattern 1: "from <IP1> to <IP2>" (explicit direction)
                                from_to_pattern = r'\bfrom\s+(\d+\.\d+\.\d+\.\d+)\s+to\s+(\d+\.\d+\.\d+\.\d+)\b'
                                from_to_match = re.search(from_to_pattern, search_text, re.IGNORECASE)
                                
                                # Pattern 2: "between <IP1> and <IP2>" (bidirectional)
                                between_pattern = r'\bbetween\s+(\d+\.\d+\.\d+\.\d+)\s+and\s+(\d+\.\d+\.\d+\.\d+)\b'
                                between_match = re.search(between_pattern, search_text, re.IGNORECASE)
                                
                                if from_to_match:
                                    src_ip = from_to_match.group(1)
                                    dst_ip = from_to_match.group(2)
                                    # Directional: from X to Y means src=X AND dst=Y
                                    ip_filter = f"(src:{src_ip} AND dst:{dst_ip})"
                                    print(f"[MCP_DEBUG] [{_ts()}] 🔍 Directional query detected: from {src_ip} to {dst_ip} → (src:{src_ip} AND dst:{dst_ip})")
                                elif between_match:
                                    ip1 = between_match.group(1)
                                    ip2 = between_match.group(2)
                                    # Bidirectional: between X and Y means (src=X AND dst=Y) OR (src=Y AND dst=X)
                                    ip_filter = f"((src:{ip1} AND dst:{ip2}) OR (src:{ip2} AND dst:{ip1}))"
                                    print(f"[MCP_DEBUG] [{_ts()}] 🔍 Bidirectional query detected: between {ip1} and {ip2}")
                                else:
                                    # No directional keywords - use OR logic (any IP involvement)
                                    ip_conditions = []
                                    for ip in ips:
                                        ip_conditions.append(f'src:{ip}')
                                        ip_conditions.append(f'dst:{ip}')
                                    ip_filter = ' OR '.join(ip_conditions)
                                    print(f"[MCP_DEBUG] [{_ts()}] 🔍 Extracted IPs (no direction): {ips}")
                                
                                if ip_filter:
                                    additional_filters.append(f"({ip_filter})")
                        
                        # 2. ACTION FILTER EXTRACTION (compliance/audit)
                        # Use word boundaries to avoid false matches (e.g., "not allowed" shouldn't match "allowed")
                        # Check for negations (not blocked, not allowed, etc.) and invert action
                        action_detected = None
                        
                        # Negative patterns (not blocked → accept, not allowed → drop)
                        negative_block_pattern = r'\b(?:not|never|no)\s+(?:blocked|dropped|denied|rejected)\b'
                        negative_accept_pattern = r'\b(?:not|never|no)\s+(?:accepted|allowed|permitted)\b'
                        
                        if re.search(negative_block_pattern, search_text, re.IGNORECASE):
                            action_detected = 'accept'  # "not blocked" means accepted
                            print(f"[MCP_DEBUG] [{_ts()}] 🔍 Extracted action (negation): 'not blocked' → action:accept")
                        elif re.search(negative_accept_pattern, search_text, re.IGNORECASE):
                            action_detected = 'drop'  # "not allowed" means blocked
                            print(f"[MCP_DEBUG] [{_ts()}] 🔍 Extracted action (negation): 'not allowed' → action:drop")
                        else:
                            # Positive patterns with word boundaries
                            block_pattern = r'\b(?:blocked|dropped|denied|rejected|deny|reject|drop)\b'
                            accept_pattern = r'\b(?:accepted|allowed|permitted|permit|allow|accept)\b'
                            
                            if re.search(block_pattern, search_text, re.IGNORECASE):
                                action_detected = 'drop'
                                print(f"[MCP_DEBUG] [{_ts()}] 🔍 Extracted action: blocked/dropped → action:drop")
                            elif re.search(accept_pattern, search_text, re.IGNORECASE):
                                action_detected = 'accept'
                                print(f"[MCP_DEBUG] [{_ts()}] 🔍 Extracted action: accepted/allowed → action:accept")
                        
                        if action_detected:
                            additional_filters.append(f"action:{action_detected}")
                        
                        # 3. RULE NUMBER EXTRACTION
                        rule_pattern = r'\b(?:rule|by rule)\s+(\d+)\b'
                        rule_match = re.search(rule_pattern, search_text, re.IGNORECASE)
                        if rule_match:
                            rule_num = rule_match.group(1)
                            additional_filters.append(f"rule:{rule_num}")
                            print(f"[MCP_DEBUG] [{_ts()}] 🔍 Extracted rule number: {rule_num}")
                        
                        # 4. DOMAIN/URL EXTRACTION (application troubleshooting)
                        # First try full URLs with protocol
                        url_pattern_with_protocol = r'https?://[^\s<>"{}|\\^`\[\]]+'
                        url_match = re.search(url_pattern_with_protocol, search_text, re.IGNORECASE)
                        if url_match:
                            domain = url_match.group(0).replace('http://', '').replace('https://', '').split('/')[0]
                            additional_filters.append(f"(dst:{domain} OR url:{domain})")
                            print(f"[MCP_DEBUG] [{_ts()}] 🔍 Extracted domain from URL: {domain}")
                        else:
                            # Try domain patterns without protocol (exclude IPs we already captured)
                            domain_pattern = r'\b(?:www\.)?([a-zA-Z0-9](?:[-a-zA-Z0-9]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[-a-zA-Z0-9]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,})\b'
                            domain_matches = re.findall(domain_pattern, search_text, re.IGNORECASE)
                            # Filter out domains that are actually IPs or common words
                            valid_domains = [d for d in domain_matches if '.' in d and not re.match(r'^\d+\.\d+\.\d+\.\d+$', d)]
                            if valid_domains:
                                domain = valid_domains[0]  # Use first domain found
                                additional_filters.append(f"(dst:{domain} OR url:{domain})")
                                print(f"[MCP_DEBUG] [{_ts()}] 🔍 Extracted domain: {domain}")
                        
                        # 5. USERNAME EXTRACTION (user activity tracking)
                        user_pattern = r'\b(?:user|username|account)\s+([a-zA-Z0-9._-]+)\b'
                        user_match = re.search(user_pattern, search_text, re.IGNORECASE)
                        if user_match:
                            username = user_match.group(1)
                            additional_filters.append(f"(user:{username} OR orig_user:{username} OR identity_user:{username})")
                            print(f"[MCP_DEBUG] [{_ts()}] 🔍 Extracted username: {username}")
                        
                        # 6. SERVICE/PORT EXTRACTION
                        # Named services
                        service_keywords = {
                            'ssh': 'ssh', 'http': 'http', 'https': 'https', 'ftp': 'ftp', 'smtp': 'smtp', 
                            'dns': 'dns', 'telnet': 'telnet', 'rdp': 'ms-wbt-server', 'smb': 'microsoft-ds'
                        }
                        for keyword, service in service_keywords.items():
                            if f' {keyword} ' in f' {search_text} ' or f' {keyword},' in search_text or search_text.endswith(keyword):
                                additional_filters.append(f"service:{service}")
                                print(f"[MCP_DEBUG] [{_ts()}] 🔍 Extracted service: {keyword} → service:{service}")
                                break
                        
                        # Port numbers
                        port_pattern = r'\b(?:port|on port)\s+(\d+)\b'
                        port_match = re.search(port_pattern, search_text, re.IGNORECASE)
                        if port_match:
                            port = port_match.group(1)
                            additional_filters.append(f"service:{port}")
                            print(f"[MCP_DEBUG] [{_ts()}] 🔍 Extracted port: {port}")
                        
                        # Combine all additional filters
                        combined_additional_filter = None
                        if additional_filters:
                            combined_additional_filter = ' AND '.join(additional_filters)
                            print(f"[MCP_DEBUG] [{_ts()}] 🔍 Combined additional filters: {combined_additional_filter}")
                        
                        # Create new_query dict AFTER max_logs adjustment from blade filters
                        new_query = {
                            "time-frame": time_frame,
                            "max-logs-per-request": max_logs
                        }
                        if log_type:
                            new_query["type"] = log_type
                        
                        # Combine blade_filter and additional_filters
                        final_filter = None
                        if blade_filter and combined_additional_filter:
                            # Both filters: combine with AND logic (blade AND (additional conditions))
                            final_filter = f"({blade_filter}) AND ({combined_additional_filter})"
                            print(f"[MCP_DEBUG] [{_ts()}] ✅ Combined blade + additional filters: {final_filter}")
                        elif blade_filter:
                            final_filter = blade_filter
                            print(f"[MCP_DEBUG] [{_ts()}] ✅ Using blade filter: {blade_filter}")
                        elif combined_additional_filter:
                            final_filter = combined_additional_filter
                            print(f"[MCP_DEBUG] [{_ts()}] ✅ Using additional filters: {combined_additional_filter}")
                        
                        if final_filter:
                            # MCP server expects flat string - it handles CheckPoint API transformation internally
                            new_query["filter"] = final_filter
                            
                            # Mark VPN queries for special handling (verbose logs)
                            if blade_filter and ('VPN' in blade_filter or 'IKE' in blade_filter):
                                args["_vpn_query"] = True  # Internal flag for pagination control
                        
                        args["new-query"] = new_query
                        print(f"[MCP_DEBUG] [{_ts()}] Auto-constructed new-query for {tool.name}: {new_query}")
                    
                    # 2. GATEWAY CLI: All tools require target_gateway parameter
                    if 'target_gateway' in required and 'target_gateway' not in args:
                        # Helper function to check if string is an IP address
                        def is_ip_address(s):
                            if not s:
                                return False
                            parts = s.split('.')
                            if len(parts) != 4:
                                return False
                            try:
                                return all(0 <= int(part) <= 255 for part in parts)
                            except ValueError:
                                return False
                        
                        # Priority 1: Use session gateway (most reliable, from QueryOrchestrator)
                        if session_gateway and not is_ip_address(session_gateway):
                            args['target_gateway'] = session_gateway
                            print(f"[MCP_DEBUG] [{_ts()}] ✓ Auto-filled target_gateway from session context: {args['target_gateway']}")
                        # Priority 2: Try discovered gateways (but skip if it's an IP address)
                        elif gateways and len(gateways) > 0:
                            gateway_name = gateways[0].get('name')
                            if gateway_name and not is_ip_address(gateway_name):
                                args['target_gateway'] = gateway_name
                                print(f"[MCP_DEBUG] [{_ts()}] Auto-filled target_gateway from discovery: {args['target_gateway']}")
                            else:
                                print(f"[MCP_DEBUG] [{_ts()}] ⚠️ Discovered gateway has IP in name field ({gateway_name}), skipping...")
                        
                        # Priority 3: Extract from user query
                        if 'target_gateway' not in args and user_query:
                            # Pattern 1: "on <gateway>" or "for <gateway>" or "in <gateway>"
                            match = re.search(r'\b(?:on|for|in|from|at)\s+([a-zA-Z0-9][a-zA-Z0-9._-]+)', user_query, re.IGNORECASE)
                            if match:
                                potential_gateway = match.group(1)
                                # Exclude common words AND IP addresses (IPs should not be used as gateway names)
                                if (potential_gateway.lower() not in ['the', 'this', 'that', 'my', 'our', 'all', 'each', 'every', 'gateway', 'firewall'] 
                                    and not is_ip_address(potential_gateway)):
                                    args['target_gateway'] = potential_gateway
                                    print(f"[MCP_DEBUG] [{_ts()}] Auto-filled target_gateway from user query: {args['target_gateway']}")
                                elif is_ip_address(potential_gateway):
                                    print(f"[MCP_DEBUG] [{_ts()}] ⚠️ Skipped IP address from query pattern: {potential_gateway} (not a valid gateway name)")
                            
                            # Pattern 2: Direct gateway name mention (cp-gw, gw-01, firewall-dmz, etc.)
                            if 'target_gateway' not in args:
                                match = re.search(r'\b([a-zA-Z0-9]+[-_][a-zA-Z0-9][a-zA-Z0-9._-]*)', user_query)
                                if match:
                                    potential_gateway = match.group(1)
                                    # Validate it's not an IP address
                                    if not is_ip_address(potential_gateway):
                                        args['target_gateway'] = potential_gateway
                                        print(f"[MCP_DEBUG] [{_ts()}] Auto-filled target_gateway from identifier pattern: {args['target_gateway']}")
                                    else:
                                        print(f"[MCP_DEBUG] [{_ts()}] ⚠️ Skipped IP address from identifier pattern: {potential_gateway}")
                        
                        # Priority 4: Fallback to GATEWAY_HOST environment variable
                        # In discovery mode, try to resolve gateway IP→name from directory before skipping
                        if 'target_gateway' not in args:
                            if 'GATEWAY_HOST' in env_vars:
                                gateway_host_value = env_vars['GATEWAY_HOST']
                                # Check if it's an IP address
                                if is_ip_address(gateway_host_value):
                                    # Try to resolve IP to gateway name from directory
                                    gateway_dir = _get_gateway_directory()
                                    gateway_name = gateway_dir.get_gateway_name(gateway_host_value)
                                    
                                    if gateway_name:
                                        # Successfully resolved IP→name, use gateway name
                                        args['target_gateway'] = gateway_name
                                        print(f"[MCP_DEBUG] [{_ts()}] Auto-filled target_gateway from IP lookup: {gateway_host_value} → {gateway_name}")
                                    elif not discovery_mode:
                                        # Non-discovery mode: use IP directly (some APIs accept IP)
                                        args['target_gateway'] = gateway_host_value
                                        print(f"[MCP_DEBUG] [{_ts()}] Auto-filled target_gateway from GATEWAY_HOST env (IP): {args['target_gateway']}")
                                    else:
                                        # Discovery mode + IP only + no name resolution = skip this tool
                                        print(f"[MCP_DEBUG] [{_ts()}] ⚠️ Discovery mode: Skipping tool '{tool.name}' (IP {gateway_host_value} not resolved to gateway name)")
                                        continue  # Skip this tool
                                else:
                                    # Not an IP - it's a hostname/gateway name, safe to use
                                    args['target_gateway'] = gateway_host_value
                                    print(f"[MCP_DEBUG] [{_ts()}] Auto-filled target_gateway from GATEWAY_HOST env: {args['target_gateway']}")
                    
                    # 3. GAIA: Requires gateway_ip parameter for authentication
                    if 'gateway_ip' in required and 'gateway_ip' not in args:
                        # Try to find gateway IP from previous discovery
                        if gateways and len(gateways) > 0:
                            # Prefer ipv4-address field if available
                            gateway_ip = gateways[0].get('ipv4-address') or gateways[0].get('name')
                            if gateway_ip:
                                args['gateway_ip'] = gateway_ip
                                print(f"[MCP_DEBUG] [{_ts()}] Auto-filled gateway_ip: {args['gateway_ip']}")
                    
                    # 4. HARMONY SASE: Network/Gateway/Region/Application ID parameters
                    if 'network_id' in required and 'network_id' not in args:
                        # Look for network ID in data_points or previous context
                        for dp in data_points:
                            if 'network' in dp.lower() or 'net' in dp.lower():
                                args['network_id'] = dp
                                print(f"[MCP_DEBUG] [{_ts()}] Auto-filled network_id: {args['network_id']}")
                                break
                    
                    # 5. SPARK MANAGEMENT: gatewayName parameter
                    if 'gatewayName' in required and 'gatewayName' not in args:
                        if gateways and len(gateways) > 0:
                            args['gatewayName'] = gateways[0].get('name')
                            print(f"[MCP_DEBUG] [{_ts()}] Auto-filled gatewayName: {args['gatewayName']}")
                    
                    # 6. THREAT EMULATION: file_path parameter
                    if 'file_path' in required and 'file_path' not in args:
                        # Look for file path in data_points
                        for dp in data_points:
                            if '/' in dp or '\\' in dp or '.' in dp:
                                args['file_path'] = dp
                                print(f"[MCP_DEBUG] [{_ts()}] Auto-filled file_path: {args['file_path']}")
                                break
                    
                    # 7. CHECKPOINT RULEBASE TOOLS: Critical API parameters for complete data
                    # show-nat-rulebase, show-access-rulebase, show-https-rulebase, and similar tools MUST have these
                    # Without them, CheckPoint API returns minimal/incomplete data (Unnamed Rule, Any, etc.)
                    # NOTE: These are valid CheckPoint API parameters even if not in MCP schema
                    if 'rulebase' in tool.name.lower() or tool.name.lower() in ['show-nat-rule', 'show-access-rule', 'show-https-rule']:
                        # HTTPS rulebase requires layer name or UID - use discovered HTTPS layers
                        if 'https' in tool.name.lower() and 'name' not in args and 'uid' not in args:
                            # Use discovered HTTPS layers instead of hardcoding
                            https_layers = [r for r in all_discovered if r.get('type') == 'https-layer']
                            if https_layers:
                                # Check if user has already selected a layer
                                if user_parameter_selections and 'name' in user_parameter_selections:
                                    args['name'] = user_parameter_selections['name']
                                    print(f"[MCP_DEBUG] [{_ts()}] Using user-selected HTTPS layer '{args['name']}' for {tool.name}")
                                elif len(https_layers) == 1:
                                    # Single layer - use it automatically
                                    args['name'] = https_layers[0].get('name')
                                    print(f"[MCP_DEBUG] [{_ts()}] Using discovered HTTPS layer '{args['name']}' for {tool.name}")
                                elif len(https_layers) > 1:
                                    # Multiple HTTPS layers - need user selection
                                    if 'name' not in parameter_options:
                                        parameter_options['name'] = [
                                            {'value': l.get('name'), 'display': f"{l.get('name')} (HTTPS Inspection Layer)"} 
                                            for l in https_layers
                                        ]
                                    print(f"[MCP_DEBUG] [{_ts()}] Multiple HTTPS layers found ({len(https_layers)}) - need user selection for {tool.name}.name")
                                    skip_tool = True  # Skip this tool until user selects
                            else:
                                # Fallback: try "Standard Layer" as default if no layers discovered yet
                                args['name'] = 'Standard Layer'
                                print(f"[MCP_DEBUG] [{_ts()}] No HTTPS layers discovered, trying default 'Standard Layer' for {tool.name}")
                        
                        # Set details-level to "full" for complete rule information (names, objects, etc.)
                        if 'details-level' not in args:
                            args['details-level'] = 'full'
                            print(f"[MCP_DEBUG] [{_ts()}] Set details-level=full for {tool.name} (required for complete data)")
                        
                        # Set use-object-dictionary for object names instead of UIDs
                        if 'use-object-dictionary' not in args:
                            args['use-object-dictionary'] = True
                            print(f"[MCP_DEBUG] [{_ts()}] Set use-object-dictionary=true for {tool.name} (gets object names)")
                        
                        # CRITICAL: Use show_raw=true to get raw JSON and bypass MCP server's table formatting
                        # The MCP server's formatted table may not properly resolve object names from dictionary
                        # EXCEPTION: threat-prevention MCP server rejects 'show_raw' parameter (generates invalid 'body' param)
                        if 'show_raw' not in args:
                            # Check if this is threat-prevention MCP server
                            is_threat_prevention = 'threat-prevention' in package_name.lower()
                            if not is_threat_prevention:
                                args['show_raw'] = True
                                print(f"[MCP_DEBUG] [{_ts()}] Set show_raw=true for {tool.name} (bypass server formatting, get raw JSON)")
                            else:
                                print(f"[MCP_DEBUG] [{_ts()}] Skipping show_raw for {tool.name} (threat-prevention MCP server incompatibility)")
                    
                    # FIX: Special handling for show_access_rule, show_access_section, show_nat_section
                    # These tools have specific parameter requirements that differ from rulebases
                    if tool.name == 'show_access_rule':
                        # show_access_rule requires: uid OR rule-number OR name
                        # If we have 'layer' but no identifier, skip this tool (can't show all rules)
                        if 'uid' not in args and 'rule-number' not in args and 'name' not in args:
                            print(f"[MCP_DEBUG] [{_ts()}] ⚠️ show_access_rule needs uid/rule-number/name, skipping...")
                            skip_tool = True
                    
                    elif tool.name == 'show_access_section':
                        # show_access_section requires: name OR uid (of the section)
                        # If we have 'layer' but no section identifier, skip this tool
                        if 'name' not in args and 'uid' not in args:
                            print(f"[MCP_DEBUG] [{_ts()}] ⚠️ show_access_section needs name/uid of section, skipping...")
                            skip_tool = True
                    
                    elif tool.name == 'show_nat_section':
                        # show_nat_section does NOT accept 'layer' parameter - remove it if present
                        if 'layer' in args:
                            del args['layer']
                            print(f"[MCP_DEBUG] [{_ts()}] Removed invalid 'layer' parameter from show_nat_section")
                        # show_nat_section needs: name OR uid (of the section) plus package
                        if ('name' not in args and 'uid' not in args) or 'package' not in args:
                            print(f"[MCP_DEBUG] [{_ts()}] ⚠️ show_nat_section needs name/uid + package, skipping...")
                            skip_tool = True
                    
                    # Add tool ONLY if ALL required parameters are filled
                    required_filled = all(param in args for param in required) if required else True
                    has_useful_params = len(args) > 0
                    
                    # Skip tools flagged during parameter checking
                    if skip_tool:
                        print(f"[MCP_DEBUG] [{_ts()}] ✗ Skipping '{tool.name}' - flagged during parameter check")
                    # Skip tools where required params can't be filled (prevents API errors)
                    elif required and not required_filled:
                        print(f"[MCP_DEBUG] [{_ts()}] ✗ Skipping '{tool.name}' - cannot fill required params: {required}")
                    # For all other tools with no required params: call with whatever args we have (even if empty)
                    elif not required:
                        tools_with_args.append((tool, args))
                        print(f"[MCP_DEBUG] [{_ts()}] ✓ Can call '{tool.name}' with args: {args}")
                    # Tool with all required params filled
                    else:
                        tools_with_args.append((tool, args))
                        print(f"[MCP_DEBUG] [{_ts()}] ✓ Can call '{tool.name}' with args: {args}")
                
                # If we found parameters with multiple options and user hasn't selected, ask user
                if parameter_options and not user_parameter_selections:
                    print(f"[MCP_DEBUG] [{_ts()}] Found {len(parameter_options)} parameters with multiple options - returning for user selection")
                    return {
                        "needs_user_input": True,
                        "parameter_options": parameter_options,
                        "tool_results": [],
                        "resources": []
                    }
                
                # Prioritize tools based on relevance to data_points (user's query)
                # Score each tool: higher score = more relevant
                def score_tool_relevance(tool, data_points, tool_args=None):
                    """Score tool based on how relevant it is to the requested data points and parameter readiness"""
                    score = 0
                    tool_name_lower = tool.name.lower()
                    tool_desc_lower = (tool.description or "").lower()
                    
                    # Combine data points into search text (filter to strings only)
                    string_data_points = [str(dp) for dp in data_points if isinstance(dp, str)]
                    search_keywords = ' '.join(string_data_points).lower()
                    
                    # QUERY TYPE DETECTION - Distinguish threat/log queries from policy/config queries
                    threat_keywords = ['suspicious', 'threat', 'attack', 'malware', 'intrusion', 'breach', 
                                      'compromise', 'exploit', 'anomaly', 'incident', 'alert', 'detection',
                                      'blocked', 'dropped', 'deny', 'reject', 'ips', 'ids', 'antivirus',
                                      'anti-bot', 'anti-virus', 'infected', 'virus', 'bot', 'scan']
                    log_keywords = ['log', 'activity', 'traffic', 'connection', 'session', 'event', 'audit']
                    policy_keywords = ['policy', 'rule', 'rulebase', 'access', 'nat', 'configuration', 
                                     'config', 'review', 'analyze', 'show', 'list', 'display']
                    
                    is_threat_query = any(kw in search_keywords for kw in threat_keywords)
                    is_log_query = any(kw in search_keywords for kw in log_keywords)
                    is_policy_query = any(kw in search_keywords for kw in policy_keywords)
                    
                    # Determine primary query type with mixed-intent support
                    query_type = 'other'
                    if is_policy_query and (is_threat_query or is_log_query):
                        query_type = 'mixed'  # Mixed threat/policy query (e.g., "suspicious policy changes")
                    elif is_threat_query or is_log_query:
                        query_type = 'threat_log'  # Pure security investigation query
                    elif is_policy_query:
                        query_type = 'policy'  # Pure policy/config query
                    
                    # CRITICAL RULE: For PURE threat/log queries (NOT mixed), EXCLUDE policy/config tools
                    # Mixed queries need both logs AND policy tools
                    policy_tools = ['access_rulebase', 'nat_rulebase', 'access_rule', 'nat_rule', 
                                   'access_section', 'nat_section', 'access_layer', 'find_zero_hits']
                    if query_type == 'threat_log':  # Only exclude for PURE threat queries
                        if any(pt in tool_name_lower for pt in policy_tools):
                            score -= 1000  # MASSIVE penalty - exclude these from pure threat queries
                            print(f"[MCP_DEBUG] [{_ts()}] 🚫 Excluding '{tool.name}' from pure threat/log query (policy tool)")
                    
                    # Exact keyword matches in tool name (highest priority)
                    # CRITICAL: Include HTTPS/SSL/TLS keywords for inspection tools
                    for keyword in ['nat', 'access', 'threat', 'log', 'vpn', 'gateway', 'policy', 'rule', 
                                   'https', 'ssl', 'tls', 'certificate', 'inspection', 'decryption']:
                        if keyword in search_keywords and keyword in tool_name_lower:
                            score += 100  # Very high score for exact keyword match
                    
                    # BONUS: Tools with filled required parameters are more valuable
                    # This ensures tools with auto-filled params rank higher than empty discovery tools
                    if tool_args and len(tool_args) > 0:
                        score += 25  # Significant boost for tools with parameters ready
                    
                    # SPECIAL RULE: "rulebase" or "rule" WITHOUT "nat" → prefer ACCESS over NAT
                    # This ensures "show my rulebase" defaults to access control rules, not NAT
                    if ('rulebase' in search_keywords or 'rule' in search_keywords) and 'nat' not in search_keywords:
                        if 'access' in tool_name_lower and 'rulebase' in tool_name_lower:
                            score += 150  # HIGHEST priority for access_rulebase when NAT not mentioned
                        elif 'nat' in tool_name_lower and 'rulebase' in tool_name_lower:
                            score -= 50  # Deprioritize NAT tools when user didn't ask for NAT
                    
                    # Partial matches in tool name
                    if 'nat' in search_keywords and 'nat' in tool_name_lower:
                        score += 50
                    if 'rule' in search_keywords and 'rule' in tool_name_lower:
                        score += 30
                    if 'policy' in search_keywords and ('policy' in tool_name_lower or 'rulebase' in tool_name_lower):
                        score += 30
                    if 'log' in search_keywords and 'log' in tool_name_lower:
                        score += 50
                    if 'threat' in search_keywords and 'threat' in tool_name_lower:
                        score += 50
                    
                    # Discovery/general tools get lower priority (but not zero)
                    if tool_name_lower in ['init', 'show_hosts', 'show_objects', 'show_gateways_and_servers']:
                        score += 5  # Keep them available but deprioritize
                    
                    # Tools with 'show' prefix that match data types
                    if tool_name_lower.startswith('show_'):
                        score += 10  # Base score for info-gathering tools
                    
                    return score
                
                # Sort tools by relevance score (highest first)
                # Pass tool_args to scoring function so tools with parameters get bonus points
                tools_with_scores = [(tool, args, score_tool_relevance(tool, data_points, args)) for tool, args in tools_with_args]
                tools_with_scores.sort(key=lambda x: x[2], reverse=True)
                
                # Debug: Show top prioritized tools
                print(f"[MCP_DEBUG] [{_ts()}] Tool prioritization (top 10):")
                for i, (tool, args, score) in enumerate(tools_with_scores[:10]):
                    print(f"[MCP_DEBUG] [{_ts()}]   {i+1}. {tool.name} (score: {score}) with args: {args}")
                
                # INTELLIGENT DYNAMIC TOOL SELECTION
                # Check if caller requested ALL tools (override mode)
                if call_all_tools:
                    # OVERRIDE MODE: Call ALL available tools with arguments
                    selected_tools = [(t, a, s) for t, a, s in tools_with_scores]  # Keep all tools with scores
                    print(f"[MCP_DEBUG] [{_ts()}] ⚠️ OVERRIDE MODE: call_all_tools=True - Calling ALL {len(selected_tools)} available tools")
                    print(f"[MCP_DEBUG] [{_ts()}] This provides comprehensive coverage but may impact performance")
                else:
                    # STANDARD MODE: Score-based intelligent selection with rate limit protection
                    RELEVANCE_THRESHOLD = 15  # Only call tools with score > 15 (filters out noise)
                    AGGRESSIVE_THRESHOLD = 100  # Very high relevance (exact keyword matches)
                    MAX_TOOLS = 8  # Maximum tools to call in parallel (prevents API rate limiting)
                    
                    selected_tools = []
                    
                    # Phase 1: Intelligent tool selection with cap to prevent rate limiting
                    # Priority: aggressive-match tools first, then high-relevance, then medium
                    aggressive_tools = [(t, a, s) for t, a, s in tools_with_scores if s > AGGRESSIVE_THRESHOLD]
                    high_tools = [(t, a, s) for t, a, s in tools_with_scores if 50 < s <= AGGRESSIVE_THRESHOLD]
                    medium_tools = [(t, a, s) for t, a, s in tools_with_scores if RELEVANCE_THRESHOLD < s <= 50]
                    
                    # Add tools by priority, STRICTLY enforcing MAX_TOOLS cap at each step
                    selected_tools.extend(aggressive_tools[:MAX_TOOLS])  # Take up to MAX_TOOLS aggressive tools
                    remaining = MAX_TOOLS - len(selected_tools)
                    
                    if remaining > 0:
                        selected_tools.extend(high_tools[:remaining])  # Fill remaining slots with high-relevance
                        remaining = MAX_TOOLS - len(selected_tools)
                    
                    if remaining > 0:
                        selected_tools.extend(medium_tools[:remaining])  # Fill remaining slots with medium-relevance
                    
                    # Count by score tier for visibility
                    aggressive_count = len(aggressive_tools)
                    high_count = len(high_tools)
                    medium_count = len(medium_tools)
                    
                    print(f"[MCP_DEBUG] [{_ts()}] Tool selection (max {MAX_TOOLS} to prevent rate limiting):")
                    print(f"[MCP_DEBUG] [{_ts()}]   - {aggressive_count} aggressive-match tools (score > {AGGRESSIVE_THRESHOLD})")
                    print(f"[MCP_DEBUG] [{_ts()}]   - {high_count} high-relevance tools (score 51-{AGGRESSIVE_THRESHOLD})")
                    print(f"[MCP_DEBUG] [{_ts()}]   - {medium_count} medium-relevance tools (score {RELEVANCE_THRESHOLD+1}-50)")
                    print(f"[MCP_DEBUG] [{_ts()}] Selected {len(selected_tools)} tools (capped at {MAX_TOOLS})")
                    
                    # Phase 2: Filter out tools with empty/useless args that would return irrelevant data
                    # CRITICAL: Tools like show_objects with {} args return 12,000+ random objects!
                    filtered_tools = []
                    excluded_count = 0
                    for t, a, s in selected_tools:
                        # Check if tool has empty or minimal args
                        meaningful_args = {k: v for k, v in a.items() if not k.startswith('_') and v}
                        
                        # Exclude tools with no meaningful filtering parameters
                        # These return massive amounts of irrelevant data OR require specific parameters
                        # Singular tools REQUIRE name/uid - exclude them if not provided
                        singular_tools_requiring_params = [
                            'show_vpn_community_star', 'show_vpn_community_meshed', 'show_vpn_community_remote_access',
                            'show_simple_gateway', 'show_lsm_gateway', 'show_simple_cluster', 'show_lsm_cluster',
                            'show_cluster_member', 'show_access_layer', 'show_access_rule', 'show_access_section',
                            'show_nat_section'
                        ]
                        if not meaningful_args and (t.name in ['show_objects', 'show_hosts', 'show_networks', 
                                                              'show_services', 'show_service_groups'] or
                                                   t.name in singular_tools_requiring_params):
                            print(f"[MCP_DEBUG] [{_ts()}] ⚠️ Excluding '{t.name}' - no filtering params (would return irrelevant data or API error)")
                            excluded_count += 1
                            continue
                        
                        filtered_tools.append((t, a, s))
                    
                    selected_tools = filtered_tools
                    if excluded_count > 0:
                        print(f"[MCP_DEBUG] [{_ts()}] Excluded {excluded_count} tools with empty args to prevent irrelevant data")
                
                # Extract tool and args (drop scores)
                tools_to_call = [(tool, args) for tool, args, score in selected_tools]
                
                # Log final selection with performance warning
                print(f"[MCP_DEBUG] [{_ts()}] Dynamic tool selection: calling {len(tools_to_call)} tools (out of {len(tools_with_args)} callable)")
                if len(tools_to_call) > 15:
                    print(f"[MCP_DEBUG] [{_ts()}] ⚠️⚠️ HIGH TOOL COUNT: Calling {len(tools_to_call)} tools - complex/broad query")
                elif len(tools_to_call) > 10:
                    print(f"[MCP_DEBUG] [{_ts()}] ⚠️ Calling {len(tools_to_call)} tools - comprehensive analysis")
                print(f"[MCP_DEBUG] [{_ts()}] Selected tools: {[t.name for t, a in tools_to_call]}")
                
                for idx, (tool, args) in enumerate(tools_to_call):
                    try:
                        # Add delay between parallel tool calls to reduce API rate limiting
                        # Skip delay for first tool
                        if idx > 0:
                            # Increase delay for high tool counts to prevent rate limiting
                            if len(tools_to_call) > 20:
                                delay = 0.8  # 800ms for very high tool counts
                            elif len(tools_to_call) > 10:
                                delay = 0.5  # 500ms for high tool counts
                            else:
                                delay = 0.3  # 300ms for normal tool counts
                            print(f"[MCP_DEBUG] [{_ts()}] ⏸️  Rate limiting: waiting {delay}s before next tool...")
                            await asyncio.sleep(delay)
                        
                        # Remove internal flags before API call
                        internal_flags = {k: v for k, v in args.items() if k.startswith('_')}
                        api_args = {k: v for k, v in args.items() if not k.startswith('_')}
                        
                        print(f"[MCP_DEBUG] [{_ts()}] Calling tool {idx+1}/{len(tools_to_call)}: {tool.name} with args: {api_args}")
                        
                        # UNIVERSAL PAGINATION SUPPORT
                        # CheckPoint API returns max 100 items per request with query-id for pagination
                        # Works for show_logs, show_threat_logs, show_objects, show_gateways_and_servers, etc.
                        
                        # First request (use api_args without internal flags)
                        tool_result = await call_tool_with_retry(session, tool.name, arguments=api_args)
                        content_dict = convert_to_dict(tool_result.content)
                        
                        # Try to detect pagination support (query-id OR offset-based)
                        query_id = None
                        offset_total = None  # For offset-based pagination
                        offset_from = None
                        offset_to = None
                        data_field = None  # The field containing the data array (logs, objects, etc.)
                        first_page_data = []
                        all_data = []
                        page_count = 1
                        original_wrapper = None  # Store original response structure for pagination
                        
                        # INTELLIGENT PAGINATION: Adjust max pages based on time range and query type
                        # Broad time ranges (7 days) need fewer pages to prevent token overflow
                        # Specific queries can fetch more pages for comprehensive results
                        time_range_days = 1  # Default
                        if 'new-query' in args and isinstance(args['new-query'], dict):
                            time_frame_str = args['new-query'].get('time-frame', 'last-1-days')
                            if '30-days' in time_frame_str or '30-day' in time_frame_str:
                                time_range_days = 30
                            elif '7-days' in time_frame_str or '7-day' in time_frame_str or 'week' in time_frame_str:
                                time_range_days = 7
                            elif '24-hours' in time_frame_str or '1-day' in time_frame_str or time_frame_str == 'today':
                                time_range_days = 1
                        
                        # Calculate MAX_PAGES based on time range to prevent token overflow
                        # No log-level filtering (user wants all data including Accept logs for traffic analysis)
                        # Token estimates with deduplication (~50% reduction) and field filtering (~35% reduction):
                        # 30 days: 4 pages (~280 logs → ~140 unique → ~50k tokens after field filtering)
                        # 7 days / this-week: 6 pages (~420 logs → ~210 unique → ~70k tokens after field filtering)
                        # 1 day / today: 10 pages (~700 logs → ~350 unique → ~120k tokens)
                        # 6-12 hours: 4 pages (~280 logs → ~140 unique → ~50k tokens) - reduced for sub-24h queries
                        
                        # Check for short time range flag (6-12 hours mapped to 24h frame)
                        short_time_range = internal_flags.get('_short_time_range')
                        
                        if short_time_range:
                            MAX_PAGES = 4  # Sub-24-hour queries: reduced pagination (6h/12h queries)
                            print(f"[MCP_DEBUG] [{_ts()}] 📊 Detected short time range ({short_time_range}) - reducing pagination to prevent token overflow")
                        elif time_range_days >= 30:
                            MAX_PAGES = 4  # Last 30 days: limited pagination
                        elif time_range_days >= 7:
                            MAX_PAGES = 6  # Last 7 days or this-week: 6 pages
                        else:
                            MAX_PAGES = 10  # Last 24 hours or today: 10 pages
                        
                        logs_per_page = args.get('new-query', {}).get('max-logs-per-request', 70) if isinstance(args.get('new-query'), dict) else 70
                        print(f"[MCP_DEBUG] [{_ts()}] 📊 Intelligent pagination: {time_range_days}-day query limited to {MAX_PAGES} pages (max ~{MAX_PAGES * logs_per_page} logs)")
                        
                        # Parse first response and detect structure
                        print(f"[MCP_DEBUG] [{_ts()}] 📊 Analyzing response structure for pagination detection...")
                        print(f"[MCP_DEBUG] [{_ts()}] 📊 content_dict type: {type(content_dict)}, is list: {isinstance(content_dict, list)}")
                        
                        if isinstance(content_dict, list):
                            print(f"[MCP_DEBUG] [{_ts()}] 📊 content_dict has {len(content_dict)} items")
                            for idx, item in enumerate(content_dict):
                                print(f"[MCP_DEBUG] [{_ts()}] 📊 Item {idx}: type={type(item)}, has 'text': {'text' in item if isinstance(item, dict) else 'N/A'}")
                                if isinstance(item, dict) and 'text' in item:
                                    try:
                                        text_content = item['text']
                                        print(f"[MCP_DEBUG] [{_ts()}] 📊 Parsing JSON from text (length: {len(text_content)} chars)...")
                                        data = json.loads(text_content)
                                        
                                        # CRITICAL FIX: Replace the JSON string with parsed object
                                        # This ensures LLM receives structured data, not double-encoded JSON strings
                                        item['text'] = data
                                        
                                        # Handle both dict and list responses
                                        if isinstance(data, dict):
                                            print(f"[MCP_DEBUG] [{_ts()}] 📊 Parsed JSON keys: {list(data.keys())}")
                                            
                                            query_id = data.get('query-id')
                                            
                                            # Detect offset-based pagination (total/from/to fields)
                                            offset_total = data.get('total')
                                            offset_from = data.get('from')
                                            offset_to = data.get('to')
                                        else:
                                            # Response is a list - no pagination support
                                            print(f"[MCP_DEBUG] [{_ts()}] 📊 Parsed JSON is a list (length: {len(data) if isinstance(data, list) else 0}) - no pagination")
                                            query_id = None
                                            offset_total = None
                                            offset_from = None
                                            offset_to = None
                                        
                                        # Detect data field: logs, objects, rulebase, or other array fields (only for dict responses)
                                        if isinstance(data, dict):
                                            for field in ['logs', 'objects', 'rulebase', 'gateways', 'servers', 'hosts', 'networks', 'services']:
                                                if field in data and isinstance(data[field], list):
                                                    data_field = field
                                                    first_page_data = data[field]
                                                    # Store original wrapper for pagination (preserve uid, name, objects-dictionary, etc.)
                                                    original_wrapper = {k: v for k, v in data.items() if k != field}
                                                    print(f"[MCP_DEBUG] [{_ts()}] 📄 Page 1: Retrieved {len(first_page_data)} {field}")
                                                    print(f"[MCP_DEBUG] [{_ts()}] 📄 First response has query-id: {query_id is not None}, total: {offset_total}, from: {offset_from}, to: {offset_to}")
                                                    
                                                    if query_id:
                                                        print(f"[MCP_DEBUG] [{_ts()}] 📄 Detected query-id pagination")
                                                    elif offset_total and offset_to:
                                                        print(f"[MCP_DEBUG] [{_ts()}] 📄 Detected offset pagination (total: {offset_total}, from: {offset_from}, to: {offset_to})")
                                                    break
                                        
                                        if data_field:
                                            break
                                    except Exception as parse_error:
                                        print(f"[MCP_DEBUG] [{_ts()}] ⚠️ JSON parse error for item {idx}: {parse_error}")
                                        # Gateway CLI tools often return plain text, not JSON - wrap it for safe processing
                                        current_text = item.get('text')
                                        print(f"[MCP_DEBUG] [{_ts()}] 📝 Current item['text'] type: {type(current_text)}, value: {current_text if len(str(current_text)) < 100 else str(current_text)[:100] + '...'}")
                                        if isinstance(current_text, str):
                                            # Keep plain text as-is (for gateway CLI output like cpinfo, show commands)
                                            item['text'] = {"message": current_text, "_plain_text": True}
                                            print(f"[MCP_DEBUG] [{_ts()}] 📝 Wrapped plain text response in message field: {item['text']}")
                                        import traceback
                                        print(f"[MCP_DEBUG] [{_ts()}] ⚠️ Traceback: {traceback.format_exc()}")
                        
                        # QUERY-ID BASED PAGINATION (logs, threat logs)
                        # Extract max-logs-per-request from args to check for full pages
                        max_logs_requested = 100  # Default
                        if 'new-query' in args and isinstance(args['new-query'], dict):
                            max_logs_requested = args['new-query'].get('max-logs-per-request', 100)
                        
                        # Start pagination if we have query-id AND got a full page (>=90% of max requested)
                        # This handles cases where API might return slightly less than requested
                        full_page_threshold = max(1, int(max_logs_requested * 0.9))
                        
                        if query_id and data_field and len(first_page_data) >= full_page_threshold:
                            print(f"[MCP_DEBUG] [{_ts()}] 📄 Starting pagination for {tool.name} (max {MAX_PAGES} pages, page size: {max_logs_requested})")
                            all_data.extend(first_page_data)
                            current_page_data = first_page_data
                            
                            # Continue pagination while we have query-id and full pages
                            while query_id and len(current_page_data) >= full_page_threshold and page_count < MAX_PAGES:
                                page_count += 1
                                print(f"[MCP_DEBUG] [{_ts()}] 📄 Fetching page {page_count} using query-id...")
                                
                                # Next request with only query-id
                                pagination_args = {"query-id": query_id}
                                page_result = await call_tool_with_retry(session, tool.name, arguments=pagination_args)
                                page_dict = convert_to_dict(page_result.content)
                                
                                # Extract data from this page
                                current_page_data = []
                                if isinstance(page_dict, list):
                                    for item in page_dict:
                                        if isinstance(item, dict) and 'text' in item:
                                            try:
                                                data = json.loads(item['text'])
                                                if data_field in data:
                                                    current_page_data = data[data_field]
                                                    query_id = data.get('query-id')  # Update for next page
                                                    print(f"[MCP_DEBUG] [{_ts()}] 📄 Page {page_count}: Retrieved {len(current_page_data)} {data_field}")
                                                    break
                                            except:
                                                pass
                                
                                all_data.extend(current_page_data)
                            
                            # Build aggregated response
                            total_items = len(all_data)
                            print(f"[MCP_DEBUG] [{_ts()}] 📄 ✓ Pagination complete: {total_items} total {data_field} across {page_count} pages")
                            
                            # Preserve original wrapper structure (uid, name, objects-dictionary, etc.) and merge with paginated data
                            aggregated_response = original_wrapper.copy() if original_wrapper else {}
                            aggregated_response[data_field] = all_data
                            aggregated_response["total"] = total_items
                            aggregated_response["pages_fetched"] = page_count
                            if query_id and page_count >= MAX_PAGES:
                                aggregated_response["note"] = f"Reached maximum page limit ({MAX_PAGES}). More {data_field} may be available."
                            
                            # Create serializable content
                            content_serializable = [{
                                "type": "text",
                                "text": json.dumps(aggregated_response, indent=2)
                            }]
                            # Extract UUID mappings BEFORE cleaning
                            uuid_mappings = extract_uuid_mappings(aggregated_response)
                            content_serializable = clean_uuids_from_data(content_serializable)
                            # Resolve UUID references using extracted mappings
                            if uuid_mappings:
                                content_serializable = resolve_uuid_references(content_serializable, uuid_mappings)
                        
                        # OFFSET-BASED PAGINATION (objects, gateways, etc.)
                        elif offset_total and offset_to and data_field and offset_total > offset_to:
                            print(f"[MCP_DEBUG] [{_ts()}] 📄 Starting offset pagination for {tool.name} (total: {offset_total})")
                            print(f"[MCP_DEBUG] [{_ts()}] 📄 Base args type: {type(args)}, content: {args}")
                            print(f"[MCP_DEBUG] [{_ts()}] 📄 Args contains {len(args)} parameters: {list(args.keys()) if isinstance(args, dict) else 'NOT A DICT!'}")
                            
                            # Store base args before pagination (defensive copy)
                            base_args = dict(args) if isinstance(args, dict) else {}
                            all_data.extend(first_page_data)
                            current_offset = offset_to
                            
                            # Continue fetching while there's more data
                            while current_offset < offset_total and page_count < MAX_PAGES:
                                page_count += 1
                                print(f"[MCP_DEBUG] [{_ts()}] 📄 Fetching page {page_count} with offset {current_offset}...")
                                
                                # CRITICAL: Merge base args with pagination params
                                page_args = {**base_args, "offset": current_offset, "limit": 100}
                                print(f"[MCP_DEBUG] [{_ts()}] 📄 Page {page_count} merged args ({len(page_args)} params): {page_args}")
                                
                                page_result = await call_tool_with_retry(session, tool.name, arguments=page_args)
                                page_dict = convert_to_dict(page_result.content)
                                
                                # Extract data from this page
                                page_data = []
                                if isinstance(page_dict, list):
                                    for item in page_dict:
                                        if isinstance(item, dict) and 'text' in item:
                                            try:
                                                data = json.loads(item['text'])
                                                if data_field in data:
                                                    page_data = data[data_field]
                                                    current_offset = data.get('to', current_offset + len(page_data))
                                                    print(f"[MCP_DEBUG] [{_ts()}] 📄 Page {page_count}: Retrieved {len(page_data)} {data_field} (offset now: {current_offset})")
                                                    break
                                            except:
                                                pass
                                
                                if not page_data:
                                    print(f"[MCP_DEBUG] [{_ts()}] 📄 No more data returned, stopping pagination")
                                    break
                                
                                all_data.extend(page_data)
                            
                            # Build aggregated response
                            total_items = len(all_data)
                            print(f"[MCP_DEBUG] [{_ts()}] 📄 ✓ Offset pagination complete: {total_items} total {data_field} across {page_count} pages")
                            
                            # Preserve original wrapper structure (uid, name, objects-dictionary, etc.) and merge with paginated data
                            aggregated_response = original_wrapper.copy() if original_wrapper else {}
                            aggregated_response[data_field] = all_data
                            aggregated_response["total"] = total_items
                            aggregated_response["pages_fetched"] = page_count
                            aggregated_response["expected_total"] = offset_total
                            if current_offset < offset_total and page_count >= MAX_PAGES:
                                aggregated_response["note"] = f"Reached maximum page limit ({MAX_PAGES}). More {data_field} may be available (expected {offset_total} total)."
                            
                            # Create serializable content
                            content_serializable = [{
                                "type": "text",
                                "text": json.dumps(aggregated_response, indent=2)
                            }]
                            # Extract UUID mappings BEFORE cleaning
                            uuid_mappings = extract_uuid_mappings(aggregated_response)
                            content_serializable = clean_uuids_from_data(content_serializable)
                            # Resolve UUID references using extracted mappings
                            if uuid_mappings:
                                content_serializable = resolve_uuid_references(content_serializable, uuid_mappings)
                            
                        else:
                            # No pagination needed or detected - use original response
                            if query_id and data_field:
                                print(f"[MCP_DEBUG] [{_ts()}] 📄 Partial page ({len(first_page_data)} {data_field}) - no pagination needed")
                            elif offset_total and offset_to and data_field:
                                print(f"[MCP_DEBUG] [{_ts()}] 📄 All data retrieved ({offset_to} of {offset_total} {data_field}) - no pagination needed")
                            print(f"[MCP_DEBUG] [{_ts()}] ✓ Tool {tool.name} returned successfully")
                            print(f"[MCP_DEBUG] [{_ts()}] Result type: {type(tool_result.content)}")
                            
                            # Convert MCP objects to JSON-serializable dictionaries
                            content_serializable = content_dict
                            # Extract UUID mappings BEFORE cleaning
                            uuid_mappings = extract_uuid_mappings(content_serializable)
                            content_serializable = clean_uuids_from_data(content_serializable)
                            # Resolve UUID references using extracted mappings
                            if uuid_mappings:
                                content_serializable = resolve_uuid_references(content_serializable, uuid_mappings)
                            
                            # CRITICAL FIX: Re-serialize item['text'] back to JSON string
                            # Line 1346 replaced JSON strings with Python dicts for parsing,
                            # but QueryOrchestrator expects JSON strings. Convert back!
                            if isinstance(content_serializable, list):
                                for item in content_serializable:
                                    if isinstance(item, dict) and 'text' in item:
                                        if isinstance(item['text'], (dict, list)):
                                            # Re-serialize Python objects back to JSON strings
                                            item['text'] = json.dumps(item['text'])
                                            print(f"[MCP_DEBUG] [{_ts()}] 🔄 Re-serialized item['text'] back to JSON string")
                            
                            print(f"[MCP_DEBUG] [{_ts()}] ✓ Converted result to JSON-serializable format")
                        
                        # Check if result contains CheckPoint API errors
                        has_api_error = False
                        api_error_msg = None
                        if isinstance(content_serializable, list):
                            for item in content_serializable:
                                if isinstance(item, dict):
                                    text = item.get('text', '')
                                    # Look for CheckPoint API error patterns
                                    if 'API Error' in text or 'generic_err_' in text:
                                        has_api_error = True
                                        # Extract error message
                                        if 'message:' in text:
                                            api_error_msg = text.split('message:')[-1].strip().strip("'}")
                                        else:
                                            api_error_msg = text
                                        print(f"[MCP_DEBUG] [{_ts()}] ⚠️ CheckPoint API error detected: {api_error_msg}")
                        
                        # Combine MCP server's isError flag with our API error detection
                        # Use OR logic: error if either the tool says so OR we detected an API error
                        is_error = (tool_result.isError if hasattr(tool_result, 'isError') else False) or has_api_error
                        
                        results["tool_results"].append({
                            "tool": tool.name,
                            "description": tool.description or "",
                            "result": {
                                "content": content_serializable,
                                "isError": is_error,
                                "api_error": api_error_msg if has_api_error else None
                            }
                        })
                    except Exception as e:
                        error_msg = str(e)
                        print(f"[MCP_DEBUG] [{_ts()}] ✗ Error calling tool {tool.name}: {type(e).__name__}: {error_msg}")
                        import traceback
                        print(f"[MCP_DEBUG] [{_ts()}] Traceback:\n{traceback.format_exc()}")
                        
                        # Categorize error type for better handling
                        error_category = "unknown"
                        if "timeout" in error_msg.lower():
                            error_category = "timeout"
                        elif "connection" in error_msg.lower():
                            error_category = "connection"
                        elif "authentication" in error_msg.lower() or "unauthorized" in error_msg.lower():
                            error_category = "auth"
                        elif "parameter" in error_msg.lower():
                            error_category = "missing_parameter"
                        
                        results["tool_results"].append({
                            "tool": tool.name,
                            "error": error_msg,
                            "error_category": error_category
                        })
                
                # If no tools, try resources
                if not results["tool_results"]:
                    print(f"[MCP_DEBUG] [{_ts()}] No tool results available, trying resources...")
                    try:
                        resources_result = await session.list_resources()
                        print(f"[MCP_DEBUG] [{_ts()}] ✓ Received {len(resources_result.resources)} resources from server")
                        results["data_type"] = "resources"
                        results["resources"] = []
                        
                        for idx, resource in enumerate(resources_result.resources[:5]):
                            try:
                                print(f"[MCP_DEBUG] [{_ts()}] Reading resource {idx+1}/5: {resource.uri}")
                                resource_data = await session.read_resource(resource.uri)
                                # Convert MCP objects to JSON-serializable dictionaries
                                contents_serializable = convert_to_dict(resource_data.contents)
                                print(f"[MCP_DEBUG] [{_ts()}] ✓ Resource read successfully")
                                
                                results["resources"].append({
                                    "uri": resource.uri,
                                    "name": resource.name,
                                    "contents": contents_serializable
                                })
                            except Exception as e:
                                print(f"[MCP_DEBUG] [{_ts()}] ✗ Error reading resource {resource.uri}: {type(e).__name__}: {e}")
                    except Exception as e:
                        print(f"[MCP_DEBUG] [{_ts()}] ✗ Error listing resources: {type(e).__name__}: {e}")
                
                print(f"[MCP_DEBUG] [{_ts()}] ✓ Query completed successfully")
                print(f"[MCP_DEBUG] [{_ts()}] Total tool results: {len(results.get('tool_results', []))}")
                print(f"[MCP_DEBUG] [{_ts()}] Total resources: {len(results.get('resources', []))}")
                print(f"[MCP_DEBUG] [{_ts()}] ========== MCP Query Complete ==========\n")
                
                return results
                
    except Exception as e:
        print(f"\n[MCP_DEBUG] ✗✗✗ FATAL ERROR in MCP Query ✗✗✗")
        print(f"[MCP_DEBUG] [{_ts()}] Package: {package_name}")
        print(f"[MCP_DEBUG] [{_ts()}] Error type: {type(e).__name__}")
        print(f"[MCP_DEBUG] [{_ts()}] Error message: {e}")
        import traceback
        print(f"[MCP_DEBUG] [{_ts()}] Full traceback:")
        traceback.print_exc()
        print(f"[MCP_DEBUG] [{_ts()}] ========== MCP Query Failed ==========\n")
        return {"error": str(e), "package": package_name}

def query_mcp_server(package_name: str, env_vars: Dict[str, str], 
                     data_points: List[str], user_parameter_selections: Optional[Dict[str, str]] = None, 
                     discovery_mode: bool = True, user_query: str = "", 
                     call_all_tools: bool = False) -> Dict[str, Any]:
    """Synchronous wrapper for query_mcp_server_async
    
    Args:
        package_name: NPM package name (e.g., '@chkp/management-logs-mcp')
        env_vars: Environment variables for authentication
        data_points: List of data points to fetch
        user_parameter_selections: User-selected values for ambiguous parameters
        discovery_mode: If True, first discover available resources before querying
        user_query: The user's original query for context-aware parameter construction
        call_all_tools: If True, bypass scoring and call ALL available tools (override mode)
        
    Returns:
        Dict containing tools and their results
    """
    return asyncio.run(query_mcp_server_async(package_name, env_vars, data_points, user_parameter_selections, discovery_mode, user_query, call_all_tools))
