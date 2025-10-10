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

def clean_uuids_from_data(obj: Any) -> Any:
    """Remove UUIDs from CheckPoint object data, keeping only readable names
    
    Handles multiple CheckPoint data formats:
    1. Objects with uid/name fields: {"uid": "xxx", "name": "yyy"} -> "yyy"
    2. Strings with "uuid (name)" pattern -> "name"  
    3. Standalone UUID strings -> removed/replaced with placeholder
    
    Args:
        obj: Any data structure (dict, list, str, etc.)
        
    Returns:
        Cleaned version with UUIDs removed and names extracted
    """
    # UUID pattern: 8-4-4-4-12 hex digits
    uuid_pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    uuid_with_name_pattern = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\s*\(\s*([^)]+)\s*\)'
    
    if isinstance(obj, dict):
        # CheckPoint object structure: if dict has both 'uid' and 'name', return just the name
        if 'uid' in obj and 'name' in obj:
            # Return just the name string, discarding the uid
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
            return {key: clean_uuids_from_data(value) for key, value in obj.items()}
    
    elif isinstance(obj, str):
        # Pattern 1: "uuid (name)" -> extract name
        cleaned = re.sub(uuid_with_name_pattern, r'\1', obj, flags=re.IGNORECASE)
        
        # Pattern 2: standalone UUID -> remove or replace
        if re.match(uuid_pattern, cleaned, flags=re.IGNORECASE):
            return f"<uuid-{cleaned[:8]}>"  # Keep first 8 chars for reference
        
        return cleaned
    
    elif isinstance(obj, list):
        return [clean_uuids_from_data(item) for item in obj]
    
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
                                  call_all_tools: bool = False) -> Dict[str, Any]:
    """Query an MCP server for data (async version)
    
    Args:
        package_name: NPM package name (e.g., '@chkp/management-logs-mcp')
        env_vars: Environment variables for authentication
        data_points: List of data points to fetch (used for tool selection)
        user_parameter_selections: User-selected values for ambiguous parameters
        discovery_mode: If True, first discover available resources before querying
        user_query: Original user query string for context
        call_all_tools: If True, bypass scoring and call ALL available tools (override mode)
        
    Returns:
        Dict containing tools and their results
    """
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
                    discovery_keywords = ['show.gateways', 'list.packages', 'show.packages', 
                                         'list.policy.packages', 'show.objects', 'show.access.layers', 'show.https.layers', 'init']
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
                            
                            # Clean UUIDs AFTER extraction (for display purposes)
                            content_serializable = clean_uuids_from_data(content_serializable)
                            if resources:
                                discovered_resources[tool.name] = resources
                                print(f"[MCP_DEBUG] [{_ts()}] ✓ Discovered {len(resources)} resources from {tool.name}")
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
                            
                            # Clean UUIDs AFTER extraction (for display purposes)
                            content_serializable = clean_uuids_from_data(content_serializable)
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
                                    args[param] = user_parameter_selections[param]
                                    print(f"[MCP_DEBUG] [{_ts()}] Using user-selected layer '{args[param]}' for {tool.name}.{param}")
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
                                        args[param] = user_parameter_selections[param]
                                        has_name_identifier = True
                                        print(f"[MCP_DEBUG] [{_ts()}] Using user-selected access-layer '{args[param]}' for {tool.name}.{param}")
                                    elif len(access_layers) == 1:
                                        args[param] = access_layers[0].get('name')
                                        has_name_identifier = True
                                        print(f"[MCP_DEBUG] [{_ts()}] Using discovered access-layer '{args[param]}' for {tool.name}.{param}")
                                    else:
                                        print(f"[MCP_DEBUG] [{_ts()}] Multiple access-layers found - need user selection for {tool.name}.{param}")
                                else:
                                    print(f"[MCP_DEBUG] [{_ts()}] No access-layers found for {tool.name}.{param}")
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
                        elif any(pattern in search_text for pattern in ['24 hour', 'last 24 hours', 'last-24-hours', 'past 24 hours']):
                            time_frame = "last-24-hours"
                        elif any(pattern in search_text for pattern in ['last hour', 'past hour', 'last 60 min']):
                            time_frame = "last-hour"
                        
                        # Log type detection (Check Point schema: 'logs' for connection/traffic, 'audit' for audit)
                        if tool.name == 'show_logs':
                            log_type = "audit" if 'audit' in search_text else "logs"
                            
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
                        
                        # VPN connection logs - filter by service or blade
                        if any(kw in search_text for kw in ['vpn', 'vpn tunnel', 'vpn connection', 'remote access', 
                                                             'site-to-site', 'ipsec', 'ikev2', 'ikev1']):
                            # VPN logs can be filtered by service (VPN) or specific VPN-related attributes
                            blade_filter = 'service:"VPN" OR service:"IKE" OR service:"ISAKMP" OR product:"VPN"'
                            # VPN traffic is typically lower volume - reduce max logs to prevent excessive pagination
                            max_logs = 50
                        # Threat Prevention umbrella (includes Anti-Bot, Anti-Virus, IPS, Threat Emulation, etc.)
                        elif any(kw in search_text for kw in ['threat prevention', 'threat', 'ips', 'intrusion', 
                                                             'threat emulation', 'threat extraction', 'zero-phishing', 
                                                             'zero phishing', 'anti-bot', 'anti bot', 'bot protection',
                                                             'anti-virus', 'antivirus', 'malware']):
                            # Use OR logic to capture all threat-related blades
                            blade_filter = 'blade:"Threat Prevention" OR blade:"Anti-Bot" OR blade:"Anti-Virus" OR blade:"IPS" OR blade:"Threat Emulation"'
                        elif any(kw in search_text for kw in ['content awareness', 'content', 'dlp', 'data loss']):
                            blade_filter = 'blade:"Content Awareness"'
                        elif any(kw in search_text for kw in ['https inspection', 'ssl inspection', 'tls inspection']):
                            blade_filter = 'blade:"HTTPS Inspection"'
                        
                        # Create new_query dict AFTER max_logs adjustment from blade filters
                        new_query = {
                            "time-frame": time_frame,
                            "max-logs-per-request": max_logs
                        }
                        if log_type:
                            new_query["type"] = log_type
                        
                        if blade_filter:
                            # MCP server expects flat string - it handles CheckPoint API transformation internally
                            new_query["filter"] = blade_filter
                            print(f"[MCP_DEBUG] [{_ts()}] Added blade filter: {blade_filter}")
                            
                            # Mark VPN queries for special handling (verbose logs)
                            if 'VPN' in blade_filter or 'IKE' in blade_filter:
                                args["_vpn_query"] = True  # Internal flag for pagination control
                        
                        args["new-query"] = new_query
                        print(f"[MCP_DEBUG] [{_ts()}] Auto-constructed new-query for {tool.name}: {new_query}")
                    
                    # 2. GATEWAY CLI: All tools require target_gateway parameter
                    if 'target_gateway' in required and 'target_gateway' not in args:
                        # Try to find gateway from previous discovery or data_points
                        if gateways and len(gateways) > 0:
                            args['target_gateway'] = gateways[0].get('name')
                            print(f"[MCP_DEBUG] [{_ts()}] Auto-filled target_gateway: {args['target_gateway']}")
                        else:
                            # No gateways discovered - try to extract from user query or use GATEWAY_HOST
                            # Look for gateway name in user query (e.g., "routing on cp-gw", "diagnose gateway01")
                            if user_query:
                                # Pattern 1: "on <gateway>" or "for <gateway>" or "in <gateway>"
                                match = re.search(r'\b(?:on|for|in|from|at)\s+([a-zA-Z0-9][a-zA-Z0-9._-]+)', user_query, re.IGNORECASE)
                                if match:
                                    potential_gateway = match.group(1)
                                    # Exclude common words
                                    if potential_gateway.lower() not in ['the', 'this', 'that', 'my', 'our', 'all', 'each', 'every', 'gateway', 'firewall']:
                                        args['target_gateway'] = potential_gateway
                                        print(f"[MCP_DEBUG] [{_ts()}] Auto-filled target_gateway from user query: {args['target_gateway']}")
                                
                                # Pattern 2: Direct gateway name mention (cp-gw, gw-01, firewall-dmz, etc.)
                                if 'target_gateway' not in args:
                                    match = re.search(r'\b([a-zA-Z0-9]+[-_][a-zA-Z0-9][a-zA-Z0-9._-]*)', user_query)
                                    if match:
                                        args['target_gateway'] = match.group(1)
                                        print(f"[MCP_DEBUG] [{_ts()}] Auto-filled target_gateway from identifier pattern: {args['target_gateway']}")
                            
                            # Fallback: use GATEWAY_HOST environment variable if available
                            if 'target_gateway' not in args and 'GATEWAY_HOST' in env_vars:
                                args['target_gateway'] = env_vars['GATEWAY_HOST']
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
                        if 'show_raw' not in args:
                            args['show_raw'] = True
                            print(f"[MCP_DEBUG] [{_ts()}] Set show_raw=true for {tool.name} (bypass server formatting, get raw JSON)")
                    
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
                    # STANDARD MODE: Score-based intelligent selection
                    RELEVANCE_THRESHOLD = 15  # Only call tools with score > 15 (filters out noise)
                    MIN_TOOLS = 3  # Always call at least this many tools
                    AGGRESSIVE_THRESHOLD = 100  # Very high relevance (exact keyword matches)
                    
                    selected_tools = []
                    
                    # Phase 1: Add ALL tools above relevance threshold (NO CAP)
                    # This ensures we call every tool that's actually relevant to the query
                    relevant_tools = [(t, a, s) for t, a, s in tools_with_scores if s > RELEVANCE_THRESHOLD]
                    selected_tools.extend(relevant_tools)  # NO CAP - include all relevant tools
                    
                    # Count by score tier for visibility
                    aggressive_count = len([s for t, a, s in relevant_tools if s > AGGRESSIVE_THRESHOLD])
                    high_count = len([s for t, a, s in relevant_tools if 50 < s <= AGGRESSIVE_THRESHOLD])
                    medium_count = len([s for t, a, s in relevant_tools if RELEVANCE_THRESHOLD < s <= 50])
                    
                    print(f"[MCP_DEBUG] [{_ts()}] Selected {len(relevant_tools)} tools above threshold ({RELEVANCE_THRESHOLD}) - NO LIMIT:")
                    print(f"[MCP_DEBUG] [{_ts()}]   - {aggressive_count} aggressive-match tools (score > {AGGRESSIVE_THRESHOLD})")
                    print(f"[MCP_DEBUG] [{_ts()}]   - {high_count} high-relevance tools (score 51-{AGGRESSIVE_THRESHOLD})")
                    print(f"[MCP_DEBUG] [{_ts()}]   - {medium_count} medium-relevance tools (score {RELEVANCE_THRESHOLD+1}-50)")
                    
                    # Phase 2: If still below minimum, add remaining tools to reach MIN_TOOLS
                    # This only happens for very generic queries with no strong keyword matches
                    if len(selected_tools) < MIN_TOOLS:
                        remaining_needed = MIN_TOOLS - len(selected_tools)
                        already_selected_names = {t.name for t, a, s in selected_tools}
                        remaining_tools = [(t, a, s) for t, a, s in tools_with_scores 
                                          if t.name not in already_selected_names]
                        selected_tools.extend(remaining_tools[:remaining_needed])
                        print(f"[MCP_DEBUG] [{_ts()}] Added {len(remaining_tools[:remaining_needed])} additional tools to reach minimum of {MIN_TOOLS}")
                
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
                        # With log field filtering (70% token reduction: 850→250 tokens/log), we can retrieve more logs
                        # VPN logs: 10 pages (500 logs), Traffic/General logs: 10 pages (500-700 logs)
                        MAX_PAGES = 10  # Increased from 3/5 to 10 with intelligent log field filtering
                        
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
                                        
                                        # Detect data field: logs, objects, or other array fields (only for dict responses)
                                        if isinstance(data, dict):
                                            for field in ['logs', 'objects', 'gateways', 'servers', 'hosts', 'networks', 'services']:
                                                if field in data and isinstance(data[field], list):
                                                    data_field = field
                                                    first_page_data = data[field]
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
                            
                            aggregated_response = {
                                data_field: all_data,
                                "total": total_items,
                                "pages_fetched": page_count
                            }
                            if query_id and page_count >= MAX_PAGES:
                                aggregated_response["note"] = f"Reached maximum page limit ({MAX_PAGES}). More {data_field} may be available."
                            
                            # Create serializable content
                            content_serializable = [{
                                "type": "text",
                                "text": json.dumps(aggregated_response, indent=2)
                            }]
                            content_serializable = clean_uuids_from_data(content_serializable)
                        
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
                            
                            aggregated_response = {
                                data_field: all_data,
                                "total": total_items,
                                "pages_fetched": page_count,
                                "expected_total": offset_total
                            }
                            if current_offset < offset_total and page_count >= MAX_PAGES:
                                aggregated_response["note"] = f"Reached maximum page limit ({MAX_PAGES}). More {data_field} may be available (expected {offset_total} total)."
                            
                            # Create serializable content
                            content_serializable = [{
                                "type": "text",
                                "text": json.dumps(aggregated_response, indent=2)
                            }]
                            content_serializable = clean_uuids_from_data(content_serializable)
                            
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
                            content_serializable = clean_uuids_from_data(content_serializable)
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
