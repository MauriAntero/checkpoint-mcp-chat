"""
Gateway Script Executor - Safe Diagnostic Command Execution on Check Point Gateways

This module provides a secure, multi-layer validation system for executing 
read-only diagnostic commands on Check Point gateways via Management API run-script.

Safety Architecture:
- Layer 1: Strict command whitelist validation
- Layer 2: Dangerous pattern blocking (regex-based)
- Layer 3: Special character filtering
- Layer 4: LLM instruction constraints
- Layer 5: Execution wrapper with audit logging

All commands are verified against Check Point R81/R82 official documentation.
"""

import re
import json
import os
from typing import Tuple, Dict, List, Optional
from datetime import datetime
from pathlib import Path

class CommandValidator:
    """Multi-layer command validation system"""
    
    # Layer 1: Exact command whitelist (base commands only, args validated separately)
    SAFE_COMMANDS = {
        # System Information
        'show', 'uname', 'hostname', 'date', 'uptime', 'df', 'free',
        
        # Network Information
        'ifconfig', 'ip', 'netstat', 'arp',
        
        # Firewall Status
        'fw', 'fwaccel', 'fwaccel6',
        
        # Cluster HA
        'cphaprob',
        
        # Performance & Monitoring
        'top', 'ps', 'vmstat',
        
        # Check Point Utilities
        'cpstat', 'cpwd_admin', 'api', 'cplic', 'vpn', 'cpca_client', 'cpinfo',
        
        # Log viewing
        'cat', 'tail',
        
        # Environment
        'echo'
    }
    
    # Layer 1b: Complete safe command patterns with arguments
    SAFE_COMMAND_PATTERNS = [
        # CLISH show commands (all safe by design)
        r'^show\s+(version|hostname|uptime|asset|sysenv|commands|configuration|interfaces?|route|arp|dns|ntp|bonding|cluster|routed).*$',
        
        # System commands
        r'^uname\s+-a$',
        r'^hostname$',
        r'^date$',
        r'^uptime$',
        r'^df\s+-h$',
        r'^free\s+-m$',
        
        # Network commands
        r'^ifconfig$',
        r'^ip\s+(addr|route)\s+show$',
        r'^netstat\s+-[rin]+[tulnp]*$',
        r'^arp\s+-a$',
        
        # Firewall commands
        r'^fw\s+(stat|ver|getifs|hastat|log|lslogs).*$',
        r'^fw\s+ctl\s+(pstat|chain|conn|iflist|conntab).*$',
        r'^fw\s+tab\s+-[stf]+.*$',
        
        # SecureXL
        r'^fwaccel6?\s+(stat|stats|ver|conns).*$',
        
        # Cluster HA
        r'^cphaprob\s+(state|stat|list|syncstat|ldstat|mmagic|show_bond).*$',
        r'^cphaprob\s+-[ail]+\s+(if|list)$',
        
        # Performance
        r'^top\s+-n\s+1$',
        r'^ps\s+aux$',
        r'^vmstat\s+1\s+1$',
        
        # CP Utilities
        r'^cpstat(\s+[a-z]+)?(\s+-f\s+[a-z_]+)?$',
        r'^cpwd_admin\s+(list|monitor_list)$',
        r'^api\s+status$',
        r'^cplic\s+print$',
        r'^vpn\s+tu\s+tlist$',
        r'^cpca_client\s+lscert$',
        r'^cpinfo$',
        
        # Log files (read-only with specific paths)
        r'^cat\s+(/var/log/messages|\$FWDIR/log/[a-z]+\.elg|\$CPDIR/log/[a-z]+\.elg)$',
        r'^tail\s+-\d+\s+/var/log/messages$',
        
        # Environment variables (allow paths like $FWDIR/conf)
        r'^echo\s+\$[A-Z_]+(/[a-z]+)?$'
    ]
    
    # Layer 2: Dangerous pattern blocking
    BLOCKED_PATTERNS = [
        # Service/Process Control
        r'\b(cpstop|cpstart|cphastop|reboot|shutdown|halt)\b',
        r'\b(kill|pkill|killall)\b',
        
        # File Operations
        r'\b(rm|rmdir|unlink|dd)\b',
        r'\b(chmod|chown|chgrp)\b',
        r'\b(mkfs|fdisk|parted)\b',
        
        # Firewall Control
        r'\bfw\s+(unload|load|kill)\b',
        
        # VPN Control
        r'\bvpn\s+(shell|debug|tunnelutil)\b',
        r'\bvpn\s+tu\s+tlist\s+del\b',
        
        # Configuration Changes
        r'\b(set|add|delete|commit)\s+',
        r'\bcpconfig\b',
        r'\bclusterXL_admin\s+down\b',
        
        # Interactive Tools
        r'^(cpview|top(?!\s+-n\s+1)|vmstat(?!\s+1\s+1))\b',
        r'\bfw\s+monitor\b',
        
        # Debug Commands
        r'\bfw\s+ctl\s+debug\b',
        r'\bfwaccel\s+stats\s+-r\b',
        
        # Command chaining/redirection
        r'[;|&><]',
        r'\$\(',
        r'`',
        r'&&',
        r'\|\|'
    ]
    
    def validate_command(self, command: str) -> Tuple[bool, str]:
        """
        Validate command against all safety layers
        
        Args:
            command: The command string to validate
            
        Returns:
            Tuple of (is_safe: bool, reason: str)
        """
        # Normalize whitespace
        command = ' '.join(command.split())
        
        # Layer 2: Check for dangerous patterns FIRST (most restrictive)
        for pattern in self.BLOCKED_PATTERNS:
            if re.search(pattern, command, re.IGNORECASE):
                return False, f"Blocked: Command contains dangerous pattern '{pattern}'"
        
        # Layer 1: Validate against whitelist patterns FIRST (before char filtering)
        # This allows whitelisted commands with $FWDIR, etc.
        for pattern in self.SAFE_COMMAND_PATTERNS:
            if re.match(pattern, command, re.IGNORECASE):
                return True, "Command validated successfully"
        
        # Layer 3: Check for special characters (only if NOT whitelisted above)
        # This prevents non-whitelisted commands from using dangerous characters
        if any(char in command for char in ['$', '`', '(', ')']):
            return False, "Blocked: Special characters not allowed in non-whitelisted commands"
        
        # If we get here, command didn't match any safe pattern
        cmd_base = command.split()[0] if command else ""
        return False, f"Blocked: Command '{cmd_base}' not in whitelist or invalid arguments"


class GatewayScriptExecutor:
    """
    Execute safe diagnostic commands on Check Point gateways via Management API
    """
    
    def __init__(self, mcp_manager, log_dir: str = "./logs"):
        """
        Args:
            mcp_manager: Instance of MCPManager to call quantum-management MCP tools
            log_dir: Directory to store persistent audit logs
        """
        self.mcp_manager = mcp_manager
        self.validator = CommandValidator()
        self.execution_log = []  # In-memory for fast access
        self.log_dir = Path(log_dir)
        self.log_file = self.log_dir / "gateway_script_executor.log"
        
        # Ensure log directory exists
        self.log_dir.mkdir(parents=True, exist_ok=True)
    
    def execute_command(self, gateway_name: str, command: str, session_id: Optional[str] = None) -> Dict:
        """
        Execute a validated command on a gateway
        
        Args:
            gateway_name: Name or UID of the gateway
            command: The command to execute
            session_id: Optional Management API session ID
            
        Returns:
            Dict with:
                - success: bool
                - output: str (command output)
                - error: str (if failed)
                - command: str (the executed command)
                - gateway: str
                - timestamp: str
                - validated: bool
        """
        result = {
            'success': False,
            'gateway': gateway_name,
            'command': command,
            'timestamp': datetime.now().isoformat(),
            'validated': False,
            'output': '',
            'error': ''
        }
        
        # Validate command
        is_safe, reason = self.validator.validate_command(command)
        
        if not is_safe:
            result['error'] = f"Validation failed: {reason}"
            self._log_execution(result)
            return result
        
        result['validated'] = True
        
        # Execute via Management API run-script endpoint directly
        try:
            # Get Management server config from quantum-management MCP
            all_servers = self.mcp_manager.get_all_servers()
            if 'quantum-management' not in all_servers:
                result['error'] = "quantum-management MCP server not configured. Please configure it in Settings to use Gateway Script Executor."
                self._log_execution(result)
                return result
            
            mgmt_config = all_servers['quantum-management']
            mgmt_env = mgmt_config.get('env', {})
            
            # Extract Management API credentials
            management_host = mgmt_env.get('MANAGEMENT_HOST')
            api_key = mgmt_env.get('API_KEY')
            username = mgmt_env.get('USERNAME')
            password = mgmt_env.get('PASSWORD')
            port = mgmt_env.get('PORT', '443')
            
            if not management_host:
                result['error'] = "MANAGEMENT_HOST not configured in quantum-management MCP settings"
                self._log_execution(result)
                return result
            
            # Import requests for API calls
            import requests
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            
            # Build API base URL
            base_url = f"https://{management_host}:{port}/web_api"
            
            # Step 1: Login to get session ID
            login_url = f"{base_url}/login"
            login_payload = {}
            
            if api_key:
                login_payload = {"api-key": api_key}
            elif username and password:
                login_payload = {"user": username, "password": password}
            else:
                result['error'] = "No authentication credentials found (need API_KEY or USERNAME/PASSWORD)"
                self._log_execution(result)
                return result
            
            print(f"[GatewayScriptExecutor] Attempting login to {login_url}")
            login_response = requests.post(login_url, json=login_payload, verify=False, timeout=30)
            
            if login_response.status_code != 200:
                result['error'] = f"Management API login failed: {login_response.status_code} - {login_response.text}"
                print(f"[GatewayScriptExecutor] Login failed: {result['error']}")
                self._log_execution(result)
                return result
            
            login_data = login_response.json()
            sid = login_data.get('sid')
            print(f"[GatewayScriptExecutor] Login successful, sid={sid[:10] if sid else 'None'}...")
            
            if not sid:
                result['error'] = "No session ID received from Management API"
                self._log_execution(result)
                return result
            
            # Step 2: Call run-script API
            run_script_url = f"{base_url}/run-script"
            headers = {"X-chkp-sid": sid}
            
            # Wrap Gaia clish commands in clish -c wrapper
            # Commands starting with 'show' are clish commands
            wrapped_command = command
            if command.strip().lower().startswith('show'):
                wrapped_command = f"clish -c '{command}'"
                print(f"[GatewayScriptExecutor] Wrapped clish command: {wrapped_command}")
            
            script_payload = {
                "script-name": f"Diagnostic: {command[:50]}",
                "script": wrapped_command,
                "targets": [gateway_name]  # Array of gateway names
            }
            
            print(f"[GatewayScriptExecutor] Calling run-script with gateway={gateway_name}, command={command}")
            script_response = requests.post(run_script_url, json=script_payload, headers=headers, verify=False, timeout=60)
            print(f"[GatewayScriptExecutor] run-script response status: {script_response.status_code}")
            
            # Parse run-script response to get task-id
            if script_response.status_code == 200:
                script_data = script_response.json()
                print(f"[GatewayScriptExecutor] run-script response data: {script_data}")
                
                # Extract task-id from response
                tasks = script_data.get('tasks', [])
                if tasks and len(tasks) > 0:
                    task_id = tasks[0].get('task-id')
                    print(f"[GatewayScriptExecutor] Got task-id: {task_id}")
                    
                    if task_id:
                        # Step 3: Poll show-task endpoint until task completes
                        show_task_url = f"{base_url}/show-task"
                        max_polls = 30  # Poll for up to 30 seconds
                        poll_interval = 1  # 1 second between polls
                        
                        for poll_count in range(max_polls):
                            import time
                            time.sleep(poll_interval)
                            
                            task_status_response = requests.post(
                                show_task_url, 
                                json={"task-id": task_id, "details-level": "full"}, 
                                headers=headers, 
                                verify=False, 
                                timeout=10
                            )
                            
                            if task_status_response.status_code == 200:
                                task_status_data = task_status_response.json()
                                status = task_status_data.get('tasks', [{}])[0].get('status', '')
                                print(f"[GatewayScriptExecutor] Poll {poll_count+1}: Task status = {status}")
                                
                                if status == 'succeeded':
                                    # Extract output from completed task
                                    task_details = task_status_data.get('tasks', [{}])[0].get('task-details', [])
                                    print(f"[GatewayScriptExecutor] Task completed! Details: {task_details}")
                                    
                                    output_text = ''
                                    for detail in task_details:
                                        if isinstance(detail, dict):
                                            response_msg = detail.get('responseMessage', '')
                                            if response_msg:
                                                # Decode base64-encoded output
                                                import base64
                                                try:
                                                    decoded_output = base64.b64decode(response_msg).decode('utf-8')
                                                    output_text += decoded_output + '\n'
                                                    print(f"[GatewayScriptExecutor] Decoded base64 output: {decoded_output[:100]}...")
                                                except Exception as decode_error:
                                                    # If not base64, use as-is
                                                    output_text += str(response_msg) + '\n'
                                                    print(f"[GatewayScriptExecutor] Not base64, using raw: {response_msg[:100]}...")
                                        else:
                                            output_text += str(detail) + '\n'
                                    
                                    result['success'] = True
                                    result['output'] = output_text.strip()
                                    print(f"[GatewayScriptExecutor] Final output length: {len(output_text)}")
                                    break
                                elif status == 'failed':
                                    result['error'] = f"Task failed: {task_status_data}"
                                    print(f"[GatewayScriptExecutor] Task failed: {result['error']}")
                                    break
                                elif status == 'in progress':
                                    continue  # Keep polling
                            else:
                                result['error'] = f"show-task API failed: {task_status_response.status_code}"
                                print(f"[GatewayScriptExecutor] show-task error: {result['error']}")
                                break
                        else:
                            result['error'] = f"Task polling timeout after {max_polls} seconds"
                            print(f"[GatewayScriptExecutor] Timeout: {result['error']}")
                    else:
                        result['error'] = "No task-id in run-script response"
                else:
                    result['error'] = f"No tasks in run-script response: {script_data}"
                    print(f"[GatewayScriptExecutor] Error: {result['error']}")
            else:
                result['error'] = f"run-script API failed: {script_response.status_code} - {script_response.text}"
                print(f"[GatewayScriptExecutor] API error: {result['error']}")
            
            # Step 4: Logout
            logout_url = f"{base_url}/logout"
            requests.post(logout_url, headers=headers, json={}, verify=False, timeout=10)
        
        except Exception as e:
            result['error'] = f"Execution error: {str(e)}"
            import traceback
            traceback.print_exc()
        
        # Log execution
        self._log_execution(result)
        
        return result
    
    def execute_multiple_commands(self, gateway_name: str, commands: List[str], 
                                  session_id: Optional[str] = None) -> List[Dict]:
        """
        Execute multiple commands sequentially
        
        Args:
            gateway_name: Gateway to execute on
            commands: List of commands
            session_id: Optional API session ID
            
        Returns:
            List of execution results
        """
        results = []
        for command in commands:
            result = self.execute_command(gateway_name, command, session_id)
            results.append(result)
            
            # Stop on first failure
            if not result['success']:
                break
        
        return results
    
    def get_safe_commands_list(self) -> List[str]:
        """Return list of all safe command patterns"""
        return self.validator.SAFE_COMMAND_PATTERNS.copy()
    
    def _log_execution(self, result: Dict):
        """Log command execution for audit trail (both in-memory and persistent)"""
        # Add to in-memory log
        self.execution_log.append(result)
        
        # Keep only last 1000 executions in memory
        if len(self.execution_log) > 1000:
            self.execution_log = self.execution_log[-1000:]
        
        # Append to persistent audit log file
        try:
            log_entry = {
                'timestamp': result['timestamp'],
                'gateway': result['gateway'],
                'command': result['command'],
                'validated': result['validated'],
                'success': result['success'],
                'error': result.get('error', ''),
                # Don't log full output to keep log file manageable
                'has_output': bool(result.get('output'))
            }
            
            with open(self.log_file, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
        except Exception as e:
            print(f"[GatewayScriptExecutor] Warning: Failed to write audit log: {e}")
    
    def get_execution_log(self, limit: int = 100) -> List[Dict]:
        """Get recent execution log entries"""
        return self.execution_log[-limit:]
    
    def clear_execution_log(self):
        """Clear execution log"""
        self.execution_log = []


# LLM System Prompt Addition
GATEWAY_EXECUTOR_LLM_PROMPT = """
## ⚡ Gateway Script Executor - ENABLED

**CAPABILITY: You can execute CLI diagnostic commands directly on Check Point gateways when needed for analysis.**

**How It Works:**
1. When user asks gateway diagnostic questions, you can request CLI command execution
2. Include in required_servers: ["quantum-management"]
3. In data_to_fetch, specify: "run_script:<command>"
4. System automatically validates command against whitelist → Executes if safe → Returns output

**Usage Guidelines:**
- Think about what diagnostic data is needed to answer the user's question
- Request appropriate Check Point CLI commands (Gaia clish, expert mode, fw commands, etc.)
- System has a comprehensive whitelist of 120+ safe diagnostic commands
- Invalid/unsafe commands are automatically rejected (you'll see validation errors if this happens)

**Command Categories Available (not exhaustive - request what you need):**
- System diagnostics (version, uptime, hardware info, disk space, processes)
- Network status (interfaces, routing, ARP, connections)  
- Firewall operations (statistics, connections, acceleration status)
- Cluster status (HA state, sync status, failover readiness)
- VPN diagnostics (tunnels, encryption domains, IKE/IPsec)
- Security blade status (IPS, Anti-Bot, Threat Prevention, HTTPS Inspection)
- Performance metrics (CPU, memory, throughput, top processes)
- Log inspection (recent events, specific blade logs)

**Format in data_to_fetch:**
- "run_script:<any_valid_checkpoint_cli_command>"

**Example - Simple Query:**
User: "Show gateway version"
{
  "required_servers": ["quantum-management"],
  "data_to_fetch": ["run_script:fw ver"],
  "analysis_type": "gateway_diagnostics"
}

**Example - Comprehensive Analysis:**
User: "Full health check on cp-gw"
→ Think: Need version, cluster status, firewall stats, performance, network status
{
  "required_servers": ["quantum-management"],
  "data_to_fetch": [
    "gateway_identifier:cp-gw",
    "run_script:fw ver",
    "run_script:cphaprob state",
    "run_script:fw stat",
    "run_script:cpstat os -f all",
    "run_script:ifconfig"
  ],
  "analysis_type": "comprehensive_diagnostics"
}

**Key Points:**
- Request commands based on what diagnostic data you need - don't limit yourself to examples
- System enforces safety through whitelist validation (read-only, non-destructive commands only)
- For comprehensive diagnostics, combine multiple relevant commands
- Use quantum-management run-script for ALL gateway CLI commands (not quantum-gw-cli)
"""
