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
    
    def __init__(self, management_api_client, log_dir: str = "./logs"):
        """
        Args:
            management_api_client: Instance of ManagementAPIClient or similar
            log_dir: Directory to store persistent audit logs
        """
        self.api_client = management_api_client
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
        
        # Execute via Management API run-script
        try:
            # Call Management API run-script
            api_result = self.api_client.run_script(
                script_name=f"Diagnostic: {command[:50]}",
                script=command,
                targets=[gateway_name],
                session_id=session_id
            )
            
            if api_result.get('success'):
                result['success'] = True
                result['output'] = api_result.get('output', '')
                result['task_id'] = api_result.get('task_id', '')
            else:
                result['error'] = api_result.get('error', 'Unknown API error')
        
        except Exception as e:
            result['error'] = f"Execution error: {str(e)}"
        
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
## Gateway Script Executor - Safe Command Execution

You can execute diagnostic commands on Check Point gateways using the gateway_script_executor tool.

**STRICT RULES:**
1. You can ONLY suggest commands from this whitelist (see docs/GATEWAY_SAFE_COMMANDS_LIST.txt)
2. NEVER suggest commands that:
   - Stop, kill, or restart processes (cpstop, cpstart, kill, etc.)
   - Modify files or configurations (set, add, delete, commit, etc.)
   - Change permissions (chmod, chown, etc.)
   - Affect firewall rules (fw unload, fw load, etc.)
   - Open interactive shells (vpn shell, cpview, top without -n 1, etc.)
   - Use command chaining (pipes |, redirects >, command substitution $())

3. If investigation requires unsafe operations, EXPLAIN what should be done manually but DO NOT provide the command

**Safe Command Examples:**
- `show version all` - System version info
- `fw stat` - Firewall status
- `cphaprob state` - Cluster state
- `top -n 1` - Process snapshot
- `vpn tu tlist` - VPN tunnels
- `cpstat os -f all` - Complete system view

**How to Use:**
1. User asks: "What's the gateway version?"
2. You suggest: `fw ver` or `show version all`
3. System validates → Executes → Returns output
4. You analyze output and respond to user

All commands are automatically validated. If blocked, you'll receive an error message.
"""
