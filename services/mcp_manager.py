"""MCP server management service"""

import json
import subprocess
import asyncio
import requests
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
import os
import signal
import time
from dataclasses import dataclass
from enum import Enum

class MCPServerStatus(Enum):
    """MCP server status enumeration"""
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    ERROR = "error"
    UNKNOWN = "unknown"

@dataclass
class MCPServerInstance:
    """Represents a running MCP server instance"""
    name: str
    package: str
    process: Optional[subprocess.Popen] = None
    status: MCPServerStatus = MCPServerStatus.STOPPED
    port: Optional[int] = None
    env_vars: Optional[Dict[str, str]] = None
    last_health_check: Optional[float] = None
    error_message: Optional[str] = None

class MCPManager:
    """Manages CheckPoint MCP servers"""
    
    def __init__(self, data_dir: Path = Path("./data"), encryption_service=None):
        self.data_dir = data_dir
        self.servers_config_file = data_dir / "mcp_servers.json"
        self.running_servers: Dict[str, MCPServerInstance] = {}
        self.base_port = 8000
        self.encryption_service = encryption_service
        self.secrets_dir = Path("./secrets")
        
        # Ensure data directory exists
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.secrets_dir.mkdir(parents=True, exist_ok=True)
    
    def get_all_servers(self) -> Dict[str, Dict]:
        """Get all configured servers with decrypted credentials"""
        try:
            if self.servers_config_file.exists():
                with open(self.servers_config_file, 'r') as f:
                    servers = json.load(f)
                
                # Decrypt credentials for each server
                if self.encryption_service and self.encryption_service.is_initialized():
                    for server_name, server_config in servers.items():
                        # Try to load encrypted credentials
                        cred_file = self.secrets_dir / f"{server_name}_credentials.enc"
                        if cred_file.exists():
                            decrypted_creds = self.encryption_service.decrypt_file(cred_file)
                            if decrypted_creds:
                                # Populate env field with decrypted credentials
                                server_config['env'] = decrypted_creds
                        else:
                            # No encrypted credentials - check for legacy config field
                            if 'config' in server_config:
                                # Legacy plaintext credentials - use them but warn
                                print(f"[WARNING] Server '{server_name}' has plaintext credentials. Please update configuration.")
                                server_config['env'] = server_config.get('config', {})
                            else:
                                server_config['env'] = {}
                else:
                    # Encryption not initialized - use legacy config field as fallback
                    for server_name, server_config in servers.items():
                        if 'config' in server_config:
                            server_config['env'] = server_config.get('config', {})
                        else:
                            server_config['env'] = {}
                
                return servers
            return {}
        except Exception as e:
            print(f"Error loading servers config: {str(e)}")
            import traceback
            traceback.print_exc()
            return {}
    
    def save_servers_config(self, servers_config: Dict[str, Dict]) -> bool:
        """Save servers configuration (metadata only, never save env field)"""
        try:
            print(f"[MCPManager] save_servers_config called")
            print(f"[MCPManager] Config file path: {self.servers_config_file}")
            print(f"[MCPManager] Servers to save: {list(servers_config.keys())}")
            
            # Strip 'env' field from all servers before saving (credentials are in encrypted files)
            cleaned_config = {}
            for server_name, server_data in servers_config.items():
                cleaned_server = {k: v for k, v in server_data.items() if k != 'env'}
                cleaned_config[server_name] = cleaned_server
            
            print(f"[MCPManager] Saving metadata only (env field stripped)")
            with open(self.servers_config_file, 'w', encoding='utf-8') as f:
                json.dump(cleaned_config, f, indent=2)
            print(f"[MCPManager] File written successfully")
            # Verify the file was written
            if self.servers_config_file.exists():
                with open(self.servers_config_file, 'r') as f:
                    saved_data = json.load(f)
                    print(f"[MCPManager] Verification: File contains {len(saved_data)} servers (metadata only)")
            return True
        except Exception as e:
            print(f"[MCPManager] Error saving servers config: {str(e)}")
            import traceback
            traceback.print_exc()
            return False
    
    def add_server(self, server_name: str, server_config: Dict) -> bool:
        """Add a new MCP server configuration with encrypted credentials"""
        try:
            print(f"[MCPManager] add_server called for: {server_name}")
            print(f"[MCPManager] Server config: {server_config}")
            
            # Load existing servers (without decryption to get raw metadata)
            if self.servers_config_file.exists():
                with open(self.servers_config_file, 'r') as f:
                    servers = json.load(f)
            else:
                servers = {}
            
            print(f"[MCPManager] Current servers before add: {list(servers.keys())}")
            
            # Check if this is an update or new server
            is_update = server_name in servers
            was_active = servers.get(server_name, {}).get('active', False) if is_update else False
            print(f"[MCPManager] Is update: {is_update}, Was active: {was_active}")
            
            # Extract credentials from config
            credentials = server_config.get('config', {})
            print(f"[MCPManager] Credentials extracted: {list(credentials.keys()) if credentials else 'None'}")
            
            # Create metadata-only config (without credentials)
            metadata = {
                'package': server_config.get('package'),
                'type': server_config.get('type'),
                'description': server_config.get('description'),
                'added_at': servers[server_name]['added_at'] if is_update else time.time(),
                'active': was_active if is_update else False  # Preserve active status when updating
            }
            print(f"[MCPManager] Metadata active status: {metadata['active']}")
            
            # Debug encryption service status
            print(f"[MCPManager] Encryption service exists: {self.encryption_service is not None}")
            if self.encryption_service:
                print(f"[MCPManager] Encryption service initialized: {self.encryption_service.is_initialized()}")
            
            # Encrypt and save credentials if encryption is available
            if credentials and self.encryption_service and self.encryption_service.is_initialized():
                cred_file = self.secrets_dir / f"{server_name}_credentials.enc"
                print(f"[MCPManager] Attempting to encrypt credentials to {cred_file}")
                if self.encryption_service.encrypt_file(cred_file, credentials):
                    print(f"[MCPManager] ✓ Credentials encrypted and saved to {cred_file}")
                else:
                    print(f"[MCPManager] ✗ Failed to encrypt credentials for {server_name}")
                    return False
            elif credentials:
                # Encryption not available - store plaintext (legacy mode)
                print(f"[MCPManager] ⚠️ WARNING: Encryption not initialized - storing credentials in plaintext for {server_name}")
                metadata['config'] = credentials
            
            servers[server_name] = metadata
            print(f"[MCPManager] Servers after add: {list(servers.keys())}")
            
            # Save metadata to JSON
            result = self.save_servers_config(servers)
            print(f"[MCPManager] save_servers_config returned: {result}")
            return result
        except Exception as e:
            print(f"[MCPManager] Error adding server {server_name}: {str(e)}")
            import traceback
            traceback.print_exc()
            return False
    
    def remove_server(self, server_name: str) -> bool:
        """Remove MCP server configuration and encrypted credentials"""
        try:
            # Stop server if running
            if server_name in self.running_servers:
                self.stop_server(server_name)
            
            # Remove encrypted credentials file
            cred_file = self.secrets_dir / f"{server_name}_credentials.enc"
            if cred_file.exists():
                cred_file.unlink()
                print(f"[MCPManager] Removed encrypted credentials for {server_name}")
            
            # Remove from config (load raw metadata without decryption)
            if self.servers_config_file.exists():
                with open(self.servers_config_file, 'r') as f:
                    servers = json.load(f)
                if server_name in servers:
                    del servers[server_name]
                    return self.save_servers_config(servers)
            
            return True
        except Exception as e:
            print(f"Error removing server {server_name}: {str(e)}")
            return False
    
    def update_server_config(self, server_name: str, config_updates: Dict) -> bool:
        """Update server configuration with credential encryption"""
        try:
            # Load raw metadata (without decryption)
            if self.servers_config_file.exists():
                with open(self.servers_config_file, 'r') as f:
                    servers = json.load(f)
            else:
                return False
            
            if server_name not in servers:
                return False
            
            # Extract credentials if present in updates
            if 'config' in config_updates:
                credentials = config_updates.pop('config')
                
                # Encrypt and save credentials
                if credentials and self.encryption_service and self.encryption_service.is_initialized():
                    cred_file = self.secrets_dir / f"{server_name}_credentials.enc"
                    if not self.encryption_service.encrypt_file(cred_file, credentials):
                        print(f"[MCPManager] ✗ Failed to encrypt updated credentials for {server_name}")
                        return False
                    print(f"[MCPManager] ✓ Updated credentials encrypted and saved")
                elif credentials:
                    # Encryption not available - store plaintext
                    print(f"[WARNING] Encryption not initialized - storing updated credentials in plaintext")
                    config_updates['config'] = credentials
            
            # Update metadata
            servers[server_name].update(config_updates)
            servers[server_name]['updated_at'] = time.time()
            
            return self.save_servers_config(servers)
        except Exception as e:
            print(f"Error updating server {server_name}: {str(e)}")
            import traceback
            traceback.print_exc()
            return False
    
    def start_server(self, server_name: str, env_vars: Optional[Dict[str, str]] = None) -> bool:
        """Start an MCP server with encrypted credentials"""
        try:
            if server_name in self.running_servers:
                if self.running_servers[server_name].status == MCPServerStatus.RUNNING:
                    return True  # Already running
            
            servers_config = self.get_all_servers()
            if server_name not in servers_config:
                print(f"[MCPManager] Server {server_name} not found in config")
                return False
            
            server_config = servers_config[server_name]
            package_name = server_config.get('package')
            
            if not package_name:
                print(f"[MCPManager] No package name for server {server_name}")
                return False
            
            # Prepare environment variables - use decrypted credentials from server_config
            env = os.environ.copy()
            
            # First use decrypted credentials from encrypted files (in 'env' field)
            if 'env' in server_config and server_config['env']:
                print(f"[MCPManager] Using decrypted credentials from encrypted files for {server_name}")
                env.update(server_config['env'])
            
            # Override with explicit env_vars if provided (legacy/testing support)
            if env_vars:
                print(f"[MCPManager] Overriding with explicit env_vars for {server_name}")
                env.update(env_vars)
            
            # Find available port
            port = self._find_available_port()
            
            # Start the MCP server process with stdin/stdout/stderr pipes for JSON-RPC communication
            import platform
            is_windows = platform.system() == "Windows"
            
            cmd = ["npx", package_name]
            
            process = subprocess.Popen(
                cmd,
                env=env,
                stdin=subprocess.PIPE,  # Enable stdin for sending JSON-RPC requests
                stdout=subprocess.PIPE,  # Enable stdout for receiving JSON-RPC responses
                stderr=subprocess.PIPE,  # Enable stderr for logs
                text=True,
                bufsize=1,  # Line buffered
                shell=is_windows  # Required on Windows to find npx in PATH
            )
            
            # Create server instance
            server_instance = MCPServerInstance(
                name=server_name,
                package=package_name,
                process=process,
                status=MCPServerStatus.STARTING,
                port=port,
                env_vars=env_vars or {}
            )
            
            self.running_servers[server_name] = server_instance
            
            # Wait a moment and check if process started successfully
            time.sleep(2)
            if process.poll() is None:  # Process is still running
                server_instance.status = MCPServerStatus.RUNNING
                
                # Update config to mark as active
                servers = self.get_all_servers()
                if server_name in servers:
                    servers[server_name]['active'] = True
                    self.save_servers_config(servers)
                return True
            else:
                # Process died, read error
                stdout, stderr = process.communicate()
                server_instance.status = MCPServerStatus.ERROR
                server_instance.error_message = stderr or stdout
                
                # Update config to mark as inactive
                servers = self.get_all_servers()
                if server_name in servers:
                    servers[server_name]['active'] = False
                    self.save_servers_config(servers)
                return False
            
        except Exception as e:
            print(f"Error starting server {server_name}: {str(e)}")
            if server_name in self.running_servers:
                self.running_servers[server_name].status = MCPServerStatus.ERROR
                self.running_servers[server_name].error_message = str(e)
            return False
    
    def stop_server(self, server_name: str) -> bool:
        """Stop an MCP server"""
        try:
            if server_name not in self.running_servers:
                return True  # Not running
            
            server_instance = self.running_servers[server_name]
            
            if server_instance.process and server_instance.process.poll() is None:
                # Try graceful shutdown first
                server_instance.process.terminate()
                
                # Wait up to 5 seconds for graceful shutdown
                for _ in range(50):
                    if server_instance.process.poll() is not None:
                        break
                    time.sleep(0.1)
                
                # Force kill if still running
                if server_instance.process.poll() is None:
                    server_instance.process.kill()
                    server_instance.process.wait()
            
            server_instance.status = MCPServerStatus.STOPPED
            
            # Update config to mark as inactive
            servers = self.get_all_servers()
            if server_name in servers:
                servers[server_name]['active'] = False
                self.save_servers_config(servers)
            
            # Remove from running servers
            del self.running_servers[server_name]
            
            return True
            
        except Exception as e:
            print(f"Error stopping server {server_name}: {str(e)}")
            return False
    
    def restart_server(self, server_name: str, env_vars: Optional[Dict[str, str]] = None) -> bool:
        """Restart an MCP server"""
        self.stop_server(server_name)
        time.sleep(1)  # Brief pause
        return self.start_server(server_name, env_vars)
    
    def get_server_status(self, server_name: str) -> MCPServerStatus:
        """Get current status of an MCP server"""
        if server_name not in self.running_servers:
            return MCPServerStatus.STOPPED
        
        server_instance = self.running_servers[server_name]
        
        # Check if process is still alive
        if server_instance.process:
            if server_instance.process.poll() is None:
                return MCPServerStatus.RUNNING
            else:
                # Process died
                server_instance.status = MCPServerStatus.ERROR
                return MCPServerStatus.ERROR
        
        return server_instance.status
    
    def get_active_servers(self) -> List[str]:
        """Get list of currently active server names"""
        active = []
        for name, instance in self.running_servers.items():
            if self.get_server_status(name) == MCPServerStatus.RUNNING:
                active.append(name)
        return active
    
    def health_check_server(self, server_name: str) -> Dict[str, Any]:
        """Perform health check on a specific server"""
        try:
            if server_name not in self.running_servers:
                return {
                    'server': server_name,
                    'status': 'stopped',
                    'healthy': False,
                    'message': 'Server not running'
                }
            
            server_instance = self.running_servers[server_name]
            status = self.get_server_status(server_name)
            
            health_result = {
                'server': server_name,
                'status': status.value,
                'healthy': status == MCPServerStatus.RUNNING,
                'port': server_instance.port,
                'package': server_instance.package,
                'uptime': None,
                'message': None
            }
            
            if status == MCPServerStatus.RUNNING:
                # Note: Uptime calculation requires tracking start_time separately
                health_result['message'] = 'Server running normally'
            elif status == MCPServerStatus.ERROR:
                health_result['message'] = server_instance.error_message or 'Unknown error'
            
            server_instance.last_health_check = time.time()
            return health_result
            
        except Exception as e:
            return {
                'server': server_name,
                'status': 'error',
                'healthy': False,
                'message': f'Health check failed: {str(e)}'
            }
    
    def health_check_all(self) -> Dict[str, Dict[str, Any]]:
        """Perform health check on all configured servers"""
        results = {}
        servers = self.get_all_servers()
        
        for server_name in servers.keys():
            results[server_name] = self.health_check_server(server_name)
        
        return results
    
    def get_server_logs(self, server_name: str, lines: int = 50) -> List[str]:
        """Get recent logs from a server"""
        if server_name not in self.running_servers:
            return []
        
        try:
            server_instance = self.running_servers[server_name]
            if not server_instance.process:
                return []
            
            # This is a simplified version - in reality, you'd want to
            # implement proper log collection and storage
            return [f"Log entry for {server_name}"]
            
        except Exception as e:
            return [f"Error getting logs: {str(e)}"]
    
    def install_mcp_package(self, package_name: str) -> Tuple[bool, str]:
        """Install an MCP package using npm"""
        try:
            import platform
            is_windows = platform.system() == "Windows"
            
            result = subprocess.run(
                ["npm", "install", "-g", package_name],
                capture_output=True,
                text=True,
                timeout=300,  # 5 minutes timeout
                shell=is_windows  # Required on Windows to find npm in PATH
            )
            
            if result.returncode == 0:
                return True, f"Successfully installed {package_name}"
            else:
                return False, f"Installation failed: {result.stderr}"
                
        except FileNotFoundError:
            return False, f"npm not found - cannot install {package_name}. npm is required to install MCP packages."
        except subprocess.TimeoutExpired:
            return False, "Installation timed out"
        except Exception as e:
            return False, f"Installation error: {str(e)}"
    
    def update_mcp_package(self, package_name: str) -> Tuple[bool, str]:
        """Update an MCP package to latest version"""
        try:
            import platform
            is_windows = platform.system() == "Windows"
            
            result = subprocess.run(
                ["npm", "update", "-g", package_name],
                capture_output=True,
                text=True,
                timeout=300,  # 5 minutes timeout
                shell=is_windows  # Required on Windows to find npm in PATH
            )
            
            if result.returncode == 0:
                return True, f"Successfully updated {package_name}"
            else:
                return False, f"Update failed: {result.stderr}"
                
        except subprocess.TimeoutExpired:
            return False, "Update timed out"
        except Exception as e:
            return False, f"Update error: {str(e)}"
    
    def get_installed_version(self, package_name: str) -> Optional[str]:
        """Get currently installed version of a package"""
        try:
            import platform
            is_windows = platform.system() == "Windows"
            
            result = subprocess.run(
                ['npm', 'list', '-g', package_name, '--depth=0', '--json'],
                capture_output=True,
                text=True,
                timeout=10,
                shell=is_windows  # Required on Windows to find npm in PATH
            )
            
            if result.returncode == 0:
                import json
                data = json.loads(result.stdout)
                dependencies = data.get('dependencies', {})
                if package_name in dependencies:
                    return dependencies[package_name].get('version')
            return None
        except FileNotFoundError:
            print(f"[MCPManager] npm not found in environment - skipping version check for {package_name}")
            return None
        except Exception as e:
            print(f"Failed to get installed version for {package_name}: {str(e)}")
            return None
    
    def is_package_installed(self, package_name: str) -> bool:
        """Check if a package is installed globally"""
        return self.get_installed_version(package_name) is not None
    
    def check_package_version(self, package_name: str) -> Optional[str]:
        """Check latest version of a package from npm registry"""
        try:
            import requests
            
            package_url = f"https://registry.npmjs.org/{package_name}"
            response = requests.get(package_url, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                return data.get('dist-tags', {}).get('latest', None)
            return None
            
        except Exception as e:
            print(f"Version check failed for {package_name}: {str(e)}")
            return None
    
    def get_version_info(self, package_name: str) -> Dict[str, Any]:
        """Get comprehensive version information for a package"""
        installed_version = self.get_installed_version(package_name)
        latest_version = self.check_package_version(package_name)
        
        has_update = False
        if installed_version and latest_version:
            # Simple version comparison (works for semantic versioning)
            try:
                from packaging import version
                has_update = version.parse(latest_version) > version.parse(installed_version)
            except:
                # Fallback to string comparison if packaging is not available
                has_update = latest_version != installed_version
        
        return {
            'installed': installed_version,
            'latest': latest_version,
            'is_installed': installed_version is not None,
            'has_update': has_update
        }
    
    def uninstall_mcp_package(self, package_name: str) -> Tuple[bool, str]:
        """Uninstall an MCP package globally using npm"""
        try:
            import platform
            is_windows = platform.system() == "Windows"
            
            result = subprocess.run(
                ['npm', 'uninstall', '-g', package_name],
                capture_output=True,
                text=True,
                timeout=120,
                shell=is_windows  # Required on Windows to find npm in PATH
            )
            
            if result.returncode == 0:
                return True, f"Successfully uninstalled {package_name}"
            else:
                error_msg = result.stderr if result.stderr else "Unknown error during uninstall"
                return False, f"Uninstall failed: {error_msg}"
                
        except subprocess.TimeoutExpired:
            return False, "Uninstall operation timed out"
        except Exception as e:
            return False, f"Uninstall error: {str(e)}"
    
    def _find_available_port(self) -> int:
        """Find an available port starting from base_port"""
        import socket
        
        port = self.base_port
        while True:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.bind(('', port))
                    return port
            except OSError:
                port += 1
                if port > self.base_port + 100:  # Limit search range
                    raise Exception("No available ports found")
    
    def cleanup_dead_processes(self):
        """Clean up any dead server processes"""
        dead_servers = []
        
        for server_name, instance in self.running_servers.items():
            if instance.process and instance.process.poll() is not None:
                dead_servers.append(server_name)
        
        for server_name in dead_servers:
            print(f"Cleaning up dead server: {server_name}")
            self.running_servers[server_name].status = MCPServerStatus.STOPPED
            del self.running_servers[server_name]
            self.update_server_config(server_name, {'active': False})
