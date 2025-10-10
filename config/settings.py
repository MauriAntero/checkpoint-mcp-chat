"""Application configuration settings"""

import os
from dataclasses import dataclass
from typing import Dict, List, Optional
from pathlib import Path

@dataclass
class AppConfig:
    """Main application configuration"""
    
    # Default CheckPoint MCP servers configuration
    CHECKPOINT_MCP_SERVERS: Dict[str, Dict] = None
    
    # Ollama configuration
    OLLAMA_DEFAULT_HOST: str = "http://network-host:11434"
    SECURITY_MODEL: str = "saki007ster/cybersecurityriskanalyst"
    GENERAL_MODEL: str = "llama3.1"
    
    # GitHub configuration
    GITHUB_REPO: str = "MauriAntero/checkpoint-mcp-frontend"
    
    # File paths
    DATA_DIR: Path = Path("./data")
    CONFIG_DIR: Path = Path("./config")
    SECRETS_DIR: Path = Path("./secrets")
    
    # Encryption settings
    ENCRYPTION_ALGORITHM: str = "AES"
    KEY_DERIVATION_ITERATIONS: int = 100000
    
    def __post_init__(self):
        """Initialize default MCP servers configuration"""
        if self.CHECKPOINT_MCP_SERVERS is None:
            self.CHECKPOINT_MCP_SERVERS = {
                "quantum-management": {
                    "package": "@chkp/quantum-management-mcp",
                    "description": "Query policies, rules, objects, and network topology",
                    "type": "Management",
                    "auth_modes": ["cloud", "onprem"],
                    "env_vars": [
                        # Cloud (S1C) authentication
                        "S1C_URL",
                        "API_KEY",
                        "CLOUD_INFRA_TOKEN",
                        # On-Prem authentication
                        "MANAGEMENT_HOST",
                        "PORT",
                        "USERNAME",
                        "PASSWORD"
                    ]
                },
                "management-logs": {
                    "package": "@chkp/management-logs-mcp",
                    "description": "Make queries and gain insights from connection and audit logs",
                    "type": "Logs",
                    "auth_modes": ["cloud", "onprem"],
                    "env_vars": [
                        # Cloud (S1C) authentication
                        "S1C_URL",
                        "API_KEY",
                        # On-Prem authentication
                        "MANAGEMENT_HOST",
                        "PORT",
                        "USERNAME",
                        "PASSWORD"
                    ]
                },
                "threat-prevention": {
                    "package": "@chkp/threat-prevention-mcp",
                    "description": "Query Threat Prevention policies, profiles and indicators",
                    "type": "Threat Prevention",
                    "auth_modes": ["cloud", "onprem"],
                    "env_vars": [
                        # Cloud (S1C) authentication
                        "S1C_URL",
                        "API_KEY",
                        # On-Prem authentication
                        "MANAGEMENT_HOST",
                        "PORT",
                        "USERNAME",
                        "PASSWORD"
                    ]
                },
                "https-inspection": {
                    "package": "@chkp/https-inspection-mcp",
                    "description": "Query HTTPS Inspection policies, rules and exceptions",
                    "type": "HTTPS Inspection",
                    "auth_modes": ["cloud", "onprem"],
                    "env_vars": [
                        # Cloud (S1C) authentication
                        "S1C_URL",
                        "API_KEY",
                        # On-Prem authentication
                        "MANAGEMENT_HOST",
                        "PORT",
                        "USERNAME",
                        "PASSWORD"
                    ]
                },
                "harmony-sase": {
                    "package": "@chkp/harmony-sase-mcp",
                    "description": "Query and manage Harmony SASE configurations",
                    "type": "Harmony SASE",
                    "auth_modes": ["cloud"],
                    "env_vars": [
                        "API_KEY",
                        "MANAGEMENT_HOST",
                        "ORIGIN"
                    ]
                },
                "reputation-service": {
                    "package": "@chkp/reputation-service-mcp",
                    "description": "Query URL, IP and File Reputations",
                    "type": "Reputation",
                    "auth_modes": ["cloud"],
                    "env_vars": [
                        "API_KEY"
                    ]
                },
                "quantum-gw-cli": {
                    "package": "@chkp/quantum-gw-cli-mcp",
                    "description": "Comprehensive gateway diagnostics and analysis",
                    "type": "Gateway CLI",
                    "auth_modes": ["ssh", "cloud", "onprem"],
                    "env_vars": [
                        # Gateway SSH credentials
                        "GATEWAY_HOST",
                        "SSH_USERNAME",
                        "SSH_PASSWORD",
                        "SSH_KEY",
                        # Management server credentials (same as quantum-management)
                        # Cloud (S1C) authentication
                        "S1C_URL",
                        "API_KEY",
                        "CLOUD_INFRA_TOKEN",
                        # On-Prem authentication
                        "MANAGEMENT_HOST",
                        "PORT",
                        "USERNAME",
                        "PASSWORD"
                    ]
                },
                "quantum-gw-connection-analysis": {
                    "package": "@chkp/quantum-gw-connection-analysis-mcp",
                    "description": "Debug logs for connection issue analysis",
                    "type": "Connection Analysis",
                    "auth_modes": ["ssh"],
                    "env_vars": [
                        "GATEWAY_HOST",
                        "SSH_USERNAME",
                        "SSH_PASSWORD",
                        "SSH_KEY"
                    ]
                },
                "threat-emulation": {
                    "package": "@chkp/threat-emulation-mcp",
                    "description": "Upload and analyze files for malware using CheckPoint cloud sandbox (async: upload → query → report)",
                    "type": "Threat Emulation",
                    "auth_modes": ["cloud"],
                    "env_vars": [
                        "API_KEY"
                    ]
                },
                "quantum-gaia": {
                    "package": "@chkp/quantum-gaia-mcp",
                    "description": "Network management and interface configuration for GAIA OS",
                    "type": "GAIA",
                    "auth_modes": ["ssh"],
                    "env_vars": [
                        "GATEWAY_HOST",
                        "SSH_USERNAME",
                        "SSH_PASSWORD",
                        "SSH_KEY"
                    ]
                },
                "spark-management": {
                    "package": "@chkp/spark-management-mcp",
                    "description": "Manage Quantum Spark appliances for MSPs",
                    "type": "Spark Management",
                    "auth_modes": ["cloud", "onprem"],
                    "env_vars": [
                        # Cloud authentication
                        "API_KEY",
                        # On-Prem authentication
                        "MANAGEMENT_HOST",
                        "USERNAME",
                        "PASSWORD"
                    ]
                }
            }
        
        # Ensure directories exist
        self.DATA_DIR.mkdir(parents=True, exist_ok=True)
        self.CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        self.SECRETS_DIR.mkdir(parents=True, exist_ok=True)
    
    def get_server_config(self, server_name: str) -> Optional[Dict]:
        """Get configuration for a specific MCP server"""
        return self.CHECKPOINT_MCP_SERVERS.get(server_name)
    
    def get_all_server_names(self) -> List[str]:
        """Get list of all available MCP server names"""
        return list(self.CHECKPOINT_MCP_SERVERS.keys())
    
    def get_servers_by_type(self, server_type: str) -> Dict[str, Dict]:
        """Get all servers of a specific type"""
        return {
            name: config for name, config in self.CHECKPOINT_MCP_SERVERS.items()
            if config.get("type") == server_type
        }
