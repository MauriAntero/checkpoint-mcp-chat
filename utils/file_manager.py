"""File management utilities for configuration and data handling"""

import json
import yaml
import os
import shutil
from pathlib import Path
from typing import Dict, Any, List, Optional, Union
import time
import tempfile
from datetime import datetime

class FileManager:
    """Manages application files, configurations, and data storage"""
    
    def __init__(self, base_dir: Path = Path(".")):
        self.base_dir = base_dir
        self.config_dir = base_dir / "config"
        self.data_dir = base_dir / "data"
        self.backup_dir = base_dir / "backups"
        self.logs_dir = base_dir / "logs"
        
        # Create directories
        for directory in [self.config_dir, self.data_dir, self.backup_dir, self.logs_dir]:
            directory.mkdir(parents=True, exist_ok=True)
        
        self.config_file = self.config_dir / "app_config.json"
        self.activity_log_file = self.logs_dir / "activity.log"
    
    def save_config(self, config_data: Dict[str, Any]) -> bool:
        """Save application configuration"""
        try:
            config_data['updated_at'] = time.time()
            config_data['version'] = "1.0"
            
            with open(self.config_file, 'w') as f:
                json.dump(config_data, f, indent=2)
            
            self.log_activity(f"Configuration saved")
            return True
            
        except Exception as e:
            self.log_activity(f"Configuration save failed: {str(e)}")
            return False
    
    def load_config(self) -> Optional[Dict[str, Any]]:
        """Load application configuration"""
        try:
            if not self.config_file.exists():
                return None
            
            with open(self.config_file, 'r') as f:
                config_data = json.load(f)
            
            return config_data
            
        except Exception as e:
            self.log_activity(f"Configuration load failed: {str(e)}")
            return None
    
    def config_exists(self) -> bool:
        """Check if configuration file exists"""
        return self.config_file.exists()
    
    def check_config_health(self) -> bool:
        """Check configuration file health"""
        try:
            if not self.config_exists():
                return False
            
            config = self.load_config()
            if not config:
                return False
            
            # Check for required fields
            required_fields = ['ollama_host', 'security_model', 'general_model']
            for field in required_fields:
                if field not in config:
                    return False
            
            return True
            
        except Exception:
            return False
    
    def backup_config(self, backup_name: Optional[str] = None) -> bool:
        """Create backup of current configuration"""
        try:
            if not self.config_exists():
                return False
            
            if not backup_name:
                backup_name = f"config_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            
            backup_path = self.backup_dir / backup_name
            shutil.copy2(self.config_file, backup_path)
            
            self.log_activity(f"Configuration backed up to {backup_name}")
            return True
            
        except Exception as e:
            self.log_activity(f"Configuration backup failed: {str(e)}")
            return False
    
    def restore_config(self, backup_name: str) -> bool:
        """Restore configuration from backup"""
        try:
            backup_path = self.backup_dir / backup_name
            
            if not backup_path.exists():
                return False
            
            # Backup current config before restore
            self.backup_config("pre_restore_backup.json")
            
            # Restore from backup
            shutil.copy2(backup_path, self.config_file)
            
            self.log_activity(f"Configuration restored from {backup_name}")
            return True
            
        except Exception as e:
            self.log_activity(f"Configuration restore failed: {str(e)}")
            return False
    
    def list_backups(self) -> List[Dict[str, Any]]:
        """List available configuration backups"""
        try:
            backups = []
            
            for backup_file in self.backup_dir.glob("*.json"):
                stat = backup_file.stat()
                backups.append({
                    "name": backup_file.name,
                    "path": str(backup_file),
                    "size": stat.st_size,
                    "created": datetime.fromtimestamp(stat.st_ctime).strftime('%Y-%m-%d %H:%M:%S'),
                    "modified": datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                })
            
            # Sort by creation time, newest first
            backups.sort(key=lambda x: x['created'], reverse=True)
            return backups
            
        except Exception as e:
            self.log_activity(f"Backup listing failed: {str(e)}")
            return []
    
    def save_server_credentials(self, server_name: str, credentials: Dict[str, str], encryption_service) -> bool:
        """Save encrypted server credentials"""
        try:
            if not encryption_service.is_initialized():
                return False
            
            credentials_file = self.data_dir / f"{server_name}_credentials.enc"
            
            # Add metadata
            credential_data = {
                'server_name': server_name,
                'credentials': credentials,
                'created_at': time.time(),
                'updated_at': time.time()
            }
            
            success = encryption_service.encrypt_file(credentials_file, credential_data)
            
            if success:
                self.log_activity(f"Credentials saved for server: {server_name}")
            
            return success
            
        except Exception as e:
            self.log_activity(f"Credential save failed for {server_name}: {str(e)}")
            return False
    
    def load_server_credentials(self, server_name: str, encryption_service) -> Optional[Dict[str, str]]:
        """Load decrypted server credentials"""
        try:
            credentials_file = self.data_dir / f"{server_name}_credentials.enc"
            
            if not credentials_file.exists():
                return None
            
            credential_data = encryption_service.decrypt_file(credentials_file)
            
            if credential_data and 'credentials' in credential_data:
                return credential_data['credentials']
            
            return None
            
        except Exception as e:
            self.log_activity(f"Credential load failed for {server_name}: {str(e)}")
            return None
    
    def delete_server_credentials(self, server_name: str) -> bool:
        """Delete server credentials file"""
        try:
            credentials_file = self.data_dir / f"{server_name}_credentials.enc"
            
            if credentials_file.exists():
                credentials_file.unlink()
                self.log_activity(f"Credentials deleted for server: {server_name}")
            
            return True
            
        except Exception as e:
            self.log_activity(f"Credential deletion failed for {server_name}: {str(e)}")
            return False
    
    def save_openrouter_key(self, api_key: str, encryption_service) -> bool:
        """Save encrypted OpenRouter API key"""
        try:
            if not encryption_service.is_initialized():
                return False
            
            credentials_file = Path("./secrets/openrouter_key.enc")
            
            # Add metadata
            credential_data = {
                'api_key': api_key,
                'created_at': time.time(),
                'updated_at': time.time()
            }
            
            success = encryption_service.encrypt_file(credentials_file, credential_data)
            
            if success:
                self.log_activity("OpenRouter API key saved (encrypted)")
            
            return success
            
        except Exception as e:
            self.log_activity(f"OpenRouter API key save failed: {str(e)}")
            return False
    
    def load_openrouter_key(self, encryption_service) -> Optional[str]:
        """Load decrypted OpenRouter API key"""
        try:
            credentials_file = Path("./secrets/openrouter_key.enc")
            
            if not credentials_file.exists():
                return None
            
            credential_data = encryption_service.decrypt_file(credentials_file)
            
            if credential_data and 'api_key' in credential_data:
                return credential_data['api_key']
            
            return None
            
        except Exception as e:
            self.log_activity(f"OpenRouter API key load failed: {str(e)}")
            return None
    
    def delete_openrouter_key(self) -> bool:
        """Delete OpenRouter API key file"""
        try:
            credentials_file = Path("./secrets/openrouter_key.enc")
            
            if credentials_file.exists():
                credentials_file.unlink()
                self.log_activity("OpenRouter API key deleted")
            
            return True
            
        except Exception as e:
            self.log_activity(f"OpenRouter API key deletion failed: {str(e)}")
            return False
    
    def export_configuration(self, include_credentials: bool = False, encryption_service=None) -> Optional[Dict[str, Any]]:
        """Export complete configuration"""
        try:
            export_data = {
                'export_timestamp': time.time(),
                'export_version': '1.0',
                'config': self.load_config(),
                'servers': {},
                'metadata': {
                    'include_credentials': include_credentials,
                    'total_servers': 0
                }
            }
            
            if not export_data['config']:
                return None
            
            # Load server configurations
            server_configs = {}
            for config_file in self.data_dir.glob("*_config.json"):
                server_name = config_file.stem.replace('_config', '')
                try:
                    with open(config_file, 'r') as f:
                        server_configs[server_name] = json.load(f)
                except:
                    continue
            
            export_data['servers'] = server_configs
            export_data['metadata']['total_servers'] = len(server_configs)
            
            # Include credentials if requested and encryption is available
            if include_credentials and encryption_service and encryption_service.is_initialized():
                credentials_data = {}
                for cred_file in self.data_dir.glob("*_credentials.enc"):
                    server_name = cred_file.stem.replace('_credentials', '')
                    creds = self.load_server_credentials(server_name, encryption_service)
                    if creds:
                        credentials_data[server_name] = creds
                
                export_data['credentials'] = credentials_data
            
            self.log_activity("Configuration exported")
            return export_data
            
        except Exception as e:
            self.log_activity(f"Configuration export failed: {str(e)}")
            return None
    
    def import_configuration(self, import_data: Dict[str, Any], encryption_service=None) -> bool:
        """Import complete configuration"""
        try:
            # Validate import data
            if 'config' not in import_data:
                return False
            
            # Backup current configuration
            self.backup_config("pre_import_backup.json")
            
            # Import main configuration
            if not self.save_config(import_data['config']):
                return False
            
            # Import server configurations
            if 'servers' in import_data:
                for server_name, server_config in import_data['servers'].items():
                    server_config_file = self.data_dir / f"{server_name}_config.json"
                    with open(server_config_file, 'w') as f:
                        json.dump(server_config, f, indent=2)
            
            # Import credentials if available and encryption is initialized
            if ('credentials' in import_data and 
                encryption_service and 
                encryption_service.is_initialized()):
                
                for server_name, credentials in import_data['credentials'].items():
                    self.save_server_credentials(server_name, credentials, encryption_service)
            
            self.log_activity("Configuration imported successfully")
            return True
            
        except Exception as e:
            self.log_activity(f"Configuration import failed: {str(e)}")
            return False
    
    def save_yaml_config(self, file_path: Union[str, Path], data: Dict[str, Any]) -> bool:
        """Save data as YAML file"""
        try:
            file_path = Path(file_path)
            file_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(file_path, 'w') as f:
                yaml.dump(data, f, default_flow_style=False, indent=2)
            
            self.log_activity(f"YAML config saved: {file_path}")
            return True
            
        except Exception as e:
            self.log_activity(f"YAML config save failed: {str(e)}")
            return False
    
    def load_yaml_config(self, file_path: Union[str, Path]) -> Optional[Dict[str, Any]]:
        """Load YAML configuration file"""
        try:
            file_path = Path(file_path)
            
            if not file_path.exists():
                return None
            
            with open(file_path, 'r') as f:
                return yaml.safe_load(f)
                
        except Exception as e:
            self.log_activity(f"YAML config load failed: {str(e)}")
            return None
    
    def create_env_file(self, env_vars: Dict[str, str], file_path: Optional[Union[str, Path]] = None) -> bool:
        """Create .env file with environment variables"""
        try:
            if not file_path:
                file_path = self.base_dir / ".env"
            else:
                file_path = Path(file_path)
            
            file_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(file_path, 'w') as f:
                f.write("# CheckPoint MCP Manager Environment Variables\n")
                f.write(f"# Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                for key, value in env_vars.items():
                    # Escape special characters in values
                    if ' ' in value or '"' in value or "'" in value:
                        value = f'"{value.replace(chr(34), chr(92) + chr(34))}"'
                    f.write(f"{key}={value}\n")
            
            self.log_activity(f"Environment file created: {file_path}")
            return True
            
        except Exception as e:
            self.log_activity(f"Environment file creation failed: {str(e)}")
            return False
    
    def cleanup_old_files(self, days_old: int = 30) -> int:
        """Clean up old backup and log files"""
        try:
            cleaned_count = 0
            cutoff_time = time.time() - (days_old * 24 * 3600)
            
            # Clean old backups
            for backup_file in self.backup_dir.glob("*.json"):
                if backup_file.stat().st_mtime < cutoff_time:
                    backup_file.unlink()
                    cleaned_count += 1
            
            # Clean old logs
            for log_file in self.logs_dir.glob("*.log"):
                if log_file.stat().st_mtime < cutoff_time:
                    log_file.unlink()
                    cleaned_count += 1
            
            self.log_activity(f"Cleaned up {cleaned_count} old files")
            return cleaned_count
            
        except Exception as e:
            self.log_activity(f"Cleanup failed: {str(e)}")
            return 0
    
    def get_disk_usage(self) -> Dict[str, Any]:
        """Get disk usage statistics for application directories"""
        try:
            usage_stats = {}
            
            for dir_name, dir_path in [
                ("config", self.config_dir),
                ("data", self.data_dir),
                ("backups", self.backup_dir),
                ("logs", self.logs_dir)
            ]:
                total_size = 0
                file_count = 0
                
                for file_path in dir_path.rglob("*"):
                    if file_path.is_file():
                        total_size += file_path.stat().st_size
                        file_count += 1
                
                usage_stats[dir_name] = {
                    "size_bytes": total_size,
                    "size_mb": round(total_size / (1024 * 1024), 2),
                    "file_count": file_count,
                    "path": str(dir_path)
                }
            
            return usage_stats
            
        except Exception as e:
            self.log_activity(f"Disk usage calculation failed: {str(e)}")
            return {}
    
    def log_activity(self, message: str, level: str = "INFO") -> bool:
        """Log activity message"""
        try:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            log_entry = f"[{timestamp}] [{level}] {message}\n"
            
            with open(self.activity_log_file, 'a') as f:
                f.write(log_entry)
            
            return True
            
        except Exception as e:
            print(f"Logging failed: {str(e)}")
            return False
    
    def get_recent_activity(self, lines: int = 50) -> List[str]:
        """Get recent activity log entries"""
        try:
            if not self.activity_log_file.exists():
                return []
            
            with open(self.activity_log_file, 'r') as f:
                all_lines = f.readlines()
            
            # Return last N lines, stripped of whitespace
            return [line.strip() for line in all_lines[-lines:] if line.strip()]
            
        except Exception as e:
            self.log_activity(f"Activity retrieval failed: {str(e)}")
            return []
    
    def create_temp_file(self, content: str, suffix: str = ".tmp") -> Optional[Path]:
        """Create temporary file with content"""
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix=suffix, delete=False) as f:
                f.write(content)
                temp_path = Path(f.name)
            
            return temp_path
            
        except Exception as e:
            self.log_activity(f"Temporary file creation failed: {str(e)}")
            return None
    
    def safe_delete_file(self, file_path: Union[str, Path]) -> bool:
        """Safely delete a file with confirmation"""
        try:
            file_path = Path(file_path)
            
            if not file_path.exists():
                return True
            
            # Move to trash/backup before permanent deletion
            backup_name = f"deleted_{int(time.time())}_{file_path.name}"
            backup_path = self.backup_dir / backup_name
            
            shutil.move(str(file_path), str(backup_path))
            self.log_activity(f"File safely deleted (backed up as {backup_name}): {file_path}")
            
            return True
            
        except Exception as e:
            self.log_activity(f"Safe file deletion failed: {str(e)}")
            return False
