"""Validation utilities for configuration and input data"""

import re
import ipaddress
import socket
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urlparse
import json

class ValidationError(Exception):
    """Custom validation error"""
    pass

class ConfigValidator:
    """Validator for application configurations"""
    
    @staticmethod
    def validate_server_config(config: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """Validate MCP server configuration"""
        errors = []
        
        # Required fields
        required_fields = ['name', 'package', 'type']
        for field in required_fields:
            if field not in config:
                errors.append(f"Missing required field: {field}")
            elif not config[field] or not str(config[field]).strip():
                errors.append(f"Field '{field}' cannot be empty")
        
        # Package name validation
        if 'package' in config:
            if not ConfigValidator._validate_npm_package_name(config['package']):
                errors.append(f"Invalid npm package name: {config['package']}")
        
        # Environment variables validation
        if 'env_vars' in config and config['env_vars']:
            for env_var, value in config['env_vars'].items():
                if not ConfigValidator._validate_env_var_name(env_var):
                    errors.append(f"Invalid environment variable name: {env_var}")
        
        return len(errors) == 0, errors
    
    @staticmethod
    def validate_ollama_config(config: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """Validate Ollama configuration"""
        errors = []
        
        # Host URL validation
        if 'host' in config:
            if not ConfigValidator.validate_url(config['host']):
                errors.append(f"Invalid Ollama host URL: {config['host']}")
        
        # Model names validation
        model_fields = ['security_model', 'general_model']
        for field in model_fields:
            if field in config and config[field]:
                if not ConfigValidator._validate_model_name(config[field]):
                    errors.append(f"Invalid model name for {field}: {config[field]}")
        
        return len(errors) == 0, errors
    
    @staticmethod
    def validate_github_config(config: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """Validate GitHub configuration"""
        errors = []
        
        # Repository name validation
        if 'repo' in config:
            if not ConfigValidator._validate_github_repo(config['repo']):
                errors.append(f"Invalid GitHub repository format: {config['repo']}")
        
        # Token validation (if provided)
        if 'token' in config and config['token']:
            if not ConfigValidator._validate_github_token(config['token']):
                errors.append("Invalid GitHub token format")
        
        return len(errors) == 0, errors
    
    @staticmethod
    def validate_encryption_config(config: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """Validate encryption configuration"""
        errors = []
        
        # Password strength validation
        if 'master_password' in config:
            strength_errors = ConfigValidator._validate_password_strength(config['master_password'])
            errors.extend(strength_errors)
        
        # Key derivation iterations
        if 'iterations' in config:
            iterations = config['iterations']
            if not isinstance(iterations, int) or iterations < 10000:
                errors.append("Key derivation iterations must be at least 10,000")
        
        return len(errors) == 0, errors
    
    @staticmethod
    def validate_network_config(host: str, port: int = None) -> Tuple[bool, List[str]]:
        """Validate network configuration (host and port)"""
        errors = []
        
        # Host validation
        if not ConfigValidator.validate_hostname(host) and not ConfigValidator.validate_ip_address(host):
            errors.append(f"Invalid host: {host}")
        
        # Port validation
        if port is not None:
            if not ConfigValidator.validate_port(port):
                errors.append(f"Invalid port: {port}")
        
        return len(errors) == 0, errors
    
    @staticmethod
    def validate_url(url: str) -> bool:
        """Validate URL format"""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False
    
    @staticmethod
    def validate_hostname(hostname: str) -> bool:
        """Validate hostname format"""
        if len(hostname) > 255:
            return False
        
        # Allow localhost
        if hostname.lower() in ['localhost', 'localhost.localdomain']:
            return True
        
        # Regular hostname validation
        hostname_pattern = r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*$'
        return bool(re.match(hostname_pattern, hostname))
    
    @staticmethod
    def validate_ip_address(ip: str) -> bool:
        """Validate IP address (IPv4 or IPv6)"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def validate_port(port: int) -> bool:
        """Validate port number"""
        return isinstance(port, int) and 1 <= port <= 65535
    
    @staticmethod
    def validate_email(email: str) -> bool:
        """Validate email address format"""
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(email_pattern, email))
    
    @staticmethod
    def validate_json(json_string: str) -> Tuple[bool, Optional[str]]:
        """Validate JSON format"""
        try:
            json.loads(json_string)
            return True, None
        except json.JSONDecodeError as e:
            return False, str(e)
    
    @staticmethod
    def _validate_npm_package_name(package_name: str) -> bool:
        """Validate npm package name format"""
        # NPM package name rules
        if not package_name or len(package_name) > 214:
            return False
        
        # Cannot start with dot or underscore
        if package_name.startswith('.') or package_name.startswith('_'):
            return False
        
        # Can contain lowercase letters, numbers, hyphens, dots, and forward slashes (for scoped packages)
        package_pattern = r'^(@[a-z0-9-~][a-z0-9-._~]*/)?[a-z0-9-~][a-z0-9-._~]*$'
        return bool(re.match(package_pattern, package_name.lower()))
    
    @staticmethod
    def _validate_env_var_name(var_name: str) -> bool:
        """Validate environment variable name"""
        # Environment variable names should contain only letters, numbers, and underscores
        # and should not start with a number
        env_var_pattern = r'^[A-Za-z_][A-Za-z0-9_]*$'
        return bool(re.match(env_var_pattern, var_name))
    
    @staticmethod
    def _validate_model_name(model_name: str) -> bool:
        """Validate AI model name format"""
        # Model names can contain letters, numbers, dots, hyphens, underscores, and forward slashes
        if not model_name:
            return False
        
        model_pattern = r'^[a-zA-Z0-9._/-]+$'
        return bool(re.match(model_pattern, model_name))
    
    @staticmethod
    def _validate_github_repo(repo: str) -> bool:
        """Validate GitHub repository format (username/repo)"""
        repo_pattern = r'^[a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+$'
        return bool(re.match(repo_pattern, repo))
    
    @staticmethod
    def _validate_github_token(token: str) -> bool:
        """Validate GitHub token format"""
        # GitHub tokens are typically 40 characters of alphanumeric + underscore
        # Classic tokens start with 'ghp_', fine-grained tokens start with 'github_pat_'
        if not token:
            return False
        
        # Check for known GitHub token formats
        if token.startswith('ghp_') or token.startswith('github_pat_'):
            return len(token) >= 30
        
        # Legacy token format (40 hex characters)
        if len(token) == 40:
            return bool(re.match(r'^[a-f0-9]{40}$', token))
        
        return False
    
    @staticmethod
    def _validate_password_strength(password: str) -> List[str]:
        """Validate password strength and return list of errors"""
        errors = []
        
        if not password:
            errors.append("Password cannot be empty")
            return errors
        
        if len(password) < 8:
            errors.append("Password must be at least 8 characters long")
        
        if len(password) > 128:
            errors.append("Password cannot be longer than 128 characters")
        
        # Character type requirements
        has_lower = bool(re.search(r'[a-z]', password))
        has_upper = bool(re.search(r'[A-Z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
        
        character_types = sum([has_lower, has_upper, has_digit, has_special])
        
        if character_types < 3:
            errors.append("Password must contain at least 3 of the following: lowercase letters, uppercase letters, numbers, special characters")
        
        # Check for common weak passwords
        weak_passwords = [
            'password', 'password123', '123456', '123456789', 'qwerty',
            'abc123', 'password1', 'admin', 'root', 'user'
        ]
        
        if password.lower() in weak_passwords:
            errors.append("Password is too common or weak")
        
        return errors

class DataSanitizer:
    """Sanitizer for user input data"""
    
    @staticmethod
    def sanitize_string(value: str, max_length: int = None, allow_html: bool = False) -> str:
        """Sanitize string input"""
        if not isinstance(value, str):
            value = str(value)
        
        # Remove null bytes
        value = value.replace('\x00', '')
        
        # Trim whitespace
        value = value.strip()
        
        # Truncate if max length specified
        if max_length and len(value) > max_length:
            value = value[:max_length]
        
        # Remove HTML tags if not allowed
        if not allow_html:
            value = re.sub(r'<[^>]+>', '', value)
        
        return value
    
    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """Sanitize filename to prevent path traversal"""
        if not filename:
            return "unnamed_file"
        
        # Remove or replace dangerous characters
        filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
        
        # Remove path separators and relative path components
        filename = filename.replace('..', '_').replace('/', '_').replace('\\', '_')
        
        # Limit length
        if len(filename) > 255:
            name, ext = filename.rsplit('.', 1) if '.' in filename else (filename, '')
            max_name_len = 255 - len(ext) - 1 if ext else 255
            filename = name[:max_name_len] + ('.' + ext if ext else '')
        
        # Ensure it's not empty after sanitization
        if not filename or filename.isspace():
            filename = "sanitized_file"
        
        return filename
    
    @staticmethod
    def sanitize_json_input(json_string: str) -> str:
        """Sanitize JSON input"""
        try:
            # Parse and re-serialize to remove any malicious formatting
            parsed = json.loads(json_string)
            return json.dumps(parsed, separators=(',', ':'))
        except json.JSONDecodeError:
            return "{}"
    
    @staticmethod
    def sanitize_env_var_value(value: str) -> str:
        """Sanitize environment variable value"""
        if not isinstance(value, str):
            value = str(value)
        
        # Remove null bytes and control characters
        value = ''.join(char for char in value if ord(char) >= 32 or char in '\t\n\r')
        
        # Trim whitespace
        value = value.strip()
        
        return value

class NetworkValidator:
    """Network-specific validation utilities"""
    
    @staticmethod
    def is_port_open(host: str, port: int, timeout: int = 5) -> bool:
        """Check if a port is open on a host"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except:
            return False
    
    @staticmethod
    def resolve_hostname(hostname: str) -> Optional[str]:
        """Resolve hostname to IP address"""
        try:
            return socket.gethostbyname(hostname)
        except socket.gaierror:
            return None
    
    @staticmethod
    def validate_network_connectivity(host: str, port: int = None) -> Dict[str, Any]:
        """Comprehensive network connectivity validation"""
        result = {
            "host": host,
            "resolvable": False,
            "ip_address": None,
            "port_open": None,
            "response_time": None,
            "error": None
        }
        
        try:
            # Resolve hostname
            import time
            start_time = time.time()
            ip_address = NetworkValidator.resolve_hostname(host)
            resolve_time = time.time() - start_time
            
            if ip_address:
                result["resolvable"] = True
                result["ip_address"] = ip_address
                result["response_time"] = resolve_time
                
                # Check port if specified
                if port:
                    result["port_open"] = NetworkValidator.is_port_open(host, port)
            else:
                result["error"] = "Hostname resolution failed"
                
        except Exception as e:
            result["error"] = str(e)
        
        return result
