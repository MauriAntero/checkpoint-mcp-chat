"""Encryption service for secure credential storage"""

import os
import base64
import json
from typing import Dict, Any, Optional
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from pathlib import Path
import secrets

class EncryptionService:
    """Service for encrypting and decrypting sensitive data"""
    
    def __init__(self, key_file_path: Path = Path("./secrets/.encryption_key")):
        self.key_file_path = key_file_path
        self.key: Optional[bytes] = None
        self.salt: Optional[bytes] = None
        
    def initialize(self, master_password: str, is_setup: bool = False) -> bool:
        """Initialize encryption with master password
        
        Args:
            master_password: The master password to use
            is_setup: True if this is initial setup, False if this is login
        """
        try:
            # Generate or load salt
            salt_file = self.key_file_path.parent / ".salt"
            
            if salt_file.exists():
                with open(salt_file, 'rb') as f:
                    self.salt = f.read()
            else:
                self.salt = os.urandom(16)
                salt_file.parent.mkdir(parents=True, exist_ok=True)
                with open(salt_file, 'wb') as f:
                    f.write(self.salt)
            
            # Derive key from password
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=self.salt,
                iterations=100000,
                backend=default_backend()
            )
            
            derived_key = kdf.derive(master_password.encode())
            
            # Password verification - verify BEFORE setting the key
            verification_file = self.key_file_path.parent / ".password_verify"
            if verification_file.exists():
                # Verification file exists - MUST verify password
                try:
                    # Temporarily set key for verification
                    self.key = derived_key
                    with open(verification_file, 'r') as f:
                        encrypted_verify = f.read().strip()
                    decrypted_data = self.decrypt_data(encrypted_verify)
                    if decrypted_data.get('verify') != 'checkpoint_mcp_chat':
                        # Clear key on failed verification
                        self.key = None
                        self.salt = None
                        return False
                except:
                    # Decryption failed - wrong password - clear key
                    self.key = None
                    self.salt = None
                    return False
            elif is_setup:
                # Setup mode - set key and create verification file
                self.key = derived_key
                verification_data = {'verify': 'checkpoint_mcp_chat'}
                encrypted_verify = self.encrypt_data(verification_data)
                verification_file.parent.mkdir(parents=True, exist_ok=True)
                with open(verification_file, 'w', encoding='utf-8') as f:
                    f.write(encrypted_verify)
            else:
                # Login attempt but no verification file - this should not happen
                # Do not set key, just reject the login for security
                return False
            
            # Save encrypted key marker
            self.key_file_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.key_file_path, 'w', encoding='utf-8') as f:
                f.write("encryption_initialized")
            
            return True
            
        except Exception as e:
            print(f"Encryption initialization failed: {str(e)}")
            return False
    
    def is_initialized(self) -> bool:
        """Check if encryption is initialized"""
        return self.key is not None and self.key_file_path.exists()
    
    def encrypt_data(self, data: Dict[str, Any]) -> str:
        """Encrypt dictionary data to base64 string"""
        if self.key is None:
            raise ValueError("Encryption service not initialized")
        
        try:
            # Convert data to JSON string
            json_data = json.dumps(data)
            plaintext = json_data.encode()
            
            # Generate random IV
            iv = os.urandom(16)
            
            # Encrypt data
            cipher = Cipher(
                algorithms.AES(self.key),
                modes.CBC(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            
            # Pad plaintext to 16-byte boundary
            pad_length = 16 - (len(plaintext) % 16)
            padded_plaintext = plaintext + bytes([pad_length] * pad_length)
            
            ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
            
            # Combine IV and ciphertext
            encrypted_data = iv + ciphertext
            
            # Return base64 encoded result
            return base64.b64encode(encrypted_data).decode()
            
        except Exception as e:
            raise ValueError(f"Encryption failed: {str(e)}")
    
    def decrypt_data(self, encrypted_string: str) -> Dict[str, Any]:
        """Decrypt base64 string to dictionary data"""
        if self.key is None:
            raise ValueError("Encryption service not initialized")
        
        try:
            # Decode from base64
            encrypted_data = base64.b64decode(encrypted_string.encode())
            
            # Extract IV and ciphertext
            iv = encrypted_data[:16]
            ciphertext = encrypted_data[16:]
            
            # Decrypt data
            cipher = Cipher(
                algorithms.AES(self.key),
                modes.CBC(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Remove padding
            pad_length = padded_plaintext[-1]
            plaintext = padded_plaintext[:-pad_length]
            
            # Convert back to dictionary
            json_string = plaintext.decode()
            return json.loads(json_string)
            
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")
    
    def encrypt_file(self, file_path: Path, data: Dict[str, Any]) -> bool:
        """Encrypt and save data to file"""
        try:
            encrypted_string = self.encrypt_data(data)
            
            file_path.parent.mkdir(parents=True, exist_ok=True)
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(encrypted_string)
            
            return True
            
        except Exception as e:
            print(f"File encryption failed: {str(e)}")
            return False
    
    def decrypt_file(self, file_path: Path) -> Optional[Dict[str, Any]]:
        """Load and decrypt data from file"""
        encrypted_string = ""
        try:
            if not file_path.exists():
                return None
            
            with open(file_path, 'r') as f:
                encrypted_string = f.read().strip()
            
            # Skip empty files silently
            if not encrypted_string:
                return None
            
            return self.decrypt_data(encrypted_string)
            
        except Exception as e:
            # Silently suppress JSON parsing errors from empty/invalid credential files
            # These happen when credential files don't exist yet or are corrupted
            error_msg = str(e)
            if "Expecting value" not in error_msg:
                # Only print non-JSON errors (actual decryption failures)
                print(f"File decryption failed: {error_msg}")
            return None
    
    def change_master_password(self, old_password: str, new_password: str) -> bool:
        """Change the master password"""
        try:
            # Verify old password by trying to initialize with it
            old_key = self.key
            old_salt = self.salt
            
            if not self.initialize(old_password):
                return False
            
            # Load all encrypted files with old password
            secrets_dir = self.key_file_path.parent
            encrypted_files = {}
            
            for file_path in secrets_dir.glob("*.enc"):
                data = self.decrypt_file(file_path)
                if data is not None:
                    encrypted_files[file_path] = data
            
            # Re-initialize with new password
            if not self.initialize(new_password):
                # Restore old key/salt on failure
                self.key = old_key
                self.salt = old_salt
                return False
            
            # Re-encrypt all files with new password
            for file_path, data in encrypted_files.items():
                if not self.encrypt_file(file_path, data):
                    return False
            
            return True
            
        except Exception as e:
            print(f"Password change failed: {str(e)}")
            return False
