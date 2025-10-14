"""Ollama client for LLM integration"""

import requests
import json
from typing import Dict, List, Optional, Any, Generator
import time
import os

class OllamaClient:
    """Client for interacting with Ollama LLM service"""
    
    def __init__(self, base_url: str = None, context_window: int = 32768):
        url = base_url or os.getenv("OLLAMA_HOST", "http://localhost:11434")
        self.base_url = self._normalize_url(url)
        self.security_model = os.getenv("SECURITY_MODEL", "saki007ster/cybersecurityriskanalyst")
        self.general_model = os.getenv("GENERAL_MODEL", "llama3.1")
        self.context_window = context_window  # User-configurable context window (4k to 128k)
        self.timeout = 30
        self.session = requests.Session()
    
    def _normalize_url(self, url: str) -> str:
        """Ensure URL has http:// or https:// protocol"""
        if not url:
            return "http://localhost:11434"
        
        url = url.strip()
        
        # If URL already has protocol, return as is
        if url.startswith(('http://', 'https://')):
            return url
        
        # Add http:// if missing
        return f"http://{url}"
    
    def get_model_context_window(self, model_id: str = None) -> int:
        """Get context window size for Ollama model
        
        Args:
            model_id: The model ID (not used for Ollama, returns configured context)
            
        Returns:
            Context window size in tokens (user-configured)
        """
        print(f"[Ollama] Model context window: {self.context_window:,} tokens")
        return self.context_window
    
    def check_connection(self) -> bool:
        """Check if Ollama service is available"""
        try:
            response = self.session.get(
                f"{self.base_url}/api/version",
                timeout=self.timeout
            )
            return response.status_code == 200
        except Exception as e:
            print(f"Ollama connection check failed: {str(e)}")
            return False
    
    def list_models(self) -> List[str]:
        """Get list of available models"""
        try:
            response = self.session.get(
                f"{self.base_url}/api/tags",
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                data = response.json()
                models = []
                for model in data.get('models', []):
                    models.append(model.get('name', ''))
                return models
            else:
                print(f"Failed to list models: {response.status_code}")
                return []
                
        except Exception as e:
            print(f"Error listing models: {str(e)}")
            return []
    
    def model_exists(self, model_name: str) -> bool:
        """Check if a specific model is available"""
        try:
            models = self.list_models()
            return any(model_name in model for model in models)
        except:
            return False
    
    def pull_model(self, model_name: str) -> bool:
        """Pull/download a model"""
        try:
            response = self.session.post(
                f"{self.base_url}/api/pull",
                json={"name": model_name},
                timeout=600,  # 10 minutes for model download
                stream=True
            )
            
            if response.status_code == 200:
                # Process streaming response
                for line in response.iter_lines():
                    if line:
                        try:
                            data = json.loads(line)
                            if data.get('status') == 'success':
                                return True
                        except json.JSONDecodeError:
                            continue
                return True
            else:
                print(f"Failed to pull model {model_name}: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"Error pulling model {model_name}: {str(e)}")
            return False
    
    def generate_response(self, 
                         prompt: str, 
                         model: str = None,
                         context: str = None,
                         max_tokens: int = 2000,
                         temperature: float = 0.7) -> Optional[str]:
        """Generate a response from the model"""
        try:
            # Use security model if context suggests security analysis
            if not model:
                security_keywords = ['security', 'threat', 'vulnerability', 'attack', 'breach', 'malware', 'firewall', 'policy']
                if any(keyword in prompt.lower() for keyword in security_keywords):
                    model = self.security_model
                else:
                    model = self.general_model
            
            # Ensure model is available
            if not self.model_exists(model):
                print(f"Model {model} not available, attempting to pull...")
                if not self.pull_model(model):
                    print(f"Failed to pull model {model}, falling back to general model")
                    model = self.general_model
            
            # Build the full prompt
            full_prompt = prompt
            if context:
                full_prompt = f"Context: {context}\n\nQuestion: {prompt}"
            
            request_data = {
                "model": model,
                "prompt": full_prompt,
                "stream": False,
                "options": {
                    "num_predict": max_tokens,
                    "temperature": temperature,
                    "num_ctx": self.context_window,  # Use user-configured context window
                }
            }
            
            response = self.session.post(
                f"{self.base_url}/api/generate",
                json=request_data,
                timeout=600  # 10 minutes for generation (local hardware needs time for large contexts)
            )
            
            if response.status_code == 200:
                data = response.json()
                return data.get('response', '').strip()
            else:
                print(f"Generation failed: {response.status_code} - {response.text}")
                return None
                
        except Exception as e:
            print(f"Error generating response: {str(e)}")
            return None
    
    def generate_streaming_response(self, 
                                   prompt: str, 
                                   model: str = None,
                                   context: str = None,
                                   max_tokens: int = 2000,
                                   temperature: float = 0.7) -> Generator[str, None, None]:
        """Generate a streaming response from the model"""
        try:
            # Use security model if context suggests security analysis
            if not model:
                security_keywords = ['security', 'threat', 'vulnerability', 'attack', 'breach', 'malware', 'firewall', 'policy']
                if any(keyword in prompt.lower() for keyword in security_keywords):
                    model = self.security_model
                else:
                    model = self.general_model
            
            # Build the full prompt
            full_prompt = prompt
            if context:
                full_prompt = f"Context: {context}\n\nQuestion: {prompt}"
            
            request_data = {
                "model": model,
                "prompt": full_prompt,
                "stream": True,
                "options": {
                    "num_predict": max_tokens,
                    "temperature": temperature,
                    "num_ctx": self.context_window,  # Use user-configured context window
                }
            }
            
            response = self.session.post(
                f"{self.base_url}/api/generate",
                json=request_data,
                timeout=600,  # 10 minutes for generation (local hardware needs time for large contexts)
                stream=True
            )
            
            if response.status_code == 200:
                for line in response.iter_lines():
                    if line:
                        try:
                            data = json.loads(line)
                            if 'response' in data:
                                yield data['response']
                            if data.get('done', False):
                                break
                        except json.JSONDecodeError:
                            continue
            else:
                yield f"Error: Generation failed with status {response.status_code}"
                
        except Exception as e:
            yield f"Error: {str(e)}"
    
    def analyze_security_data(self, data: Dict[str, Any], query: str) -> Optional[str]:
        """Analyze security data with specialized security model"""
        try:
            # Format the data for analysis
            context = f"Security Data Analysis:\n{json.dumps(data, indent=2)}"
            
            prompt = f"""
            As a cybersecurity risk analyst, analyze the following security data and answer the query.
            
            Query: {query}
            
            Please provide:
            1. Risk assessment
            2. Key findings
            3. Recommendations
            4. Priority level (High/Medium/Low)
            
            Be specific and actionable in your response.
            """
            
            return self.generate_response(
                prompt=prompt,
                model=self.security_model,
                context=context,
                temperature=0.3  # Lower temperature for more focused analysis
            )
            
        except Exception as e:
            print(f"Security analysis error: {str(e)}")
            return None
    
    def troubleshoot_issue(self, issue_description: str, system_info: Dict[str, Any] = None) -> Optional[str]:
        """Troubleshoot technical issues using general model"""
        try:
            context = ""
            if system_info:
                context = f"System Information:\n{json.dumps(system_info, indent=2)}"
            
            prompt = f"""
            As a technical troubleshooting expert for CheckPoint security systems, help resolve this issue:
            
            Issue: {issue_description}
            
            Please provide:
            1. Possible root causes
            2. Diagnostic steps
            3. Solution recommendations
            4. Prevention measures
            
            Focus on CheckPoint-specific solutions and best practices.
            """
            
            return self.generate_response(
                prompt=prompt,
                model=self.general_model,
                context=context,
                temperature=0.5
            )
            
        except Exception as e:
            print(f"Troubleshooting error: {str(e)}")
            return None
    
    def get_model_info(self, model_name: str) -> Optional[Dict[str, Any]]:
        """Get information about a specific model"""
        try:
            response = self.session.post(
                f"{self.base_url}/api/show",
                json={"name": model_name},
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                print(f"Failed to get model info: {response.status_code}")
                return None
                
        except Exception as e:
            print(f"Error getting model info: {str(e)}")
            return None
    
    def delete_model(self, model_name: str) -> bool:
        """Delete a model from Ollama"""
        try:
            response = self.session.delete(
                f"{self.base_url}/api/delete",
                json={"name": model_name},
                timeout=self.timeout
            )
            
            return response.status_code == 200
            
        except Exception as e:
            print(f"Error deleting model {model_name}: {str(e)}")
            return False
    
    def get_system_info(self) -> Optional[Dict[str, Any]]:
        """Get Ollama system information"""
        try:
            response = self.session.get(
                f"{self.base_url}/api/ps",
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                return None
                
        except Exception as e:
            print(f"Error getting system info: {str(e)}")
            return None
