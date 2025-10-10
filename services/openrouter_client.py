"""OpenRouter client for LLM integration"""

import requests
import json
from typing import Dict, List, Optional, Any, Generator
import os

class OpenRouterClient:
    """Client for interacting with OpenRouter API"""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("OPENROUTER_API_KEY", "")
        self.base_url = "https://openrouter.ai/api/v1"
        self.security_model = "anthropic/claude-3.5-sonnet"  # Default security model
        self.general_model = "anthropic/claude-3.5-sonnet"  # Default general model
        self.timeout = 60
        self.session = requests.Session()
        self._model_metadata_cache = {}  # Cache for model context windows and metadata
        
    def check_connection(self) -> bool:
        """Check if OpenRouter API is accessible and API key is valid"""
        if not self.api_key:
            return False
            
        try:
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            
            response = self.session.get(
                f"{self.base_url}/models",
                headers=headers,
                timeout=self.timeout
            )
            return response.status_code == 200
        except Exception as e:
            print(f"OpenRouter connection check failed: {str(e)}")
            return False
    
    def list_models(self) -> List[Dict[str, Any]]:
        """Get list of available models from OpenRouter"""
        try:
            headers = {}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            
            response = self.session.get(
                f"{self.base_url}/models",
                headers=headers,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                data = response.json()
                models = []
                for model in data.get('data', []):
                    models.append({
                        'id': model.get('id', ''),
                        'name': model.get('name', ''),
                        'description': model.get('description', ''),
                        'context_length': model.get('context_length', 0),
                        'pricing': model.get('pricing', {}),
                        'architecture': model.get('architecture', {})
                    })
                return models
            else:
                print(f"Failed to list models: {response.status_code}")
                return []
                
        except Exception as e:
            print(f"Error listing models: {str(e)}")
            return []
    
    def get_model_names(self) -> List[str]:
        """Get list of model IDs/names"""
        models = self.list_models()
        return [model['id'] for model in models]
    
    def model_exists(self, model_name: str) -> bool:
        """Check if a specific model is available"""
        try:
            model_names = self.get_model_names()
            return model_name in model_names
        except:
            return False
    
    def get_model_metadata(self, model_id: str) -> Optional[Dict[str, Any]]:
        """Get metadata for a specific model including context window size
        
        Args:
            model_id: The model ID (e.g., 'google/gemini-2.5-flash-lite')
            
        Returns:
            Dictionary with model metadata including context_length, or None if not found
        """
        # Check cache first
        if model_id in self._model_metadata_cache:
            return self._model_metadata_cache[model_id]
        
        # Fetch from API
        models = self.list_models()
        for model in models:
            if model['id'] == model_id:
                self._model_metadata_cache[model_id] = model
                return model
        
        print(f"[OpenRouter] Model '{model_id}' not found in available models")
        return None
    
    def get_model_context_window(self, model_id: str) -> int:
        """Get context window size for a specific model
        
        Args:
            model_id: The model ID (e.g., 'google/gemini-2.5-flash-lite')
            
        Returns:
            Context window size in tokens (default 4000 if not found)
        """
        metadata = self.get_model_metadata(model_id)
        if metadata and 'context_length' in metadata:
            context_window = metadata['context_length']
            print(f"[OpenRouter] Model '{model_id}' context window: {context_window:,} tokens")
            return context_window
        
        # Default fallback
        print(f"[OpenRouter] Using default context window (200000) for model '{model_id}'")
        return 200000  # Default to Claude 3.5 Sonnet's context
    
    def calculate_max_tokens(self, model_id: str, input_length: int = 0) -> int:
        """Calculate appropriate max_tokens for response based on model's context window
        
        Args:
            model_id: The model ID
            input_length: Estimated input length in tokens (optional)
            
        Returns:
            Recommended max_tokens for the response (guaranteed <= context_window and API limits)
        """
        context_window = self.get_model_context_window(model_id)
        
        # Safety margin to prevent context overflow
        SAFETY_MARGIN = 100
        
        # OpenRouter API practical limit - conservative cap for stability
        # Even for large context models, this prevents API errors and timeouts
        # Note: Some models/APIs may reject large max_tokens even if model supports it
        API_MAX_TOKENS_LIMIT = 8000
        
        if input_length > 0:
            # If we know input length, calculate remaining space
            remaining = context_window - input_length - SAFETY_MARGIN
            
            # If no space left, return 0
            if remaining <= 0:
                print(f"[OpenRouter] Warning: Input length ({input_length}) exceeds context window ({context_window})")
                return 0
            
            # For very large context windows (>100K), allow up to 30% of total for output
            # For smaller windows, allow up to 50% of remaining space
            if context_window > 100000:
                max_output = min(remaining, int(context_window * 0.3))
            else:
                max_output = min(remaining, int(remaining * 0.5))
            
            # Ensure we stay within remaining capacity (critical!)
            max_output = min(max_output, remaining)
            
        else:
            # Conservative estimate when input length unknown
            # For large context models (>100K), use 20% of context for output
            # For smaller models, use 25% of context for output
            if context_window > 100000:
                max_output = int(context_window * 0.2)
            else:
                max_output = int(context_window * 0.25)
        
        # CRITICAL: Cap at OpenRouter API limit to prevent JSON parsing errors
        # Even though models support huge contexts, APIs have practical limits
        max_output = min(max_output, API_MAX_TOKENS_LIMIT)
        
        # For very small outputs, use a minimum of 1000 tokens if possible
        # But NEVER exceed available space or API limits
        if max_output < 1000:
            # Only increase to 1000 if we have the space
            if input_length > 0:
                # We know exact space - use only what's available
                return max(max_output, 0)
            else:
                # Unknown input - safe to aim for 1000 if context allows
                return min(max_output, 1000)
        
        return max_output
    
    def generate_response_with_history(self,
                                     messages: list,
                                     model: Optional[str] = None,
                                     max_tokens: Optional[int] = None,
                                     temperature: float = 0.7) -> Optional[str]:
        """Generate a response with conversation history
        
        Args:
            messages: List of message dicts with 'role' and 'content'
            model: Model ID to use
            max_tokens: Maximum tokens for response
            temperature: Temperature for response generation
            
        Returns:
            Generated response text, or None if failed
        """
        try:
            if not self.api_key:
                print("No API key provided")
                return None
            
            # Use provided model or default
            if not model:
                model = self.security_model
            
            # Calculate max_tokens if not provided
            if max_tokens is None:
                # Estimate total input from all messages
                total_input = sum(len(msg.get('content', '')) for msg in messages)
                estimated_input_tokens = total_input // 4
                max_tokens = self.calculate_max_tokens(model, estimated_input_tokens)
            
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            
            request_data = {
                "model": model,
                "messages": messages,
                "max_tokens": max_tokens,
                "temperature": temperature
            }
            
            response = self.session.post(
                f"{self.base_url}/chat/completions",
                headers=headers,
                json=request_data,
                timeout=120
            )
            
            if response.status_code == 200:
                data = response.json()
                if 'choices' in data and len(data['choices']) > 0:
                    return data['choices'][0]['message']['content'].strip()
            
            print(f"[OpenRouter ERROR] Conversation API call failed: {response.status_code}")
            return None
            
        except Exception as e:
            print(f"[OpenRouter ERROR] generate_response_with_history failed: {e}")
            return None
    
    def generate_response(self, 
                         prompt: str, 
                         model: Optional[str] = None,
                         context: Optional[str] = None,
                         max_tokens: Optional[int] = None,
                         temperature: float = 0.7) -> Optional[str]:
        """Generate a response from the model
        
        Args:
            prompt: The prompt to send to the model
            model: Model ID (if None, auto-selects based on prompt)
            context: Optional context/system message
            max_tokens: Maximum tokens for response (if None, auto-calculated from model's context window)
            temperature: Temperature for response generation
            
        Returns:
            Generated response text, or None if failed
        """
        try:
            if not self.api_key:
                print("No API key provided")
                return None
            
            # Use security model if context suggests security analysis
            if not model:
                security_keywords = ['security', 'threat', 'vulnerability', 'attack', 'breach', 'malware', 'firewall', 'policy']
                if any(keyword in prompt.lower() for keyword in security_keywords):
                    model = self.security_model
                else:
                    model = self.general_model
            
            # Build messages
            messages = []
            if context:
                messages.append({
                    "role": "system",
                    "content": f"Context: {context}"
                })
            
            messages.append({
                "role": "user",
                "content": prompt
            })
            
            # Calculate max_tokens based on model's context window if not provided
            if max_tokens is None:
                # Estimate input length (rough: 4 chars per token)
                input_text = prompt + (context or "")
                estimated_input_tokens = len(input_text) // 4
                max_tokens = self.calculate_max_tokens(model, estimated_input_tokens)
                print(f"[OpenRouter] Auto-calculated max_tokens={max_tokens} for model '{model}'")
            
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            
            request_data = {
                "model": model,
                "messages": messages,
                "max_tokens": max_tokens,
                "temperature": temperature
            }
            
            response = self.session.post(
                f"{self.base_url}/chat/completions",
                headers=headers,
                json=request_data,
                timeout=120
            )
            
            # Debug: Always log response status and basic info
            print(f"[OpenRouter] Response status: {response.status_code}")
            print(f"[OpenRouter] Response content length: {len(response.text)} bytes")
            
            if response.status_code == 200:
                # Debug: Show actual response content
                print(f"[OpenRouter] Response text repr: {repr(response.text[:500])}")
                
                # Check if response is actually empty
                if not response.text or len(response.text.strip()) == 0:
                    print(f"[OpenRouter ERROR] API returned 200 but response body is empty!")
                    print(f"[OpenRouter ERROR] Response headers: {dict(response.headers)}")
                    print(f"[OpenRouter ERROR] This usually means the API timed out or rejected the request")
                    print(f"[OpenRouter ERROR] Request details: model={model}, max_tokens={max_tokens}")
                    return None
                
                try:
                    data = response.json()
                    
                    # Check if response contains an error instead of choices
                    if 'error' in data:
                        print(f"[OpenRouter ERROR] API returned error: {data['error']}")
                        print(f"[OpenRouter ERROR] Full response: {response.text}")
                        return None
                    
                    # Check if choices exist
                    if 'choices' not in data or len(data.get('choices', [])) == 0:
                        print(f"[OpenRouter ERROR] Response missing 'choices' field")
                        print(f"[OpenRouter ERROR] Response keys: {list(data.keys())}")
                        print(f"[OpenRouter ERROR] Full response: {response.text[:1000]}")
                        return None
                    
                    return data['choices'][0]['message']['content'].strip()
                except json.JSONDecodeError as json_err:
                    print(f"[OpenRouter ERROR] JSON parsing error: {str(json_err)}")
                    print(f"[OpenRouter ERROR] This often happens with very large contexts or model timeouts")
                    print(f"[OpenRouter ERROR] Raw response (first 1000 chars): {response.text[:1000]}")
                    print(f"[OpenRouter ERROR] Response headers: {dict(response.headers)}")
                    print(f"[OpenRouter ERROR] Request: model={model}, max_tokens={max_tokens}, temp={temperature}")
                    return None  # Return None to trigger standard error handling
                except (KeyError, IndexError) as e:
                    print(f"[OpenRouter ERROR] Unexpected response structure: {str(e)}")
                    print(f"[OpenRouter ERROR] Response data: {response.text[:500]}")
                    return None  # Return None to trigger standard error handling
            else:
                print(f"Generation failed: {response.status_code} - {response.text}")
                return None
                
        except Exception as e:
            print(f"Error generating response: {str(e)}")
            print(f"Exception type: {type(e).__name__}")
            import traceback
            traceback.print_exc()
            return None
    
    def generate_streaming_response(self, 
                                   prompt: str, 
                                   model: Optional[str] = None,
                                   context: Optional[str] = None,
                                   max_tokens: Optional[int] = None,
                                   temperature: float = 0.7) -> Generator[str, None, None]:
        """Generate a streaming response from the model
        
        Args:
            prompt: The prompt to send to the model
            model: Model ID (if None, auto-selects based on prompt)
            context: Optional context/system message
            max_tokens: Maximum tokens for response (if None, auto-calculated from model's context window)
            temperature: Temperature for response generation
            
        Yields:
            Chunks of generated response text
        """
        try:
            if not self.api_key:
                yield "Error: No API key provided"
                return
            
            # Use security model if context suggests security analysis
            if not model:
                security_keywords = ['security', 'threat', 'vulnerability', 'attack', 'breach', 'malware', 'firewall', 'policy']
                if any(keyword in prompt.lower() for keyword in security_keywords):
                    model = self.security_model
                else:
                    model = self.general_model
            
            # Build messages
            messages = []
            if context:
                messages.append({
                    "role": "system",
                    "content": f"Context: {context}"
                })
            
            messages.append({
                "role": "user",
                "content": prompt
            })
            
            # Calculate max_tokens based on model's context window if not provided
            if max_tokens is None:
                # Estimate input length (rough: 4 chars per token)
                input_text = prompt + (context or "")
                estimated_input_tokens = len(input_text) // 4
                max_tokens = self.calculate_max_tokens(model, estimated_input_tokens)
                print(f"[OpenRouter] Auto-calculated max_tokens={max_tokens} for streaming with model '{model}'")
            
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            
            request_data = {
                "model": model,
                "messages": messages,
                "max_tokens": max_tokens,
                "temperature": temperature,
                "stream": True
            }
            
            response = self.session.post(
                f"{self.base_url}/chat/completions",
                headers=headers,
                json=request_data,
                timeout=120,
                stream=True
            )
            
            # Debug: Log response status for streaming
            print(f"[OpenRouter Streaming] Response status: {response.status_code}")
            
            if response.status_code == 200:
                for line in response.iter_lines():
                    if line:
                        line_str = line.decode('utf-8')
                        if line_str.startswith('data: '):
                            data_str = line_str[6:]
                            if data_str == '[DONE]':
                                break
                            try:
                                data = json.loads(data_str)
                                if 'choices' in data and len(data['choices']) > 0:
                                    delta = data['choices'][0].get('delta', {})
                                    if 'content' in delta:
                                        yield delta['content']
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
                temperature=0.3
            )
            
        except Exception as e:
            print(f"Security analysis error: {str(e)}")
            return None
    
    def troubleshoot_issue(self, issue_description: str, system_info: Optional[Dict[str, Any]] = None) -> Optional[str]:
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
