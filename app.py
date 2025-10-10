import streamlit as st
import os
import time
import json
import uuid
import hashlib
from typing import Optional
from pathlib import Path
from config.settings import AppConfig
from services.encryption import EncryptionService
from services.mcp_manager import MCPManager
from services.ollama_client import OllamaClient
from services.openrouter_client import OpenRouterClient
from services.query_orchestrator import QueryOrchestrator
from utils.file_manager import FileManager

# Application version
__version__ = "0.0.1"

# Page configuration
st.set_page_config(
    page_title="Check Point MCP Chat",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Custom CSS for enhanced UI - Version 2.0
st.markdown("""
<style>
    /* Hide default Streamlit elements */
    #MainMenu {visibility: hidden !important;}
    footer {visibility: hidden !important;}
    header {visibility: hidden !important;}
    
    /* Static gradient background */
    .stApp {
        background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%) !important;
        background-attachment: fixed !important;
        max-width: 1200px !important;
        margin: 0 auto !important;
    }
    
    /* Main content area with glass effect and enhanced shadows */
    .main .block-container {
        padding: 2rem 1rem !important;
        margin: 2rem auto !important;
        background: rgba(255, 255, 255, 0.85) !important;
        backdrop-filter: blur(10px) !important;
        border-radius: 20px !important;
        border-left: 4px solid #EE0C5D !important;
        box-shadow: 
            0 15px 50px rgba(31, 38, 135, 0.25),
            0 25px 80px rgba(31, 38, 135, 0.2),
            0 5px 15px rgba(0, 0, 0, 0.12) !important;
    }
    
    /* Ensure parent allows overflow for shadows */
    .main {
        overflow: visible !important;
    }
    
    /* Chat messages with enhanced shadows and expanded width for tables */
    .stChatMessage {
        border-radius: 12px;
        padding: 16px;
        margin: 12px 0;
        background: rgba(255, 255, 255, 0.9);
        box-shadow: 
            0 4px 12px rgba(0, 0, 0, 0.08),
            0 2px 6px rgba(0, 0, 0, 0.06);
        border: 1px solid rgba(0, 0, 0, 0.05);
        transition: transform 0.3s ease, box-shadow 0.3s ease;
        max-width: 1200px !important;
    }
    
    /* Expand chat message content area for wide tables */
    .stChatMessage > div {
        max-width: 100% !important;
    }
    
    /* Make tables horizontally scrollable if they exceed container width */
    .stChatMessage table {
        display: block;
        max-width: 100%;
        overflow-x: auto;
        white-space: nowrap;
    }
    
    .stChatMessage table thead,
    .stChatMessage table tbody {
        display: table;
        width: 100%;
    }
    
    .stChatMessage:hover {
        transform: translateY(-4px);
        box-shadow: 
            0 12px 24px rgba(0, 0, 0, 0.15),
            0 6px 12px rgba(0, 0, 0, 0.1),
            0 2px 4px rgba(0, 0, 0, 0.05);
    }
    
    /* Input area with gradient and brand accent */
    .stChatInputContainer {
        border-top: 2px solid rgba(238, 12, 93, 0.2);
        padding: 20px 0;
        background: linear-gradient(to top, rgba(255, 255, 255, 0.95), rgba(255, 255, 255, 0.5) 50%, rgba(255, 255, 255, 0));
    }
    
    /* Chat input focus state */
    .stChatInput textarea:focus {
        border-color: #EE0C5D !important;
        box-shadow: 0 0 0 2px rgba(238, 12, 93, 0.2) !important;
    }
    
    /* Enhanced buttons with Check Point brand accent */
    .stButton > button,
    button[kind="primary"],
    button[type="primary"],
    div[data-testid="stButton"] > button,
    button[data-testid="baseButton-primary"],
    .stFormSubmitButton > button {
        border-radius: 8px !important;
        border: 1px solid rgba(238, 12, 93, 0.3) !important;
        padding: 10px 20px !important;
        background: linear-gradient(135deg, #EE0C5D 0%, #C10A4D 100%) !important;
        color: white !important;
        font-weight: 600 !important;
        transition: all 0.3s ease !important;
        box-shadow: 
            0 6px 16px rgba(238, 12, 93, 0.3),
            0 3px 8px rgba(0, 0, 0, 0.15),
            0 1px 3px rgba(0, 0, 0, 0.1) !important;
    }
    
    .stButton > button:hover,
    button[kind="primary"]:hover,
    button[type="primary"]:hover,
    div[data-testid="stButton"] > button:hover,
    button[data-testid="baseButton-primary"]:hover,
    .stFormSubmitButton > button:hover {
        transform: translateY(-3px) !important;
        background: linear-gradient(135deg, #FF1566 0%, #EE0C5D 100%) !important;
        box-shadow: 
            0 12px 28px rgba(238, 12, 93, 0.4),
            0 8px 16px rgba(0, 0, 0, 0.2),
            0 3px 8px rgba(0, 0, 0, 0.15) !important;
    }
    
    .stButton > button:active,
    button[kind="primary"]:active,
    button[type="primary"]:active,
    div[data-testid="stButton"] > button:active,
    button[data-testid="baseButton-primary"]:active,
    .stFormSubmitButton > button:active {
        transform: translateY(-1px) !important;
        box-shadow: 
            0 4px 12px rgba(238, 12, 93, 0.3),
            0 2px 6px rgba(0, 0, 0, 0.15) !important;
    }
    
    /* Ensure button text is always white */
    .stButton > button *,
    button[kind="primary"] *,
    button[type="primary"] *,
    .stFormSubmitButton > button *,
    button[data-testid="baseButton-primary"] * {
        color: white !important;
    }
    
    /* Title styling with Check Point brand color - Bold & Dynamic */
    h1 {
        color: #EE0C5D !important;
        font-weight: 800;
        letter-spacing: -1px;
        font-size: 2.5rem !important;
        filter: drop-shadow(0 2px 4px rgba(0, 0, 0, 0.1));
        margin-bottom: 1rem !important;
    }
    
    /* Subtitle and secondary headings */
    h2, h3 {
        font-weight: 600;
        letter-spacing: -0.3px;
        color: #1a1a1a !important;
    }
    
    /* Body text hierarchy - all text elements */
    p, div, span, label, li, td, th {
        line-height: 1.6;
        color: #1a1a1a !important;
    }
    
    p {
        font-weight: 400;
    }
    
    /* Caption text - make it bigger and darker for readability */
    .stCaption,
    [data-testid="stCaptionContainer"],
    small {
        font-size: 0.95rem !important;
        line-height: 1.5 !important;
        color: #1a1a1a !important;
        font-weight: 500 !important;
    }
    
    /* Spinner with Check Point brand color */
    .stSpinner > div {
        border-top-color: #EE0C5D !important;
    }
    
    /* Loading text */
    .stSpinner + div {
        color: #EE0C5D !important;
        font-weight: 500;
    }
    
    /* Settings button */
    .stButton > button[kind="secondary"] {
        background: rgba(255, 255, 255, 0.8);
        color: #333;
        border: 1px solid rgba(0, 0, 0, 0.1);
    }
</style>
""", unsafe_allow_html=True)

def initialize_app():
    """Initialize application state and services"""
    if 'app_initialized' not in st.session_state:
        st.session_state.app_initialized = False
    
    if 'config' not in st.session_state:
        st.session_state.config = AppConfig()
    
    if 'encryption_service' not in st.session_state:
        st.session_state.encryption_service = EncryptionService()
    
    if 'mcp_manager' not in st.session_state:
        st.session_state.mcp_manager = MCPManager(encryption_service=st.session_state.encryption_service)
    
    if 'file_manager' not in st.session_state:
        st.session_state.file_manager = FileManager()
    
    if 'ollama_client' not in st.session_state:
        # Initialize with default context window (will be updated from config if available)
        st.session_state.ollama_client = OllamaClient(context_window=32768)
    
    if 'openrouter_client' not in st.session_state:
        # Get API key from session state (loaded after login), environment, or encrypted storage
        api_key = ""
        
        # First priority: check if key was loaded after login (stored in session state)
        if 'loaded_openrouter_key' in st.session_state:
            api_key = st.session_state.loaded_openrouter_key
        
        # Second priority: environment variable
        if not api_key:
            api_key = os.getenv("OPENROUTER_API_KEY", "")
        
        # Third priority: load from encrypted storage (if encryption is initialized)
        if not api_key and st.session_state.encryption_service.is_initialized():
            try:
                encrypted_key = st.session_state.file_manager.load_openrouter_key(
                    st.session_state.encryption_service
                )
                if encrypted_key:
                    api_key = encrypted_key
                    st.session_state.loaded_openrouter_key = encrypted_key
            except:
                pass
        st.session_state.openrouter_client = OpenRouterClient(api_key)
    
    if 'llm_provider' not in st.session_state:
        st.session_state.llm_provider = "ollama"  # Default to Ollama
    
    if 'query_orchestrator' not in st.session_state:
        # Initialize orchestrator with both clients
        st.session_state.query_orchestrator = QueryOrchestrator(
            st.session_state.ollama_client,
            st.session_state.mcp_manager,
            st.session_state.openrouter_client
        )
    
    if 'chat_history' not in st.session_state:
        st.session_state.chat_history = []
    
    if 'use_orchestration' not in st.session_state:
        st.session_state.use_orchestration = True
    
    if 'uploaded_file_path' not in st.session_state:
        st.session_state.uploaded_file_path = None
    
    if 'uploaded_file_name' not in st.session_state:
        st.session_state.uploaded_file_name = None
    
    # Load active model selections from config if not already set
    if st.session_state.file_manager.config_exists():
        try:
            config_data = st.session_state.file_manager.load_config()
            
            # Load active model selections if not already in session state
            if config_data:
                if 'active_planner_model' not in st.session_state and 'active_planner_model' in config_data:
                    st.session_state.active_planner_model = config_data['active_planner_model']
                if 'active_security_model' not in st.session_state and 'active_security_model' in config_data:
                    st.session_state.active_security_model = config_data['active_security_model']
                
                # Auto-fetch available models if we have saved selections but empty model lists
                if 'active_planner_model' in st.session_state or 'active_security_model' in st.session_state:
                    # Fetch OpenRouter models if we have API key and the list is empty
                    if 'available_openrouter_models' not in st.session_state or not st.session_state.available_openrouter_models:
                        if st.session_state.openrouter_client.api_key and st.session_state.openrouter_client.check_connection():
                            models_data = st.session_state.openrouter_client.list_models()
                            st.session_state.available_openrouter_models = [m['id'] for m in models_data]
                    
                    # Fetch Ollama models if connection is available and the list is empty
                    if 'available_models' not in st.session_state or not st.session_state.available_models:
                        if st.session_state.ollama_client.check_connection():
                            st.session_state.available_models = st.session_state.ollama_client.list_models()
        except:
            pass

def show_setup_wizard():
    """Display first-time setup wizard"""
    st.markdown(f"<h1 style='text-align: center;'>Check Point MCP Chat</h1>", unsafe_allow_html=True)
    st.markdown(f"<h3 style='text-align: center; color: #666;'>First Time Setup - v{__version__}</h3>", unsafe_allow_html=True)
    st.markdown("<br>", unsafe_allow_html=True)
    
    # Center the form
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        with st.form("setup_wizard"):
            st.markdown("#### Create Master Password")
            st.caption("This password will be used to encrypt all your sensitive credentials")
            master_password = st.text_input("Master Password", type="password", help="Choose a strong password")
            confirm_password = st.text_input("Confirm Password", type="password")
            
            st.markdown("<br>", unsafe_allow_html=True)
            setup_submit = st.form_submit_button("Complete Setup", type="primary", use_container_width=True)
            
            if setup_submit:
                if not master_password or master_password != confirm_password:
                    st.error("Passwords don't match or are empty!")
                    return False
                
                try:
                    # Initialize encryption (setup mode)
                    st.session_state.encryption_service.initialize(master_password, is_setup=True)
                    
                    # Save minimal initial configuration
                    config_data = {
                        'data_directory': './data'
                    }
                    
                    st.session_state.file_manager.save_config(config_data)
                    st.session_state.app_initialized = True
                    st.session_state.logged_in = True
                    
                    # Redirect to settings page to configure LLM providers
                    st.session_state.show_settings = True
                    
                    st.success("Master password created! Redirecting to settings...")
                    time.sleep(1)
                    st.rerun()
                    
                except Exception as e:
                    st.error(f"Setup failed: {str(e)}")
                    return False

def show_login_screen():
    """Display login screen for master password"""
    st.markdown(f"<h1 style='text-align: center;'>Check Point MCP Chat</h1>", unsafe_allow_html=True)
    st.markdown(f"<h3 style='text-align: center; color: #666;'>Login - v{__version__}</h3>", unsafe_allow_html=True)
    st.markdown("<br>", unsafe_allow_html=True)
    
    # Center the form
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        with st.form("login_form"):
            st.markdown("#### Enter Master Password")
            st.caption("Required to decrypt your API/MCP credentials")
            master_password = st.text_input("Master Password", type="password", key="login_password")
            
            st.markdown("<br>", unsafe_allow_html=True)
            login_submit = st.form_submit_button("Login", type="primary", use_container_width=True)
            
            if login_submit:
                if not master_password:
                    st.error("Please enter your master password!")
                    return False
                
                try:
                    # Try to initialize encryption with the password
                    if st.session_state.encryption_service.initialize(master_password):
                        migrated_key = None
                        
                        # Migrate old plain text API key if it exists
                        try:
                            config_data = st.session_state.file_manager.load_config()
                            if config_data and 'openrouter_api_key' in config_data:
                                old_key = config_data.get('openrouter_api_key', '')
                                if old_key:
                                    # Migrate to encrypted storage
                                    st.session_state.file_manager.save_openrouter_key(
                                        old_key, st.session_state.encryption_service
                                    )
                                    # Remove from config
                                    del config_data['openrouter_api_key']
                                    st.session_state.file_manager.save_config(config_data)
                                    migrated_key = old_key
                        except Exception:
                            pass
                        
                        # Load encrypted OpenRouter API key after successful login
                        if migrated_key:
                            loaded_key = migrated_key
                        else:
                            try:
                                loaded_key = st.session_state.file_manager.load_openrouter_key(
                                    st.session_state.encryption_service
                                )
                            except Exception:
                                loaded_key = None
                        
                        # Update session state, environment, and recreate client with the key
                        if loaded_key:
                            st.session_state.loaded_openrouter_key = loaded_key
                            os.environ["OPENROUTER_API_KEY"] = loaded_key
                            # Recreate OpenRouter client with the decrypted key
                            st.session_state.openrouter_client = OpenRouterClient(loaded_key)
                            # Recreate QueryOrchestrator with updated client
                            if 'query_orchestrator' in st.session_state:
                                del st.session_state['query_orchestrator']
                        
                        st.session_state.logged_in = True
                        st.success("Login successful!")
                        time.sleep(0.5)
                        st.rerun()
                    else:
                        st.error("Invalid password!")
                        return False
                    
                except Exception as e:
                    st.error(f"Login failed: {str(e)}")
                    return False

def show_chat_interface():
    """Display main chat interface (Claude-like)"""
    
    # Auto-start configured servers on first load after login
    if 'servers_auto_started' not in st.session_state:
        st.session_state.servers_auto_started = True
        
        # Get all configured servers
        all_servers = st.session_state.mcp_manager.get_all_servers()
        servers_to_start = []
        
        # Find servers marked as active
        for server_name, server_config in all_servers.items():
            if server_config.get('active', False):
                # Check if not already running
                if server_name not in st.session_state.mcp_manager.running_servers:
                    servers_to_start.append(server_name)
        
        # Start the servers
        if servers_to_start:
            with st.spinner(f"Starting {len(servers_to_start)} configured server(s)..."):
                for server_name in servers_to_start:
                    try:
                        # Start the server (credentials loaded automatically from encrypted files)
                        st.session_state.mcp_manager.start_server(server_name)
                    except Exception as e:
                        print(f"Failed to auto-start {server_name}: {str(e)}")
    
    # Top bar with title and settings/exit button
    col1, col2 = st.columns([6, 1])
    with col1:
        st.markdown(f"# Check Point MCP Chat v{__version__}")
    with col2:
        # Change button text based on settings panel state
        button_text = "Exit" if st.session_state.get('show_settings', False) else "Settings"
        button_help = "Exit settings and return to chat" if st.session_state.get('show_settings', False) else "Open settings"
        if st.button(button_text, help=button_help):
            st.session_state.show_settings = not st.session_state.get('show_settings', False)
            st.rerun()
    
    # Settings panel (collapsible)
    if st.session_state.get('show_settings', False):
        with st.expander("Settings", expanded=True):
            st.markdown("### LLM Provider Configuration")
            st.caption("Configure both providers and select models from either one")
            
            st.markdown("---")
            
            # Ollama Configuration
            st.markdown("### Ollama Server Configuration")
            
            col1, col2, col3 = st.columns([3, 1, 1])
            with col1:
                ollama_host = st.text_input(
                    "Ollama Server Address",
                    value=st.session_state.ollama_client.base_url,
                    help="Format: http://hostname:port",
                    key="ollama_host_input"
                )
                # Update session state with current input value
                if ollama_host:
                    st.session_state.ollama_host_current = ollama_host
            with col2:
                if st.button("Test Connection", key="ollama_test", use_container_width=True):
                    test_host = ollama_host if ollama_host else st.session_state.ollama_client.base_url
                    temp_client = OllamaClient(test_host)
                    if temp_client.check_connection():
                        st.success("Connected")
                        st.session_state.ollama_client.base_url = test_host
                        st.session_state.ollama_host_current = test_host
                        # Save to config
                        config_data = st.session_state.file_manager.load_config() or {}
                        config_data['ollama_host'] = test_host
                        st.session_state.file_manager.save_config(config_data)
                        # Fetch models
                        st.session_state.available_models = temp_client.list_models()
                        st.rerun()
                    else:
                        st.error("Connection failed")
            with col3:
                if st.button("Clear", key="clear_ollama", use_container_width=True):
                    # Reset to default
                    default_host = "http://network-host:11434"
                    st.session_state.ollama_client.base_url = default_host
                    st.session_state.ollama_host_current = default_host
                    st.session_state.available_models = []
                    # Remove from config
                    config_data = st.session_state.file_manager.load_config() or {}
                    if 'ollama_host' in config_data:
                        del config_data['ollama_host']
                    st.session_state.file_manager.save_config(config_data)
                    st.success("Cleared")
                    st.rerun()
            
            # Context Window Configuration
            st.markdown("#### Context Window Size")
            col1, col2 = st.columns([3, 1])
            with col1:
                # Load current context window from config or use default
                config_data = st.session_state.file_manager.load_config() or {}
                current_ctx_window = config_data.get('ollama_context_window', 32768)
                
                context_window = st.slider(
                    "Ollama Context Window (tokens)",
                    min_value=4096,
                    max_value=131072,
                    value=current_ctx_window,
                    step=4096,
                    help="Context window size for Ollama models. Higher values allow more MCP data but require more memory. Llama 3.1 supports up to 128k tokens.",
                    key="ollama_ctx_window"
                )
                
                # Show selected value in human-readable format
                ctx_display = f"{context_window // 1024}k tokens"
                st.caption(f"Selected: {ctx_display}")
            
            with col2:
                if st.button("Save Context", key="save_ollama_ctx", use_container_width=True):
                    config_data = st.session_state.file_manager.load_config() or {}
                    config_data['ollama_context_window'] = context_window
                    if st.session_state.file_manager.save_config(config_data):
                        # Update the client
                        st.session_state.ollama_client.context_window = context_window
                        st.success(f"Context window set to {context_window // 1024}k")
                        st.rerun()
                    else:
                        st.error("Failed to save context window")
            
            # Display available models if connected
            # Don't auto-fetch models on page load to prevent blocking
            if 'available_models' not in st.session_state:
                st.session_state.available_models = []
            
            if st.session_state.available_models:
                st.caption(f"Connected - {len(st.session_state.available_models)} models available")
            else:
                st.info("Click 'Test Connection' to discover available Ollama models")
            
            st.markdown("---")
            
            # OpenRouter Configuration
            st.markdown("### OpenRouter API Configuration")
            
            # Check if API key exists
            has_api_key = bool(st.session_state.openrouter_client.api_key)
            
            if not has_api_key:
                st.warning("OpenRouter API key not configured")
                st.info("Get your API key from: https://openrouter.ai/keys")
                
                # Form for API key input to preserve value on button click
                with st.form("openrouter_api_key_form"):
                    api_key_input = st.text_input(
                        "Enter your OpenRouter API Key",
                        type="password",
                        help="Your API key will be stored securely as an environment secret"
                    )
                    
                    submit_key = st.form_submit_button("Save API Key", use_container_width=True)
                    
                    if submit_key:
                        if api_key_input:
                            # Save to encrypted storage first
                            save_result = st.session_state.file_manager.save_openrouter_key(
                                api_key_input, st.session_state.encryption_service
                            )
                            if save_result:
                                # Save to session state
                                st.session_state.loaded_openrouter_key = api_key_input
                                os.environ["OPENROUTER_API_KEY"] = api_key_input
                                
                                # Force recreation of OpenRouter client and QueryOrchestrator
                                if 'openrouter_client' in st.session_state:
                                    del st.session_state['openrouter_client']
                                if 'query_orchestrator' in st.session_state:
                                    del st.session_state['query_orchestrator']
                                
                                st.success("API Key saved securely (encrypted)! Click Test Connection to verify.")
                            else:
                                st.error("Failed to save API key. Make sure you're logged in.")
                            st.rerun()
                        else:
                            st.error("Please enter an API key")
            
            col1, col2, col3 = st.columns([3, 1, 1])
            with col1:
                api_key_display = "••••••••" if has_api_key else "Not configured"
                st.text_input(
                    "API Key Status",
                    value=api_key_display,
                    disabled=True,
                    help="Get your API key from https://openrouter.ai/keys",
                    key="openrouter_status"
                )
            with col2:
                if st.button("Test Connection", key="openrouter_test", use_container_width=True):
                    if st.session_state.openrouter_client.check_connection():
                        st.success("Connected")
                        # Fetch models
                        models_data = st.session_state.openrouter_client.list_models()
                        st.session_state.available_openrouter_models = [m['id'] for m in models_data]
                        st.rerun()
                    else:
                        st.error("Connection failed - check API key")
            with col3:
                if has_api_key:
                    if st.button("Change Key", key="openrouter_change", use_container_width=True):
                        # Clear the API key from all locations
                        st.session_state.openrouter_client.api_key = ""
                        if "OPENROUTER_API_KEY" in os.environ:
                            del os.environ["OPENROUTER_API_KEY"]
                        # Clear from session state (critical!)
                        if 'loaded_openrouter_key' in st.session_state:
                            del st.session_state['loaded_openrouter_key']
                        # Delete encrypted key file
                        st.session_state.file_manager.delete_openrouter_key()
                        # Also remove from old config if present
                        config_data = st.session_state.file_manager.load_config() or {}
                        if 'openrouter_api_key' in config_data:
                            del config_data['openrouter_api_key']
                            st.session_state.file_manager.save_config(config_data)
                        # Clear models
                        st.session_state.available_openrouter_models = []
                        st.success("API Key cleared")
                        st.rerun()
            
            # Display available models if connected
            if 'available_openrouter_models' not in st.session_state:
                st.session_state.available_openrouter_models = []
            
            if st.session_state.available_openrouter_models:
                st.caption(f"Connected - {len(st.session_state.available_openrouter_models)} models available")
            else:
                st.info("Click 'Test Connection' to discover available OpenRouter models")
            
            st.markdown("---")
            
            # Unified Model Selection
            st.markdown("### Active Model Selection")
            st.caption("Select two active models from either provider")
            
            # Combine models from both providers
            all_models = []
            if st.session_state.available_models:
                all_models.extend([f"Ollama: {m}" for m in st.session_state.available_models])
            if st.session_state.available_openrouter_models:
                all_models.extend([f"OpenRouter: {m}" for m in st.session_state.available_openrouter_models])
            
            if all_models:
                # Determine default index for selectboxes
                # If saved model is in list, use it; otherwise use first available
                planner_index = 0
                security_index = 0
                
                if 'active_planner_model' in st.session_state:
                    if st.session_state.active_planner_model in all_models:
                        planner_index = all_models.index(st.session_state.active_planner_model)
                    # Don't reset saved value - keep it for when models are available
                
                if 'active_security_model' in st.session_state:
                    if st.session_state.active_security_model in all_models:
                        security_index = all_models.index(st.session_state.active_security_model)
                    # Don't reset saved value - keep it for when models are available
                
                # Planner Model Selection
                st.markdown("#### Planner Model")
                st.selectbox(
                    "Model for query planning and orchestration:",
                    options=all_models,
                    index=planner_index,
                    help="This model will be used for planning queries and coordinating MCP servers",
                    key="active_planner_model"
                )
                
                # Security Analysis Model Selection
                st.markdown("#### Security Analysis Model")
                st.selectbox(
                    "Model for security analysis:",
                    options=all_models,
                    index=security_index,
                    help="This model will be used for security analysis and threat detection",
                    key="active_security_model"
                )
                
                st.markdown("---")
                
                # Save Settings Button
                col1, col2, col3 = st.columns([1, 2, 1])
                with col2:
                    if st.button("Save Active Models", type="primary", use_container_width=True):
                        # Load existing config and update only the model fields
                        config_data = st.session_state.file_manager.load_config() or {}
                        config_data['active_planner_model'] = st.session_state.active_planner_model
                        config_data['active_security_model'] = st.session_state.active_security_model
                        if st.session_state.file_manager.save_config(config_data):
                            st.success("Active models saved successfully!")
                            st.rerun()
                        else:
                            st.error("Failed to save settings")
            else:
                st.warning("No models available. Please configure and test at least one provider above.")
            
            st.markdown("---")
            
            # Gateway Credential Sharing
            st.markdown("### Gateway Credential Sharing")
            st.caption("Automatically share SSH credentials with discovered gateways in the same management domain")
            
            # Load current consent setting
            config_data = st.session_state.file_manager.load_config() or {}
            current_consent = config_data.get('auto_share_gateway_credentials', False)
            
            consent_enabled = st.checkbox(
                "Enable automatic gateway credential sharing",
                value=current_consent,
                help="When enabled, SSH credentials from configured gateways will automatically be shared with other gateways discovered from the management server",
                key="auto_share_gateway_credentials"
            )
            
            # Save consent setting if changed
            if consent_enabled != current_consent:
                config_data['auto_share_gateway_credentials'] = consent_enabled
                if st.session_state.file_manager.save_config(config_data):
                    if consent_enabled:
                        st.success("✓ Gateway credential sharing enabled")
                    else:
                        st.info("Gateway credential sharing disabled")
                    st.rerun()
            
            st.markdown("---")
            
            # Check Point MCP Server Configuration
            st.markdown("### Check Point MCP Servers")
            
            # Initialize server configs in session state if not present
            if 'mcp_server_configs' not in st.session_state:
                st.session_state.mcp_server_configs = {}
            
            # Initialize version info cache if not present
            if 'mcp_version_cache' not in st.session_state:
                st.session_state.mcp_version_cache = {}
            
            # Initialize installation status cache if not present
            if 'mcp_install_cache' not in st.session_state:
                st.session_state.mcp_install_cache = {}
            
            # Get available MCP servers from config
            available_servers = st.session_state.config.CHECKPOINT_MCP_SERVERS
            configured_servers = st.session_state.mcp_manager.get_all_servers()
            
            # Auto-populate cache on first load if empty
            if not st.session_state.mcp_install_cache:
                for srv_name, srv_config in available_servers.items():
                    pkg_name = srv_config['package']
                    # Quick check without showing spinner on first load
                    st.session_state.mcp_install_cache[pkg_name] = st.session_state.mcp_manager.is_package_installed(pkg_name)
            
            # Server list description with refresh button
            col1, col2 = st.columns([3, 1])
            with col1:
                st.caption(f"{len(available_servers)} MCP servers configured")
            with col2:
                if st.button("Refresh Versions", key="refresh_versions", use_container_width=True, help="Check for package updates from npm"):
                    # Clear caches and fetch fresh info for all packages
                    st.session_state.mcp_version_cache = {}
                    st.session_state.mcp_install_cache = {}
                    with st.spinner("Checking npm for package status..."):
                        for srv_name, srv_config in available_servers.items():
                            pkg_name = srv_config['package']
                            # Cache installation status
                            st.session_state.mcp_install_cache[pkg_name] = st.session_state.mcp_manager.is_package_installed(pkg_name)
                            # Cache version info
                            st.session_state.mcp_version_cache[pkg_name] = st.session_state.mcp_manager.get_version_info(pkg_name)
                    st.success("Version info refreshed!")
                    st.rerun()
            
            st.markdown("#### Available Servers")
            
            # Display servers in expandable sections
            for server_name, server_config in available_servers.items():
                # Check if server is configured
                is_configured = server_name in configured_servers
                is_active = configured_servers.get(server_name, {}).get('active', False) if is_configured else False
                
                # Load existing credentials from MCPManager (already decrypted in 'env' field)
                if server_name not in st.session_state.mcp_server_configs:
                    if is_configured and 'env' in configured_servers[server_name]:
                        saved_credentials = configured_servers[server_name]['env']
                        if saved_credentials:
                            st.session_state.mcp_server_configs[server_name] = saved_credentials
                
                # Status indicator
                status_icon = "●" if is_active else ("●" if is_configured else "○")
                status_text = "Running" if is_active else ("Configured" if is_configured else "Not configured")
                
                with st.expander(f"{status_icon} **{server_name}** - {status_text}", expanded=False):
                    # Use cached installation status and version info (no subprocess/network calls on page load)
                    package_name = server_config['package']
                    is_installed = st.session_state.mcp_install_cache.get(package_name, False)
                    version_info = st.session_state.mcp_version_cache.get(package_name)
                    has_update = version_info['has_update'] if version_info else False
                    
                    # Header with server info
                    st.caption(f"**{server_config['type']}**: {server_config['description']}")
                    st.caption(f"Package: `{server_config['package']}`")
                    
                    # Version display (only if cached)
                    if version_info:
                        if version_info['installed']:
                            if has_update:
                                st.caption(f"Version: `{version_info['installed']}` → `{version_info['latest']}`")
                            else:
                                st.caption(f"Version: `{version_info['installed']}`" + 
                                          (f" (latest)" if version_info['latest'] == version_info['installed'] else ""))
                        elif version_info['latest']:
                            st.caption(f"Latest version: `{version_info['latest']}` (not installed)")
                    else:
                        # Show message when no cached info available
                        st.caption("Click 'Refresh Versions' button above to check installation status and updates")
                    
                    st.markdown("---")
                    
                    # NOT INSTALLED - Show only Install button
                    if not is_installed:
                        st.info("📦 Package not installed. Install it first to configure this server.")
                        if st.button("📥 Install Package", key=f"install_{server_name}", type="primary", use_container_width=True):
                            with st.spinner(f"Installing {server_config['package']}..."):
                                success, message = st.session_state.mcp_manager.install_mcp_package(server_config['package'])
                                if success:
                                    st.success(message)
                                    # Update cache
                                    st.session_state.mcp_install_cache[package_name] = True
                                    st.session_state.mcp_version_cache[package_name] = st.session_state.mcp_manager.get_version_info(package_name)
                                    st.rerun()
                                else:
                                    st.error(message)
                                    # Don't rerun on failure so error message stays visible
                    
                    # INSTALLED - Show configuration form and action buttons
                    else:
                        # Update/Delete buttons
                        col1, col2 = st.columns(2)
                        with col1:
                            if has_update:
                                if st.button("⬆️ Update Package", key=f"update_{server_name}", use_container_width=True):
                                    with st.spinner(f"Updating {server_config['package']}..."):
                                        success, message = st.session_state.mcp_manager.update_mcp_package(server_config['package'])
                                        if success:
                                            st.success(message)
                                            st.session_state.mcp_version_cache[package_name] = st.session_state.mcp_manager.get_version_info(package_name)
                                        else:
                                            st.error(message)
                                        st.rerun()
                        with col2:
                            if st.button("🗑️ Delete Server", key=f"delete_{server_name}", use_container_width=True, help="Uninstall package and delete all configuration"):
                                # Stop server if running
                                if is_active:
                                    st.session_state.mcp_manager.stop_server(server_name)
                                # Remove server config
                                st.session_state.mcp_manager.remove_server(server_name)
                                # Delete credentials
                                st.session_state.file_manager.delete_server_credentials(server_name)
                                # Clear from session state
                                if server_name in st.session_state.mcp_server_configs:
                                    del st.session_state.mcp_server_configs[server_name]
                                # Uninstall package
                                with st.spinner(f"Uninstalling {server_config['package']}..."):
                                    success, message = st.session_state.mcp_manager.uninstall_mcp_package(server_config['package'])
                                    # Update cache
                                    st.session_state.mcp_install_cache[package_name] = False
                                    if success:
                                        st.success(message)
                                    else:
                                        st.error(message)
                                    st.rerun()
                        
                        st.markdown("---")
                        
                        # Configuration form
                        with st.form(f"server_config_{server_name}", clear_on_submit=False):
                            st.markdown("##### Configuration")
                            
                            # Check if server has multiple auth modes
                            auth_modes = server_config.get('auth_modes', [])
                        
                            # Info message for dual-mode servers
                            if len(auth_modes) > 1:
                                st.info("This server supports both Cloud (S1C) and On-Premise authentication. You can configure either or both - the MCP server will auto-detect based on which credentials you provide.")
                        
                            # Cloud fields
                            cloud_fields = ['S1C_URL', 'CLOUD_INFRA_TOKEN', 'ORIGIN', 'SERVICE_URL']
                            # On-Prem fields
                            onprem_fields = ['MANAGEMENT_HOST', 'PORT', 'USERNAME', 'PASSWORD', 'GATEWAY_HOST', 'SSH_USERNAME', 'SSH_PASSWORD', 'SSH_KEY']
                        
                            # Group fields by type for better UX
                            if len(auth_modes) > 1:
                                # Show cloud fields first
                                st.markdown("**Cloud (Smart-1 Cloud) Credentials** _(optional if using on-premise)_")
                                cloud_values = {}
                                for env_var in server_config['env_vars']:
                                    if env_var in cloud_fields or env_var == 'API_KEY':
                                        is_sensitive = any(keyword in env_var for keyword in ['API_KEY', 'PASSWORD', 'SECRET', 'SSH_KEY', 'TOKEN'])
                                        existing_value = st.session_state.mcp_server_configs.get(server_name, {}).get(env_var, '')
                                    
                                        # Format label
                                        label = env_var.replace('CHECKPOINT_', '').replace('_', ' ').title()
                                        if env_var == 'API_KEY':
                                            label += " (for Cloud auth)"
                                    
                                        if is_sensitive:
                                            value = st.text_input(
                                                label,
                                                value=existing_value,
                                                type="password",
                                                key=f"{server_name}_{env_var}_cloud_input",
                                                help="🔒 Encrypted locally"
                                            )
                                        else:
                                            value = st.text_input(
                                                label,
                                                value=existing_value,
                                                key=f"{server_name}_{env_var}_cloud_input"
                                            )
                                        cloud_values[env_var] = value
                            
                                # Show on-prem fields
                                st.markdown("**On-Premise Credentials** _(optional if using cloud)_")
                                onprem_values = {}
                                for env_var in server_config['env_vars']:
                                    if env_var in onprem_fields:
                                        is_sensitive = any(keyword in env_var for keyword in ['API_KEY', 'PASSWORD', 'SECRET', 'SSH_KEY', 'TOKEN'])
                                        existing_value = st.session_state.mcp_server_configs.get(server_name, {}).get(env_var, '')
                                    
                                        # Format label
                                        label = env_var.replace('CHECKPOINT_', '').replace('_', ' ').title()
                                        if env_var == 'PORT':
                                            label += " (optional, default: 443)"
                                    
                                        if is_sensitive:
                                            value = st.text_input(
                                                label,
                                                value=existing_value,
                                                type="password",
                                                key=f"{server_name}_{env_var}_onprem_input",
                                                help="🔒 Encrypted locally"
                                            )
                                        else:
                                            value = st.text_input(
                                                label,
                                                value=existing_value,
                                                key=f"{server_name}_{env_var}_onprem_input"
                                            )
                                        onprem_values[env_var] = value
                            
                                # Merge both value sets
                                server_values = {**cloud_values, **onprem_values}
                            else:
                                # Single mode server - show all fields normally
                                server_values = {}
                                for env_var in server_config['env_vars']:
                                    is_sensitive = any(keyword in env_var for keyword in ['API_KEY', 'PASSWORD', 'SECRET', 'SSH_KEY', 'TOKEN'])
                                    existing_value = st.session_state.mcp_server_configs.get(server_name, {}).get(env_var, '')
                                
                                    # Format label
                                    label = env_var.replace('CHECKPOINT_', '').replace('_', ' ').title()
                                    if env_var == 'PORT':
                                        label += " (optional, default: 443)"
                                
                                    if is_sensitive:
                                        value = st.text_input(
                                            label,
                                            value=existing_value,
                                            type="password",
                                            key=f"{server_name}_{env_var}_input",
                                            help="🔒 Encrypted locally"
                                        )
                                    else:
                                        value = st.text_input(
                                            label,
                                            value=existing_value,
                                            key=f"{server_name}_{env_var}_input"
                                        )
                                
                                    server_values[env_var] = value
                        
                            # Form buttons - Save and Start/Stop
                            col1, col2 = st.columns(2)
                            with col1:
                                save_button = st.form_submit_button("💾 Save Config", type="primary", use_container_width=True)
                        
                            with col2:
                                if is_active:
                                    stop_button = st.form_submit_button("⏹️ Stop Server", use_container_width=True)
                                    start_button = False
                                elif is_configured:
                                    start_button = st.form_submit_button("▶️ Start Server", use_container_width=True)
                                    stop_button = False
                                else:
                                    start_button = False
                                    stop_button = False
                        
                            # Handle Save button (always available)
                            if save_button:
                                # Validate - for dual-mode servers, require at least one complete set of credentials
                                validation_error = None
                                if len(auth_modes) > 1:
                                    # Check if cloud credentials are complete
                                    has_cloud = False
                                    if server_values.get('API_KEY') and server_values.get('S1C_URL'):
                                        has_cloud = True
                                
                                    # Check if on-prem credentials are complete
                                    has_onprem = False
                                    has_api_key = bool(server_values.get('API_KEY'))
                                    has_username_password = bool(server_values.get('USERNAME') and server_values.get('PASSWORD'))
                                    has_host = bool(server_values.get('MANAGEMENT_HOST') or server_values.get('GATEWAY_HOST'))
                                
                                    if (has_api_key or has_username_password) and has_host:
                                        has_onprem = True
                                
                                    # Must have at least one complete set
                                    if not has_cloud and not has_onprem:
                                        validation_error = "Please provide either Cloud credentials (API Key + S1C URL) OR On-Premise credentials (API Key/Username+Password + Host)"
                            
                                if validation_error:
                                    st.error(f"{validation_error}")
                                else:
                                    # Collect all credentials (MCPManager will handle encryption)
                                    all_credentials = {k: v for k, v in server_values.items() if v}
                                
                                    # Store in session state
                                    st.session_state.mcp_server_configs[server_name] = all_credentials
                                    
                                    # Check if server was running before update (to restart after)
                                    was_running = server_name in st.session_state.mcp_manager.running_servers
                                    
                                    # Stop server if running (credentials are changing)
                                    if was_running:
                                        print(f"[APP] Stopping {server_name} before credential update")
                                        st.session_state.mcp_manager.stop_server(server_name)
                                
                                    # Add/update server in MCP manager (it will encrypt credentials)
                                    print(f"[APP] About to add server to MCP manager: {server_name}")
                                    add_result = st.session_state.mcp_manager.add_server(server_name, {
                                        'package': server_config['package'],
                                        'type': server_config['type'],
                                        'description': server_config['description'],
                                        'config': all_credentials
                                    })
                                    print(f"[APP] add_server returned: {add_result}")
                                
                                    if add_result:
                                        st.success(f"Configuration saved for {server_name}")
                                        
                                        # Restart server if it was running, or start if new
                                        # start_server() will load decrypted credentials automatically from encrypted files
                                        if was_running or server_name not in st.session_state.mcp_manager.running_servers:
                                            if st.session_state.mcp_manager.start_server(server_name):
                                                restart_msg = "restarted with new credentials" if was_running else "started automatically"
                                                st.success(f"Server {server_name} {restart_msg}")
                                            else:
                                                st.warning(f"Configuration saved but failed to start {server_name}. You can start it manually.")
                                    else:
                                        st.error(f"Failed to save configuration for {server_name}. Check console logs.")
                                    st.rerun()
                            
                            # Handle start/stop buttons
                            if is_active and 'stop_button' in locals() and stop_button:
                                st.session_state.mcp_manager.stop_server(server_name)
                                st.success(f"Server {server_name} stopped")
                                st.rerun()
                            elif is_configured and 'start_button' in locals() and start_button:
                                # Start server (credentials loaded automatically from encrypted files)
                                if st.session_state.mcp_manager.start_server(server_name):
                                    st.success(f"Server {server_name} started")
                                else:
                                    st.error(f"Failed to start {server_name}")
                                st.rerun()
    else:
        # Only show chat interface when settings are closed
        st.markdown("---")
        
        # Chat history
        chat_container = st.container()
        
        with chat_container:
            if st.session_state.chat_history:
                for message in st.session_state.chat_history:
                    if message['role'] == 'user':
                        with st.chat_message("user"):
                            st.write(message['content'])
                    
                    elif message['role'] == 'assistant':
                        with st.chat_message("assistant"):
                            st.markdown(message['content'])
                            
                            # Show parameter selection UI if needed
                            if message.get('parameter_selection'):
                                param_options = message['parameter_selection']
                                for param_name, options in param_options.items():
                                    st.markdown(f"**Select {param_name}:**")
                                    
                                    # Create radio buttons for options
                                    selected = st.radio(
                                        f"Choose {param_name}:",
                                        options=[opt['display'] for opt in options],
                                        key=f"param_select_{param_name}_{message['timestamp']}",
                                        label_visibility="collapsed"
                                    )
                                    
                                # Add button to confirm selection
                                if st.button("Continue with selected parameters", key=f"confirm_{message['timestamp']}"):
                                    # Store selections
                                    selections = {}
                                    for param_name, options in param_options.items():
                                        radio_key = f"param_select_{param_name}_{message['timestamp']}"
                                        if radio_key in st.session_state:
                                            selected_display = st.session_state[radio_key]
                                            # Find the actual value
                                            for opt in options:
                                                if opt['display'] == selected_display:
                                                    selections[param_name] = opt['value']
                                                    break
                                    
                                    # Store selections and resume query
                                    st.session_state.pending_parameter_selections = selections
                                    
                                    # Show confirmation feedback
                                    st.success(f"✓ Parameters selected. Running query with: {', '.join([f'{k}={v}' for k, v in selections.items()])}")
                                    
                                    # Resume the pending query
                                    if 'pending_query' in st.session_state:
                                        with st.spinner("Executing query with selected parameters..."):
                                            process_with_orchestration(st.session_state.pending_query['message'])
                            
                            # Show execution details if available
                            if message.get('orchestration_data'):
                                with st.expander("Execution Details"):
                                    orch_data = message['orchestration_data']
                                    
                                    if orch_data.get('plan'):
                                        plan = orch_data['plan']
                                        st.markdown(f"**Understanding:** {plan.get('understanding', 'N/A')}")
                                        st.markdown(f"**Servers Used:** {', '.join(plan.get('required_servers', []))}")
                                        st.markdown(f"**Analysis Type:** {plan.get('analysis_type', 'N/A')}")
                                    
                                    if orch_data.get('execution'):
                                        exec_data = orch_data['execution']
                                        if exec_data.get('errors'):
                                            st.warning(f"Issues: {', '.join(exec_data['errors'])}")
            else:
                st.markdown("""
                <div style='text-align: center; padding: 40px; color: #666;'>
                    <h3>Welcome to Check Point MCP Chat</h3>
                    <p>Query your entire Check Point infrastructure across 11 specialized services.</p>
                    <p style='font-size: 0.9em; margin-top: 20px;'><strong>Fleet-Wide Operations (For Large Deployments):</strong></p>
                    <p style='font-size: 0.85em;'>• "Which gateways need immediate attention - show threats, performance issues, and misconfigurations"</p>
                    <p style='font-size: 0.85em;'>• "Audit all gateways for compliance violations, unused rules, and security gaps across my infrastructure"</p>
                    <p style='font-size: 0.9em; margin-top: 15px;'><strong>Specialized Services:</strong></p>
                    <p style='font-size: 0.85em;'>• "Show all policy changes across my gateways" (Management)</p>
                    <p style='font-size: 0.85em;'>• "Analyze traffic and audit logs from yesterday" (Logs)</p>
                    <p style='font-size: 0.85em;'>• "What threats were blocked this week?" (Threat Prevention)</p>
                    <p style='font-size: 0.85em;'>• "Show HTTPS inspection policy exceptions" (HTTPS Inspection)</p>
                    <p style='font-size: 0.85em;'>• "Check reputation of suspicious URL" (Reputation Service)</p>
                    <p style='font-size: 0.85em;'>• "Analyze file for malware" (Threat Emulation)</p>
                    <p style='font-size: 0.85em;'>• "Debug connection issue on gateway" (Connection Analysis)</p>
                    <p style='font-size: 0.85em;'>• "Show gateway interface status" (Gateway CLI / GAIA)</p>
                    <p style='font-size: 0.85em;'>• "Review Harmony SASE configuration" (SASE)</p>
                    <p style='font-size: 0.85em;'>• "Manage Spark appliances for customer" (Spark MSP)</p>
                </div>
                """, unsafe_allow_html=True)
        
        # Chat input (fixed at bottom)
        st.markdown("<br><br>", unsafe_allow_html=True)
        
        # Simple file upload button above chat
        uploaded_file = st.file_uploader("Upload file for malware analysis", type=None, key="file_uploader")
        
        # Chat input
        user_input = st.chat_input("Ask about your Check Point infrastructure...")
        
        # Handle file upload - automatically trigger scan
        if uploaded_file is not None:
            # Generate unique file identifier from content hash for duplicate detection
            file_bytes = uploaded_file.getvalue()
            file_hash = hashlib.sha256(file_bytes).hexdigest()
            file_id = f"{uploaded_file.name}_{file_hash}"
            
            # Only process if this is a new file (not already processed)
            if st.session_state.get('last_processed_file_id') != file_id:
                # Create temporary directory for threat emulation files
                temp_dir = "/tmp/threat_emulation"
                os.makedirs(temp_dir, exist_ok=True)
                
                # Sanitize filename to prevent path traversal attacks
                safe_filename = Path(uploaded_file.name).name  # Extract basename only, strips any path components
                
                # Defensive handling for empty/invalid filenames
                if not safe_filename or safe_filename.strip() == "":
                    safe_filename = "uploaded_file"
                
                # Generate unique filename to prevent collisions
                unique_id = str(uuid.uuid4())[:8]
                sanitized_name = f"{unique_id}_{safe_filename}"
                
                # Save uploaded file to disk (required for hash integrity)
                file_path = os.path.join(temp_dir, sanitized_name)
                with open(file_path, "wb") as f:
                    f.write(uploaded_file.getbuffer())
                
                # Mark this file as processed
                st.session_state.last_processed_file_id = file_id
                
                # Automatically trigger scan without waiting for user input
                auto_message = f"Analyze this file for threats\n\nFile uploaded for analysis: {uploaded_file.name}\nFile path: {file_path}"
                process_user_message(auto_message, file_path=file_path, file_name=uploaded_file.name)
                
                # Force rerun to clear the uploader
                st.rerun()
        
        if user_input:
            process_user_message(user_input)

def scan_file_with_progress(file_path: str, file_name: str) -> dict:
    """Scan file using threat-emulation MCP server with progress indicator"""
    import json
    import hashlib
    from services.mcp_client_simple import query_mcp_server
    
    # Calculate file hashes for status tracking
    def calculate_hashes(filepath):
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        with open(filepath, 'rb') as f:
            while chunk := f.read(8192):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
        return {
            'md5': md5.hexdigest(),
            'sha1': sha1.hexdigest(),
            'sha256': sha256.hexdigest()
        }
    
    # Get threat-emulation server config
    servers = st.session_state.mcp_manager.get_all_servers()
    if 'threat-emulation' not in servers:
        st.error("❌ Threat Emulation server not configured")
        return {"error": "Threat Emulation server not configured"}
    
    server_config = servers['threat-emulation']
    package_name = server_config.get('package')
    env_vars = server_config.get('env', {})
    
    # Calculate file hashes before upload
    hashes = calculate_hashes(file_path)
    
    # Show progress directly in the UI
    with st.status(f"🔬 Analyzing {file_name} with CheckPoint cloud sandbox...", expanded=True) as status:
        st.write("Uploading file...")
        
        try:
            # Call scan_file tool which uploads and waits up to 30 seconds
            results = query_mcp_server(
                package_name, 
                env_vars, 
                data_points=[file_path],  # File path will auto-fill
                user_parameter_selections=None,
                discovery_mode=False,
                user_query=f"scan file {file_path}"
            )
            
            tool_results = results.get('tool_results', [])
            scan_complete = False
            response_data = {}
            
            # Look for scan_file results
            for tool_result in tool_results:
                if tool_result.get('tool') == 'scan_file':
                    content = tool_result.get('result', {}).get('content', [])
                    if content and len(content) > 0:
                        response_data = json.loads(content[0].get('text', '{}'))
                        
                        # Add hashes to response for status tracking
                        response_data['file_hashes'] = hashes
                        response_data['file_name'] = file_name
                        
                        # Check if we have results
                        if 'te' in response_data and 'combined_verdict' in response_data.get('te', {}):
                            verdict = response_data['te']['combined_verdict']
                            st.write(f"Verdict: **{verdict}**")
                            st.write(f"MD5: `{hashes['md5']}`")
                            status.update(label=f"✅ Scan complete: {verdict}", state="complete")
                            scan_complete = True
                            break
                        elif 'status' in response_data:
                            status_label = response_data.get('status', {}).get('label', 'unknown')
                            st.write(f"Status: {status_label}")
                            st.write(f"MD5: `{hashes['md5']}`")
                            st.info(f"💡 **To check results later**, ask: 'Check status of file with MD5 {hashes['md5']}'")
                            status.update(label="⏳ Analysis in progress (may take several minutes)", state="complete")
                            scan_complete = True
                            break
            
            if not scan_complete:
                st.write("File uploaded to CheckPoint cloud")
                st.write(f"MD5: `{hashes['md5']}`")
                st.info(f"💡 **To check results later**, ask: 'Check status of file with MD5 {hashes['md5']}'")
                status.update(label="⏳ Analysis in progress (may take several minutes)", state="complete")
                response_data = {
                    "status": "uploaded", 
                    "message": "File uploaded to CheckPoint cloud. Analysis in progress.",
                    "file_hashes": hashes,
                    "file_name": file_name
                }
            
            return response_data
            
        except Exception as e:
            st.write(f"Error: {str(e)}")
            status.update(label=f"❌ Scan error", state="error")
            return {"error": str(e)}

def process_user_message(message: str, file_path: Optional[str] = None, file_name: Optional[str] = None):
    """Process user message and generate response"""
    
    # If file is attached, ALWAYS scan it first with progress indicator
    scan_results = None
    if file_path and file_name:
        scan_results = scan_file_with_progress(file_path, file_name)
    
    # Add user message to history
    message_entry = {
        'role': 'user',
        'content': message,
        'timestamp': time.time()
    }
    if file_path:
        message_entry['file_path'] = file_path
        message_entry['file_name'] = file_name
    if scan_results:
        message_entry['scan_results'] = scan_results
    
    st.session_state.chat_history.append(message_entry)
    
    # Check which providers are being used
    planner_model = st.session_state.get('active_planner_model', '')
    security_model = st.session_state.get('active_security_model', '')
    
    # Determine if we need to check Ollama or OpenRouter connections
    needs_ollama = (planner_model.startswith("Ollama:") or 
                    security_model.startswith("Ollama:") or 
                    not st.session_state.use_orchestration)
    needs_openrouter = (planner_model.startswith("OpenRouter:") or 
                        security_model.startswith("OpenRouter:"))
    
    # Check only the required connections
    if needs_ollama and not st.session_state.ollama_client.check_connection():
        st.session_state.chat_history.append({
            'role': 'assistant',
            'content': "Cannot connect to Ollama. Please check your configuration in Settings.",
            'timestamp': time.time()
        })
        st.rerun()
        return
    
    if needs_openrouter and not st.session_state.openrouter_client.check_connection():
        st.session_state.chat_history.append({
            'role': 'assistant',
            'content': "Cannot connect to OpenRouter. Please check your API key in Settings.",
            'timestamp': time.time()
        })
        st.rerun()
        return
    
    # Show typing indicator
    with st.spinner("Thinking..."):
        # Process with orchestration or manual mode
        if st.session_state.use_orchestration:
            process_with_orchestration(message)
        else:
            process_with_manual_mode(message)

def process_with_orchestration(message: str):
    """Process message using intelligent orchestration"""
    # Get active models from session state
    planner_model = st.session_state.get('active_planner_model')
    security_model = st.session_state.get('active_security_model')
    
    # Check if we're resuming with user-selected parameters
    user_selections = st.session_state.get('pending_parameter_selections', {})
    
    # Check if we have scan results from file upload
    scan_results = None
    if st.session_state.chat_history:
        last_message = st.session_state.chat_history[-1]
        if last_message.get('role') == 'user' and 'scan_results' in last_message:
            scan_results = last_message['scan_results']
            # If we have scan results, append them to the message for context
            if scan_results and not scan_results.get('error'):
                import json
                message = f"{message}\n\n[Scan Results: {json.dumps(scan_results, indent=2)}]"
    
    # Use orchestrator to handle the query with selected models
    result = st.session_state.query_orchestrator.orchestrate_query(
        message, 
        planner_model=planner_model,
        security_model=security_model,
        user_parameter_selections=user_selections
    )
    
    # Check if orchestrator needs user input for parameters
    if result.get('needs_user_input'):
        # Store the pending state
        st.session_state.pending_query = {
            'message': message,
            'plan': result.get('execution_plan'),
            'execution': result.get('execution_results'),
            'parameter_options': result.get('parameter_options', {}),
            'planner_model': planner_model,
            'security_model': security_model
        }
        
        # Ask user to select parameters
        display_parameter_selection_ui(result.get('parameter_options', {}))
        return
    
    # Clear any pending state
    if 'pending_query' in st.session_state:
        del st.session_state['pending_query']
    if 'pending_parameter_selections' in st.session_state:
        del st.session_state['pending_parameter_selections']
    
    # Create response
    plan = result.get('execution_plan', {})
    execution = result.get('execution_results', {})
    analysis = result.get('final_analysis', '')
    
    # Build response
    response_parts = []
    
    # Show understanding
    if plan.get('understanding'):
        response_parts.append(f"**Understanding:** {plan['understanding']}\n")
    
    # Show servers used
    if execution.get('servers_queried'):
        response_parts.append(f"**Servers Queried:** {', '.join(execution['servers_queried'])}\n")
    
    # Show errors
    if execution.get('errors'):
        response_parts.append(f"**Issues:** {', '.join(execution['errors'])}\n")
    
    # Add analysis
    response_parts.append(f"\n{analysis}")
    
    response_content = "\n".join(response_parts)
    
    # Add to chat history
    st.session_state.chat_history.append({
        'role': 'assistant',
        'content': response_content,
        'timestamp': time.time(),
        'model': result.get('model_used', 'orchestrated'),
        'orchestration_data': {
            'plan': plan,
            'execution': execution
        }
    })
    
    st.rerun()

def display_parameter_selection_ui(parameter_options):
    """Display UI for user to select parameter values"""
    st.session_state.chat_history.append({
        'role': 'assistant',
        'content': "I found multiple options for the required parameters. Please select which ones to use:",
        'timestamp': time.time(),
        'parameter_selection': parameter_options
    })
    st.rerun()

def process_with_manual_mode(message: str):
    """Process message using manual mode"""
    # Generate response directly
    response = st.session_state.ollama_client.generate_response(
        prompt=message,
        temperature=0.7
    )
    
    if response:
        st.session_state.chat_history.append({
            'role': 'assistant',
            'content': response,
            'timestamp': time.time()
        })
    else:
        st.session_state.chat_history.append({
            'role': 'assistant',
            'content': "Failed to generate response. Please try again.",
            'timestamp': time.time()
        })
    
    st.rerun()

def main():
    """Main application entry point"""
    initialize_app()
    
    # Initialize logged_in state if not present
    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False
    
    # Check if this is first run
    if not st.session_state.app_initialized:
        # Check if password verification file exists - if not, need setup
        verification_file = Path("./secrets/.password_verify")
        if not verification_file.exists():
            show_setup_wizard()
        elif not st.session_state.file_manager.config_exists():
            show_setup_wizard()
        else:
            # Load existing configuration
            try:
                config_data = st.session_state.file_manager.load_config()
                
                # Apply config to Ollama client
                if 'ollama_host' in config_data:
                    st.session_state.ollama_client.base_url = config_data['ollama_host']
                
                # Load context window setting
                if 'ollama_context_window' in config_data:
                    st.session_state.ollama_client.context_window = config_data['ollama_context_window']
                
                # Load OpenRouter API key if present
                if 'openrouter_api_key' in config_data:
                    st.session_state.openrouter_client.api_key = config_data['openrouter_api_key']
                    os.environ["OPENROUTER_API_KEY"] = config_data['openrouter_api_key']
                
                # Load active model selections
                if 'active_planner_model' in config_data:
                    st.session_state.active_planner_model = config_data['active_planner_model']
                if 'active_security_model' in config_data:
                    st.session_state.active_security_model = config_data['active_security_model']
                
                st.session_state.app_initialized = True
            except Exception as e:
                st.error(f"Failed to load configuration: {str(e)}")
                show_setup_wizard()
                return
    
    # Check authentication - require login after setup
    if st.session_state.app_initialized and not st.session_state.logged_in:
        show_login_screen()
    elif st.session_state.logged_in:
        show_chat_interface()

if __name__ == "__main__":
    main()
