# Check Point MCP Chat

**AI-Powered Security Operations Platform for Check Point Infrastructure**

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Streamlit](https://img.shields.io/badge/Streamlit-1.28%2B-red)
![License](https://img.shields.io/badge/License-MIT-green)

---

## Overview

Check Point MCP Chat provides a conversational interface for Check Point infrastructure management through direct integration with Model Context Protocol (MCP) servers. The platform employs a dual LLM architecture to orchestrate queries across 11 specialized Check Point MCP servers, enabling administrators to perform fleet-wide analysis, policy reviews, and troubleshooting operations through natural language.

### Key Features

**Infrastructure Integration**
- Direct API connectivity to Check Point management servers and gateways
- Automated query orchestration across 11 MCP server types
- Fleet-wide data aggregation with automatic pagination and deduplication
- Real-time access to policies, logs, configurations, and diagnostics

**AI Architecture**
- Dual LLM design: Intent Analyzer for query planning, Security Model for Check Point-specific analysis
- Intelligent parameter extraction (gateway names, time ranges, IOCs, layer names)
- Anti-hallucination safeguards with validation and error handling
- Structured output formatting matching Check Point GUI tables (NAT, Access, HTTPS rules)

**Security**
- AES-256-CBC encryption for credential storage
- Master password-based key derivation
- Runtime credential decryption to environment variables
- Persistent audit logging
- Local (Ollama) or cloud (OpenRouter) LLM deployment options

**Operational Capabilities**
- Policy and rule analysis with compliance gap identification
- Multi-gateway threat hunting and IOC correlation
- SSL/TLS inspection troubleshooting with certificate validation
- Gateway performance diagnostics with parallel tool execution
- File-based malware analysis via Threat Emulation cloud sandbox

---

## Supported MCP Servers

| Server Type | Package | Capabilities |
|-------------|---------|--------------|
| **Management** | `@chkp/quantum-management-mcp` | Policy/object management, network topology |
| **Management Logs** | `@chkp/management-logs-mcp` | Connection and audit log analysis |
| **Threat Prevention** | `@chkp/threat-prevention-mcp` | Threat policies, profiles, IOC feeds |
| **HTTPS Inspection** | `@chkp/https-inspection-mcp` | SSL/TLS decryption policies and exceptions |
| **Gateway CLI** | `@chkp/quantum-gw-cli-mcp` | Gateway diagnostics (26+ tools) |
| **Connection Analysis** | `@chkp/quantum-gw-connection-analysis-mcp` | Connection troubleshooting |
| **Threat Emulation** | `@chkp/threat-emulation-mcp` | Cloud-based malware analysis |
| **Reputation Service** | `@chkp/reputation-service-mcp` | URL, IP, and file reputation queries |
| **GAIA** | `@chkp/quantum-gaia-mcp` | Network interface configuration |
| **Harmony SASE** | `@chkp/harmony-sase-mcp` | SASE infrastructure management |
| **Spark Management** | `@chkp/spark-management-mcp` | Quantum Spark appliance management |

**Check Point MCP Repository**: [https://github.com/CheckPointSW](https://github.com/CheckPointSW)

---

## Gateway Script Executor

Optional feature for executing diagnostic commands on Check Point gateways via Management API's `run-script` endpoint.

**Security Model**
- Whitelist validation (120+ approved commands from Check Point R81/R82 CLI Reference)
- Pattern-based blocking of destructive operations (cpstop, kill, rm, configuration changes)
- Special character filtering (pipes, redirects, command substitution)
- Non-interactive enforcement (snapshot commands only)
- Persistent audit logging with timestamps

**Approved Command Categories**
- System diagnostics: `show version`, `fw ver`, `uptime`
- Network status: `ifconfig`, `netstat -rn`, `ip route show`
- Firewall inspection: `fw stat`, `fw ctl pstat`, `fwaccel stat`
- Cluster HA: `cphaprob state`, `cphaprob -a if`
- Performance monitoring: `top -n 1`, `cpstat os -f all`
- VPN status: `vpn tu tlist`, `cpstat vpn`

**Blocked Operations**
- Service control: `cpstop`, `cpstart`, `api restart`
- Process termination: `kill`, `pkill`, `killall`
- File system modifications: `rm`, `mv`, `chmod`, `dd`
- Configuration changes: `set`, `add`, `delete`, `commit`
- Interactive shells: `vpn shell`, `cpview`, `cpconfig`

**Prerequisites**
- Management API user with "Gateways → Scripts (Write)" permission
- Enable in Settings UI under "Gateway Script Executor (Advanced)"

---

## Installation

### Prerequisites
- Python 3.11+
- Node.js 16+
- Git
- LLM Provider: [Ollama](https://ollama.ai) (local) or [OpenRouter](https://openrouter.ai) API key (cloud)
- **Windows only**: CMake and Microsoft C++ Build Tools required (auto-installed via Node.js setup - see Windows installation notes)

---

### macOS

#### 1. Install Homebrew (if not installed)
```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

#### 2. Install dependencies
```bash
brew install python@3.11 node git
```

#### 3. Clone repository and setup
```bash
git clone https://github.com/MauriAntero/checkpoint-mcp-chat.git
cd checkpoint-mcp-chat
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

#### 4. Run application
```bash
streamlit run app.py --server.port 5000
```

Access at: **http://localhost:5000**

---

### Ubuntu

#### 1. Update system and install dependencies
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3 python3-pip python3-venv nodejs npm git
```

#### 2. Clone repository and setup
```bash
git clone https://github.com/MauriAntero/checkpoint-mcp-chat.git
cd checkpoint-mcp-chat
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

#### 3. Run application
```bash
streamlit run app.py --server.port 5000
```

Access at: **http://localhost:5000**

---

### Windows

#### 1. Install Python
- Download Python 3.11+ from [python.org](https://www.python.org/downloads/)
- **CRITICAL**: Check **"Add Python to PATH"** during installation
- Verify installation:
  ```cmd
  python --version
  pip --version
  ```

#### 2. Install Node.js
- Download Node.js 18+ LTS from [nodejs.org](https://nodejs.org/)
- **CRITICAL**: During installation, check the box **"Automatically install the necessary tools"**
  - This installs Chocolatey and build tools (Python, Visual Studio Build Tools)
  - Required for MCP npm packages and Python cryptography package
  - Saves troubleshooting later
- Complete the installation and allow the post-install script to run (opens PowerShell window)
- **After Node.js installation completes**, install CMake (required for PyArrow dependency):
  - If Chocolatey was installed in previous step, run in **PowerShell as Administrator**:
    ```powershell
    choco install cmake -y
    ```
  - **OR** download CMake installer from [cmake.org/download](https://cmake.org/download/) and install manually
- **Restart your terminal/PowerShell** after CMake installation
- Verify installation:
  ```cmd
  node --version
  npm --version
  cmake --version
  ```

#### 3. Install Git
- Download Git from [git-scm.com](https://git-scm.com/download/win)
- Install with default settings
- Verify installation:
  ```cmd
  git --version
  ```

#### 4. Clone repository
Open **Command Prompt** or **PowerShell**:
```cmd
git clone https://github.com/MauriAntero/checkpoint-mcp-chat.git
cd checkpoint-mcp-chat
```

#### 5. Create virtual environment
```cmd
python -m venv venv
venv\Scripts\activate
```

**Note**: If you see an error about execution policies in PowerShell, run:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

#### 6. Install Python dependencies
```cmd
pip install -e .
```

**Troubleshooting**:

If `pip` command fails:
```cmd
python -m pip install --upgrade pip
python -m pip install -e .
```

If you see errors about `cryptography` package or "Microsoft Visual C++ 14.0 is required":
- Download and install [Microsoft C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/)
- During installation, select "Desktop development with C++"
- Restart Command Prompt/PowerShell and retry `pip install -e .`

If you see errors about `PyArrow` or "CMake must be installed":
- Install CMake: `choco install cmake -y` (PowerShell as Administrator)
- OR download from [cmake.org/download](https://cmake.org/download/)
- Restart Command Prompt/PowerShell and retry `pip install -e .`

#### 7. Verify Streamlit configuration
The `.streamlit/config.toml` file is included. If missing, create it:
```cmd
mkdir .streamlit
notepad .streamlit\config.toml
```
Paste this content:
```toml
[server]
headless = true
address = "0.0.0.0"
port = 5000

[theme]
primaryColor = "#EE0C5D"
backgroundColor = "#f5f7fa"
secondaryBackgroundColor = "#FFFFFF"
textColor = "#1a1a1a"
font = "sans serif"

[browser]
gatherUsageStats = false
```

#### 8. Run application
```cmd
streamlit run app.py --server.port 5000
```

Access at: **http://localhost:5000**

**Note**: Windows Firewall may prompt for network access - click "Allow access"

---

## Configuration

### Initial Setup
1. Set master password for credential encryption
2. Configure LLM provider (Ollama or OpenRouter)
3. Add MCP server credentials

### LLM Provider Configuration

#### Ollama (Local Deployment)
```bash
# Install from https://ollama.ai
ollama serve

# Pull models
ollama pull llama3.1:70b    # Planner model
ollama pull llama3.1:8b     # Security model
```
Configure Ollama server: `http://localhost:11434`

#### OpenRouter (Cloud Deployment)
1. Obtain API key from [openrouter.ai](https://openrouter.ai)
2. Configure in application settings
3. Recommended models:
   - Planner: `anthropic/claude-3.5-sonnet`
   - Security: `meta-llama/llama-3.2-1b-instruct`

**Note**: Testing indicates OpenRouter models provide superior performance for complex security analysis compared to local models.

### MCP Server Configuration
1. Navigate to Settings (⚙️)
2. Expand target MCP server
3. Enter credentials:
   - **Cloud**: S1C URL, Client ID, Secret Key, Tenant ID
   - **On-Premise**: Management Host, API Key
4. Save configuration (auto-installs npm package)
5. Start server

---

## Usage

### Query Examples

**Basic Operations**
```
"Show all firewall policies"
"Analyze recent security threats"
"Check HTTPS inspection status on cp-gw"
"List VPN tunnels"
```

**Advanced Operations**
```
"Troubleshoot connectivity from 192.168.1.15 to 212.59.66.78 in last 24 hours"
"Review NAT and Access policies on prod-gw and identify overly permissive rules"
"Search all gateways for connections to IP 185.220.101.45"
"Debug SSL decryption failures with certificate analysis"
"Analyze gateway performance metrics across production infrastructure"
```

**Malware Analysis**
1. Upload file via UI
2. Query: `"Analyze this file for malware"`
3. System executes: hash computation → Threat Emulation submission → report retrieval

---

## Troubleshooting

### Port Conflict
```bash
# macOS/Linux
lsof -i :5000
streamlit run app.py --server.port 8501

# Windows
netstat -ano | findstr :5000
streamlit run app.py --server.port 8501
```

### Ollama Connection Failure
```bash
# Verify service status
curl http://localhost:11434/api/version

# Start service
ollama serve
```

### Python Module Errors
```bash
# Activate virtual environment
source venv/bin/activate  # macOS/Linux
venv\Scripts\activate     # Windows

# Reinstall dependencies
pip install -e .
```

### MCP Package Installation Failure
```bash
# Update npm
npm install -g npm@latest

# Clear cache
npm cache clean --force
```

---

## Architecture

### Dual LLM System
1. **Planner Model**: Intent analysis, parameter extraction, execution planning
2. **Security Model**: Check Point domain analysis, threat correlation, policy interpretation

### Security Implementation
- AES-256-CBC credential encryption
- Master password key derivation (PBKDF2)
- Runtime environment variable injection
- Persistent audit logging with timestamps
- Zero plaintext secrets on disk

---

## License

MIT License - See LICENSE file for details

## Acknowledgments

Built with Check Point MCP servers, Streamlit, and LLM infrastructure (Ollama/OpenRouter)

---

**Version 0.0.1** | Build for Check Point administrators! 
