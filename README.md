# Check Point MCP Chat

**AI-Powered Security Operations Platform for Check Point Infrastructure**

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Streamlit](https://img.shields.io/badge/Streamlit-1.28%2B-red)
![License](https://img.shields.io/badge/License-MIT-green)

---

## Why Choose a Specialized Security Platform?

Generic AI assistants lack the infrastructure connectivity, automation capabilities, and security expertise required for enterprise operations. Check Point MCP Chat bridges this gap by providing:

### **Direct Infrastructure Integration**
- **Real-time data access** from Check Point management servers and gateways
- **Automated query orchestration** across 11 specialized MCP servers
- **Fleet-wide operations** aggregating data from all managed devices
- **No manual data export** or copy-paste workflows required

### **Security-Optimized AI Architecture**
- **Dual LLM design**: Intent Analyzer for orchestration + Security Model for Check Point-specific analysis
- **Anti-hallucination safeguards** with intelligent parameter extraction and validation
- **Context-aware processing** handling API pagination, rate limiting, and resource discovery automatically
- **Structured output formatting** matching Check Point GUI tables (NAT, Access, HTTPS rules)

### **Enterprise-Grade Security**
- **Military-grade encryption** (AES-256-CBC) for all credentials
- **Local or cloud LLM deployment** options (Ollama for data sovereignty, OpenRouter for frontier models)
- **Zero plaintext secrets** on disk with master password protection
- **Complete audit trail** with persistent logging of all operations

### **Operational Efficiency**
Transform hours of manual work into seconds of natural language queries:
- **Incident Response**: "Debug SSL decryption failures on cp-gw for the past 2 hours" → 45 seconds vs. 30-60 minutes
- **Policy Review**: "Review all firewall policies and identify overly permissive rules" → 60 seconds vs. 2-4 hours
- **Threat Hunting**: "Search all gateways for connections to IP 185.220.101.45" → Instant vs. 1-2 hours
- **Performance Analysis**: "Analyze gateway metrics across all production gateways" → Parallel execution with visual comparisons

---

## Core Capabilities

### **Intelligent Query Orchestration**
Two-stage LLM architecture analyzes admin intent, extracts parameters (gateway names, time ranges, IOCs), and automatically routes queries across Check Point infrastructure with intelligent tool prioritization.

### **Fleet-Wide Analysis**
Aggregate data from all managed gateways, analyze policies across the entire infrastructure, and identify anomalies at scale with automatic pagination and deduplication.

### **Policy & Rule Intelligence**
Universal output formatting with GUI-matching structure (8-column NAT tables, 7-column Access rules, HTTPS inspection with Site Categories). AI-powered analysis highlights security risks and compliance gaps.

### **Advanced Threat Analysis**
Native file upload with asynchronous Check Point Threat Emulation cloud sandbox integration, hash verification, and detailed XML report retrieval. Correlate IOCs across fleet-wide logs.

### **Gateway Script Executor** *(Optional)*
Execute safe diagnostic commands on gateways via Management API's run-script endpoint with multi-layer validation (whitelist, pattern blocking, special character filtering). 120+ approved commands for diagnostics without service disruption.

---

## Supported Check Point MCP Servers

| Server Type | Description |
|-------------|-------------|
| **Management** | Policy/object management, network topology |
| **Management Logs** | Connection and audit log analysis |
| **Threat Prevention** | Threat policies, profiles, IOC feeds |
| **HTTPS Inspection** | SSL/TLS decryption policies and exceptions |
| **Gateway CLI** | Comprehensive gateway diagnostics (26+ tools) |
| **Connection Analysis** | Connection issue debugging and troubleshooting |
| **Threat Emulation** | Cloud-based malware analysis sandbox |
| **Reputation Service** | URL, IP, and file reputation queries |
| **GAIA** | Network interface configuration |
| **Harmony SASE** | SASE regions, networks, applications |
| **Spark Management** | Quantum Spark appliance management |

**Check Point MCP GitHub**: [https://github.com/CheckPointSW](https://github.com/CheckPointSW)

---

## Installation

### Prerequisites
- Python 3.8 or higher
- Node.js 16 or higher
- Git
- LLM Provider: [Ollama](https://ollama.ai) (local) or [OpenRouter](https://openrouter.ai) API key (cloud)

---

### macOS

#### 1. Install Homebrew (if not already installed)
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
pip install streamlit cryptography pandas plotly psutil pyyaml requests gitpython
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
pip install streamlit cryptography pandas plotly psutil pyyaml requests gitpython
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
- Install with default settings (includes npm)
- Verify installation:
  ```cmd
  node --version
  npm --version
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
pip install streamlit cryptography pandas plotly psutil pyyaml requests gitpython
```

**Troubleshooting**: If `pip` command fails:
```cmd
python -m pip install --upgrade pip
python -m pip install streamlit cryptography pandas plotly psutil pyyaml requests gitpython
```

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

## First-Time Configuration

### 1. Security Setup
- Set a **master password** for credential encryption
- Choose deployment mode: **Cloud** (S1C), **On-Premise**, or **Dual**

### 2. LLM Provider Configuration

#### Option A: Ollama (Local - Data Sovereignty)
```bash
# Install Ollama from https://ollama.ai
ollama serve

# Pull recommended models
ollama pull llama3.1:70b    # Planner model
ollama pull llama3.1:8b     # Security model
```
Configure in app: Ollama Server → `http://localhost:11434`

#### Option B: OpenRouter (Cloud - Best Performance)
1. Get API key from [openrouter.ai](https://openrouter.ai)
2. Configure in app settings
3. Recommended models:
   - **Planner**: `anthropic/claude-3.5-sonnet`
   - **Security**: `meta-llama/llama-3.2-1b-instruct`

**Performance Note**: Testing shows OpenRouter models significantly outperform local models for complex security analysis. Local models struggle with multi-step reasoning and rule correlation.

### 3. MCP Server Configuration
1. Navigate to **Settings** (⚙️ icon)
2. Expand desired MCP server
3. Enter credentials:
   - **Cloud**: S1C URL, Client ID, Secret Key, Tenant ID
   - **On-Premise**: Management Host, API Key
4. Click **Save Configuration** (auto-installs package)
5. Click **Start Server**

---

## Usage Examples

### Basic Queries
```
"Show all firewall policies"
"Analyze recent security threats"
"Check HTTPS inspection status on cp-gw"
"List all VPN tunnels"
```

### Advanced Operations
```
"Troubleshoot connectivity from 192.168.1.15 to 212.59.66.78 in last 24 hours"
"Review NAT and Access policies on prod-gw and identify overly permissive rules"
"Search all gateways for connections to malicious IP 185.220.101.45"
"Debug SSL decryption failures with certificate and layer analysis"
"Analyze gateway performance metrics across all production gateways"
```

### Malware Analysis
1. Upload file via UI
2. Query: `"Analyze this file for malware"`
3. System automatically: computes hash → submits to Threat Emulation → retrieves verdict → presents analysis

---

## Troubleshooting

### Port Already in Use
```bash
# macOS/Linux
lsof -i :5000
streamlit run app.py --server.port 8501

# Windows
netstat -ano | findstr :5000
streamlit run app.py --server.port 8501
```

### Ollama Connection Failed
```bash
# Verify Ollama is running
curl http://localhost:11434/api/version

# Start Ollama
ollama serve
```

### Module Not Found
```bash
# Ensure virtual environment is activated
source venv/bin/activate  # macOS/Linux
venv\Scripts\activate     # Windows

# Reinstall dependencies
pip install streamlit cryptography pandas plotly psutil pyyaml requests gitpython
```

### MCP Package Installation Fails
```bash
# Update npm
npm install -g npm@latest

# Clear cache and retry
npm cache clean --force
```

---

## Architecture

### Dual LLM Design
1. **Planner Model** - Intent analysis, parameter extraction, technical execution planning
2. **Security Model** - Check Point-specific analysis, threat correlation, actionable insights

### Security Features
- AES-256-CBC encryption for all credentials
- Master password derivation (never stored)
- Runtime decryption into environment variables
- Zero plaintext secrets on disk
- Complete audit logging

---

## License

MIT License - See LICENSE file for details

## Acknowledgments

Built with Check Point MCP servers, Streamlit, and modern LLM infrastructure (Ollama/OpenRouter)

---

**Version 0.0.1** | Engineered for Check Point Security Administrators
