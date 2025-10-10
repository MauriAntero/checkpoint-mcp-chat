# Check Point MCP Chat

**Version 0.0.1**

An AI-powered conversational interface for Check Point infrastructure management. Transform complex security operations into natural language queries, enabling administrators to orchestrate fleet-wide analysis, troubleshoot issues, and review policies through intelligent automation powered by dual LLM architecture and encrypted credential management.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Streamlit](https://img.shields.io/badge/Streamlit-1.28%2B-red)
![License](https://img.shields.io/badge/License-MIT-green)
![Version](https://img.shields.io/badge/Version-0.0.1-orange)

## Overview

Check Point MCP Chat abstracts the complexity of multi-system security operations by providing an intelligent conversational layer over Check Point's Model Context Protocol (MCP) servers. Instead of manually SSH-ing into gateways, parsing logs, or navigating multiple management interfaces, administrators can query their entire infrastructure using natural language.

### Key Capabilities

- **Intelligent Query Orchestration**: Two-stage LLM architecture (Intent Analyzer + Technical Planner) that understands admin intent and automatically routes queries across 11 specialized Check Point MCP servers
- **Fleet-Wide Operations**: Aggregate data from all managed gateways, analyze policies across the entire infrastructure, and identify anomalies at scale
- **Context-Aware Analysis**: Automatically handles API pagination, rate limiting, parameter discovery, and data aggregation with anti-hallucination safeguards
- **Policy & Rule Intelligence**: Universal output formatting matching Check Point GUI structure (8-column NAT tables, 7-column Access rules, HTTPS inspection with Site Categories)
- **Malware Analysis**: Native file upload with asynchronous Check Point Threat Emulation cloud sandbox integration, hash verification, and detailed XML report retrieval
- **Military-Grade Security**: AES-256-CBC encryption for all credentials, master password protection, no plaintext secrets on disk

### AI Architecture: Dual-Model Intelligence

The application employs a sophisticated two-model AI architecture designed for security operations:

#### 1. **Planner Model** (Intent Analysis & Orchestration)
- **Role**: Analyzes natural language queries to extract structured intent, identifies required Check Point infrastructure components, and generates technical execution plans
- **Capabilities**: 
  - Understands security context (firewall rules, threat prevention, HTTPS inspection, VPN tunnels)
  - Extracts parameters (gateway names, time ranges, IOCs, layer names) using intelligent regex patterns
  - Maps user intent to specific MCP server tools with prioritization scoring
  - Handles multi-layer resource discovery (HTTPS inspection layers, policy packages, gateway objects)
- **Recommended Models**: `anthropic/claude-3.5-sonnet`, `meta-llama/llama-3.1-405b`

#### 2. **Security Model** (Analysis & Response Generation)
- **Role**: Analyzes collected infrastructure data and generates actionable security insights with Check Point-specific expertise
- **Capabilities**:
  - Identifies security misconfigurations, policy conflicts, and threat indicators
  - Formats responses in Check Point GUI table structure (NAT, Access, HTTPS rules)
  - Provides troubleshooting guidance for connection issues, SSL/TLS decryption, and threat prevention
  - Detects anomalies in logs, gateway performance metrics, and IPS signatures
- **Recommended Models**: `meta-llama/llama-3.2-1b-instruct`, `saki007ster/cybersecurityriskanalyst`

Both models work together: the Planner decides **what** to fetch and **how** to fetch it, while the Security Model interprets **why** it matters and **what** to do about it.

### LLM Provider Options

Check Point MCP Chat supports two LLM deployment strategies to match your security and operational requirements:

#### **Ollama (Local Deployment)**
Ollama is an open-source platform that runs large language models locally on your hardware, providing complete data sovereignty. All queries and Check Point infrastructure data remain within your network, making it ideal for high-security environments with strict compliance requirements (GDPR, HIPAA, SOC 2). Once models are downloaded, there are no recurring API costs, and the system works offline. Best suited for organizations with powerful local hardware (GPU recommended) and air-gapped environments.

**Recommended Models:** Planner: `llama3.1:70b`, Security: `llama3.1:8b`

#### **OpenRouter (Cloud Deployment)**
OpenRouter provides unified access to cutting-edge LLM providers (Anthropic, OpenAI, Meta, Google) through a single API. It enables instant setup without GPU infrastructure, automatic scaling for variable workloads, and access to the latest frontier models like Claude 3.5 Sonnet and GPT-4. With pay-as-you-go pricing, teams only pay for actual usage. Ideal for rapid deployment, proof-of-concept projects, and organizations prioritizing the latest AI capabilities over data locality.

**Recommended Models:** Planner: `anthropic/claude-3.5-sonnet`, Security: `meta-llama/llama-3.2-1b-instruct`

You can also use a **hybrid approach**, mixing providers per model role—for example, using Ollama for security analysis (keeping sensitive data local) while leveraging OpenRouter's Claude for superior planning and reasoning.

## Real-World Use Cases

### 1. **Rapid Incident Response**
**Traditional Approach**: SSH into each gateway → run diagnostic commands → parse output → check management server → correlate logs → identify root cause (30-60 minutes)

**With MCP Chat**: 
```
"Debug SSL decryption failures on cp-gw for the past 2 hours"
```
**Result**: AI automatically fetches HTTPS inspection policies, SSL connection traces, certificate status, gateway diagnostics, and relevant logs from all sources, presenting a unified analysis in 45 seconds.

### 2. **Policy Review & Compliance Auditing**
**Traditional Approach**: Export rulebase → open in Excel → manually review each rule → check NAT policies separately → cross-reference objects → document findings (2-4 hours per gateway)

**With MCP Chat**:
```
"Review all firewall policies on gw-prod-01 and identify overly permissive rules"
```
**Result**: Displays complete NAT and Access rulebases in GUI-matching markdown tables with AI analysis highlighting "Any-Any-Accept" rules, unused objects, and security risks in under 60 seconds.

### 3. **Fleet-Wide Threat Hunting**
**Traditional Approach**: Log into each gateway → query threat logs → filter by IOC → export → consolidate in spreadsheet → analyze patterns (1-2 hours)

**With MCP Chat**:
```
"Search all gateways for connections to IP 185.220.101.45 in the last 24 hours"
```
**Result**: Automatically queries all management logs across the fleet, aggregates findings with pagination handling, and presents threat correlation analysis with recommended actions.

### 4. **Performance Troubleshooting**
**Traditional Approach**: SSH into gateway → run fw ctl pstat, fwaccel stats, cpstat → interpret cryptic outputs → check interface stats → correlate metrics (20-30 minutes)

**With MCP Chat**:
```
"Analyze gateway performance metrics on all production gateways"
```
**Result**: Executes 26 diagnostic tools in parallel with intelligent rate limiting, presents CPU/memory/connection stats, SecureXL status, and identifies performance bottlenecks with visual comparisons.

### 5. **Malware Analysis Workflow**
**Traditional Approach**: Download suspicious file → upload to Check Point portal → wait for sandbox → check report → interpret XML → document findings (15-20 minutes)

**With MCP Chat**:
```
Upload file via UI → "Analyze this file for malware"
```
**Result**: Auto-computes hash, submits to Threat Emulation cloud, monitors async job, retrieves verdict and detailed XML report, presents formatted analysis with severity scoring.

## Supported Check Point MCP Servers

Integrate with Check Point's open-source Model Context Protocol servers for comprehensive infrastructure access:

| Server Type | Package | Description |
|-------------|---------|-------------|
| **Management** | `@chkp/quantum-management-mcp` | Policy and object management, network topology |
| **Management Logs** | `@chkp/management-logs-mcp` | Connection and audit log analysis |
| **Threat Prevention** | `@chkp/threat-prevention-mcp` | Threat policies, profiles, and IOC feeds |
| **HTTPS Inspection** | `@chkp/https-inspection-mcp` | HTTPS inspection policies and exceptions |
| **Harmony SASE** | `@chkp/harmony-sase-mcp` | SASE regions, networks, and applications |
| **Reputation Service** | `@chkp/reputation-service-mcp` | URL, IP, and file reputation queries |
| **Gateway CLI** | `@chkp/quantum-gw-cli-mcp` | Comprehensive gateway diagnostics |
| **Connection Analysis** | `@chkp/quantum-gw-connection-analysis-mcp` | Connection issue debugging |
| **Threat Emulation** | `@chkp/threat-emulation-mcp` | Cloud-based malware analysis |
| **GAIA** | `@chkp/quantum-gaia-mcp` | Network interface configuration |
| **Spark Management** | `@chkp/spark-management-mcp` | Quantum Spark appliance management |

**Check Point MCP GitHub Repository**: [https://github.com/CheckPointSW](https://github.com/CheckPointSW)

## Advanced Features

### 🛡️ Gateway Script Executor (Optional)

The Gateway Script Executor provides a secure way to execute diagnostic commands directly on Check Point gateways using the Management API's `run-script` function. This advanced feature enables LLM-driven diagnostics while maintaining enterprise-grade safety through multi-layer validation.

#### Safety Architecture

**Multi-Layer Command Validation:**
1. **Whitelist Validation** - Only pre-approved commands from Check Point R81/R82 CLI Reference Guide
2. **Pattern Blocking** - Regex-based detection of dangerous operations (cpstop, kill, rm, etc.)
3. **Special Character Filtering** - Blocks command chaining, redirects, and code injection
4. **Non-Interactive Enforcement** - Only snapshot commands allowed (e.g., `top -n 1`, no interactive TUIs)
5. **Audit Logging** - Every command execution is logged with timestamps

**What's Allowed (120+ Safe Commands):**
- ✅ System info: `show version`, `fw ver`, `uptime`
- ✅ Network status: `ifconfig`, `show interfaces`, `netstat -rn`
- ✅ Firewall status: `fw stat`, `fw ctl pstat`, `fwaccel stat`
- ✅ Cluster HA: `cphaprob state`, `cphaprob -a if`
- ✅ Performance: `top -n 1`, `ps aux`, `cpstat os -f all`
- ✅ VPN status: `vpn tu tlist`, `cpstat vpn`
- ✅ Logs (read-only): `fw log`, `cat $FWDIR/log/fw.elg`

**What's Blocked:**
- ❌ Service control: `cpstop`, `cpstart`, `api restart`
- ❌ Process control: `kill`, `pkill`, `killall`
- ❌ File operations: `rm`, `mv`, `chmod`, `dd`
- ❌ Configuration changes: `set`, `add`, `delete`, `commit`
- ❌ Interactive shells: `vpn shell`, `cpview`, `cpconfig`
- ❌ Command chaining: pipes `|`, redirects `>`, substitution `$()`

**Complete command list:** `docs/GATEWAY_SAFE_COMMANDS_LIST.txt`

#### Prerequisites

Your Management API administrator user requires these permissions:

1. **Management API Login** ✓ (You already have this if using Management MCP)
2. **Gateways → Scripts (Write)** ← Required for run-script

**Setup in SmartConsole:**
```
1. Navigate to: Manage & Settings → Permissions & Administrators
2. Select your API admin user → Edit
3. Select Permission Profile → Edit Profile
4. Go to: Gateways → Scripts
5. Enable: Write permission
6. Click OK and Publish changes
```

**⚠️ Security Note**: `run-script` executes commands at expert/root level on gateways. Check Point acknowledges this limitation - there are no granular command restrictions at the API level. That's why this application implements its own strict validation layer.

#### How to Enable

1. **Enable in Settings UI:**
   - Open Settings page (⚙️ icon)
   - Scroll to "Gateway Script Executor (Advanced)"
   - Check "Enable Gateway Script Executor"
   - Review the Management API permissions instructions

2. **Verify Permissions:**
   - Ensure your API user has "Scripts (Write)" permission in SmartConsole
   - Test with a safe command: `"Show gateway version on cp-gw"`

3. **Usage:**
   ```
   User: "Check gateway version on prod-gw-01"
   AI: [Validates command] → Executes "fw ver" → Returns output
   
   User: "Show cluster status"
   AI: [Validates command] → Executes "cphaprob state" → Analyzes results
   ```

The LLM automatically suggests appropriate diagnostic commands based on your query. All commands are validated before execution - even if the LLM suggests an unsafe command, it will be blocked by the validation system.

**Audit & Compliance:**
- All executions logged with timestamps, gateway names, and commands
- Only commands from audited whitelist (approved by security architect)
- Zero-risk: Cannot modify configurations or disrupt services
- Full transparency: See exactly what commands run

## Installation

### Prerequisites

- **Python 3.8+**
- **Node.js 16+** and npm
- **Ollama** (optional, for local LLM) or **OpenRouter API key** (for cloud LLM)

---

### macOS Installation

#### 1. Install Homebrew (if not installed)
```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

#### 2. Install Python and Node.js
```bash
brew install python@3.11 node
```

#### 3. Clone the Repository
```bash
git clone https://github.com/MauriAntero/checkpoint-mcp-chat.git
cd checkpoint-mcp-chat
```

#### 4. Create Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate
```

#### 5. Install Python Dependencies
```bash
pip install -e .
```

Or install packages individually:
```bash
pip install streamlit cryptography pandas plotly psutil pyyaml requests gitpython
```

#### 6. Verify Streamlit Configuration
The `.streamlit/config.toml` file is included in the repository and contains the required theme and server settings. If for any reason it's missing, create it:
```bash
mkdir -p .streamlit
cat > .streamlit/config.toml << EOF
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
EOF
```

#### 7. Run the Application
```bash
streamlit run app.py --server.port 5000
```

Access at: `http://localhost:5000`

---

### Windows Installation

#### 1. Install Python
- Download from [python.org](https://www.python.org/downloads/)
- **Important**: Check "Add Python to PATH" during installation

#### 2. Install Node.js
- Download from [nodejs.org](https://nodejs.org/)
- Install with default settings

#### 3. Clone the Repository
```cmd
git clone https://github.com/MauriAntero/checkpoint-mcp-chat.git
cd checkpoint-mcp-chat
```

#### 4. Create Virtual Environment
```cmd
python -m venv venv
venv\Scripts\activate
```

#### 5. Install Python Dependencies
```cmd
pip install -e .
```

Or install packages individually:
```cmd
pip install streamlit cryptography pandas plotly psutil pyyaml requests gitpython
```

#### 6. Verify Streamlit Configuration
The `.streamlit/config.toml` file is included in the repository and contains the required theme and server settings. If for any reason it's missing, create it manually with a text editor or use PowerShell:
```powershell
@"
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
"@ | Out-File -FilePath .streamlit\config.toml -Encoding UTF8
```

#### 7. Run the Application
```cmd
streamlit run app.py --server.port 5000
```

Access at: `http://localhost:5000`

---

### Linux Installation (Ubuntu/Debian)

#### 1. Update System
```bash
sudo apt update && sudo apt upgrade -y
```

#### 2. Install Python and Node.js
```bash
sudo apt install -y python3 python3-pip python3-venv nodejs npm git
```

#### 3. Clone the Repository
```bash
git clone https://github.com/MauriAntero/checkpoint-mcp-chat.git
cd checkpoint-mcp-chat
```

#### 4. Create Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate
```

#### 5. Install Python Dependencies
```bash
pip install -e .
```

Or install packages individually:
```bash
pip install streamlit cryptography pandas plotly psutil pyyaml requests gitpython
```

#### 6. Verify Streamlit Configuration
The `.streamlit/config.toml` file is included in the repository and contains the required theme and server settings. If for any reason it's missing, create it:
```bash
mkdir -p .streamlit
cat > .streamlit/config.toml << EOF
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
EOF
```

#### 7. Run the Application
```bash
streamlit run app.py --server.port 5000
```

Access at: `http://localhost:5000`

---

### Linux Installation (RHEL/CentOS/Fedora)

#### 1. Update System
```bash
sudo dnf update -y  # or 'sudo yum update -y' for older versions
```

#### 2. Install Python and Node.js
```bash
sudo dnf install -y python3 python3-pip nodejs npm git
```

#### 3. Follow steps 3-7 from Ubuntu/Debian instructions above

---

## Configuration

### First-Time Setup

1. **Open the application** at `http://localhost:5000`
2. **Complete the setup wizard**:
   - Set a master password for encryption
   - Configure Ollama or OpenRouter (or both)
   - Select planner and security analysis models

### LLM Provider Configuration

#### Option 1: Ollama (Local)
1. Install Ollama from [ollama.ai](https://ollama.ai)
2. Start Ollama service:
   ```bash
   ollama serve
   ```
3. Pull required models:
   ```bash
   ollama pull llama3.1
   ollama pull saki007ster/cybersecurityriskanalyst
   ```
4. Configure in app settings:
   - Ollama Server: `http://localhost:11434`
   - Test connection to fetch available models

#### Option 2: OpenRouter (Cloud)
1. Get API key from [openrouter.ai](https://openrouter.ai)
2. Configure in app settings:
   - Enter OpenRouter API Key
   - Test connection to fetch available models
3. Recommended models:
   - Planner: `anthropic/claude-3.5-sonnet`
   - Security: `meta-llama/llama-3.2-1b-instruct`

### MCP Server Configuration

1. Go to **Settings** (gear icon in chat)
2. Scroll to **Check Point MCP Servers**
3. Click **Refresh Versions** to check installation status
4. Expand a server and fill in credentials:
   - **Cloud Mode**: S1C URL, Client ID, Secret Key, Tenant ID
   - **On-Premise Mode**: Management Host, API Key
   - **Dual Mode**: Configure both (server auto-detects)
5. Click **Save Configuration** (auto-installs package)
6. Click **Start Server** to activate

## Usage

### Basic Queries
```
"Show me all firewall policies"
"Analyze recent security threats"
"List all gateway connections"
"Check HTTPS inspection status"
```

### Advanced Queries
```
"Analyze all gateway logs for the past 24 hours and identify anomalies"
"Compare threat prevention policies across all gateways"
"Investigate connection failures to 192.168.1.100"
"Show me IOC feeds and correlate with recent events"
"Review NAT and Access policies on gw-dmz and flag overly permissive rules"
"Debug SSL decryption issues on cp-gw with certificate and layer analysis"
```

The AI-powered orchestrator will:
1. Analyze your query intent
2. Determine which MCP servers to query
3. Collect and synthesize data
4. Provide comprehensive analysis

## Troubleshooting

### Common Issues

#### Port 5000 Already in Use
```bash
# Find process using port
lsof -i :5000          # macOS/Linux
netstat -ano | findstr :5000  # Windows

# Use different port
streamlit run app.py --server.port 8501
```

#### Ollama Connection Failed
```bash
# Check Ollama status
curl http://localhost:11434/api/version

# Start Ollama
ollama serve

# Update server address in app settings
```

#### MCP Package Installation Fails
```bash
# Update npm
npm install -g npm@latest

# Clear cache
npm cache clean --force

# Install manually
npx @chkp/quantum-management-mcp@latest
```

#### Module Not Found Errors
```bash
# Activate virtual environment
source venv/bin/activate  # macOS/Linux
venv\Scripts\activate     # Windows

# Reinstall dependencies
pip install -e .
```

## Security

- All sensitive credentials are encrypted using AES-256-CBC encryption
- Master password never stored, only derived encryption key
- Credentials decrypted at runtime into environment variables
- No plaintext secrets on disk

## Contributing

Contributions are welcome! Please follow these guidelines:
- Fork the repository
- Create a feature branch
- Submit pull requests with clear descriptions
- Follow existing code style and conventions

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Check Point for MCP server packages and security infrastructure
- Streamlit for the web framework
- Ollama and OpenRouter for LLM infrastructure
- The open-source community

---

**Version 0.0.1** | Built for Check Point Administrators
