# Network Security Admin Intent Classification Guide

## Overview
This document maps all possible network security administrator queries to their correct intent types, ensuring the system provides the appropriate response for each scenario.

## Intent Types & Query Examples

### 1. **policy_review** - Display/View Configuration
**Purpose**: Show raw data without analysis or interpretation  
**Server Mapping**: quantum-management, threat-prevention, https-inspection, management-logs  
**Response Style**: Simple display, formatted tables, lists

**Example Queries:**
- "show me the firewall rules"
- "list NAT rules"
- "what VPN communities exist"
- "display IPS profiles"
- "get gateway configuration"
- "show access layers"
- "what are the unused rules"
- "find zero hit rules"
- "list threat prevention profiles"
- "show HTTPS inspection policies"
- "what gateways are configured"
- "show all network objects"

**Expected Behavior**: Return requested data formatted as tables/lists without analysis

---

### 2. **troubleshooting** - Diagnose WHY Something is Broken
**Purpose**: Root cause analysis for connectivity/functionality issues  
**Server Mapping**: management-logs, quantum-management, quantum-gw-cli (optional)  
**Response Style**: Step-by-step diagnostic analysis with cause identification

**Example Queries:**
- "why can't user X connect to server Y"
- "debug connectivity issue from 192.168.1.10 to 10.0.0.5"
- "connection to web server is failing"
- "traffic from subnet A to subnet B is being dropped"
- "why is connection slow between sites"
- "investigate timeout connecting to application"
- "user can't access internet, why"
- "VPN connection drops frequently, diagnose"
- "email server unreachable from office, investigate"

**Expected Behavior**: 
1. Check logs for drops/blocks
2. Correlate with firewall rules
3. Analyze NAT/routing if needed
4. Run gateway diagnostics if required
5. Provide root cause and fix recommendations

---

### 3. **security_investigation** - Hunt for Threats/Attacks
**Purpose**: Find actual threat events and malicious activity  
**Server Mapping**: management-logs (primary)  
**Response Style**: Threat-focused analysis with severity assessment

**Example Queries:**
- "any suspicious activity on my network"
- "detect threats from last 24 hours"
- "find malware infections"
- "show intrusion attempts"
- "identify compromised hosts"
- "exploit detection last week"
- "scan for attack patterns"
- "any SQL injection attempts"
- "detect port scanning activity"
- "find brute force login attempts"

**Expected Behavior**: Search threat prevention logs, identify security events, assess severity

---

### 4. **log_analysis** - Examine Traffic Patterns
**Purpose**: Descriptive traffic analysis (not diagnostic)  
**Server Mapping**: management-logs, quantum-management (context)  
**Response Style**: Descriptive summary of traffic patterns

**Example Queries:**
- "show logs from IP 192.168.1.15"
- "traffic to port 443 last hour"
- "what hit rule 5"
- "connections from subnet 10.0.0.0/24"
- "bandwidth usage patterns today"
- "top talkers last week"
- "application usage statistics"
- "show all HTTPS traffic"
- "connections to external IP 8.8.8.8"
- "traffic patterns for finance department"

**Expected Behavior**: Retrieve and summarize traffic logs, show patterns/statistics

---

### 5. **network_analysis** - Network Infrastructure/Topology
**Purpose**: Understand network structure and status  
**Server Mapping**: quantum-management, quantum-gw-cli, quantum-gaia  
**Response Style**: Infrastructure overview and status information

**Example Queries:**
- "show network topology"
- "what networks are defined"
- "gateway status"
- "show interface information"
- "display routing tables"
- "VPN tunnel status"
- "cluster state"
- "HA status"
- "show all subnets"
- "gateway IP addresses"
- "interface eth2 status"
- "routing table for gateway cp-gw"

**Expected Behavior**: Provide network infrastructure details, topology, interface/routing info

---

### 6. **threat_assessment** - Security Posture Evaluation
**Purpose**: Forward-looking security assessment and recommendations  
**Server Mapping**: quantum-management, threat-prevention, https-inspection, management-logs  
**Response Style**: Assessment with recommendations

**Example Queries:**
- "assess our security posture"
- "vulnerability assessment"
- "security risk analysis"
- "compliance check"
- "identify policy gaps"
- "security recommendations"
- "evaluate threat protection coverage"
- "assess firewall policy effectiveness"
- "analyze security configuration"
- "recommend security improvements"

**Expected Behavior**: Analyze security configuration, identify gaps, provide recommendations

---

### 7. **general_info** - Help/Information Requests
**Purpose**: General questions and help  
**Server Mapping**: All servers (as needed)  
**Response Style**: Informational/instructional

**Example Queries:**
- "how does this work"
- "explain firewall rules"
- "what capabilities do you have"
- "what can you help me with"
- "how to configure NAT"
- "what is IPS"

**Expected Behavior**: Provide informational/educational response

---

## Performance Queries (Special Override)
**Purpose**: Gateway performance and capacity analysis  
**Server Mapping**: quantum-gw-cli, quantum-management, quantum-gaia  
**Response Style**: Metrics and performance data

**Example Queries:**
- "gateway CPU usage"
- "memory consumption"
- "connection counts"
- "bandwidth utilization"
- "disk space usage"
- "concurrent sessions"
- "performance metrics"
- "resource usage"
- "top processes"

**Expected Behavior**: Execute performance commands (cpview, cpstat, top, etc.)

---

## Classification Decision Tree

```
Query Type Decision Flow:
├─ Contains "show/list/display/what/get" + config object?
│  └─ YES → policy_review
│
├─ Contains "why/debug/investigate/diagnose" + problem?
│  └─ YES → troubleshooting
│
├─ Contains "threat/attack/malware/suspicious/intrusion"?
│  └─ YES → security_investigation
│
├─ Contains "logs/traffic from" + entity?
│  └─ YES → log_analysis
│
├─ Contains "network/topology/routing/interface/gateway status"?
│  └─ YES → network_analysis
│
├─ Contains "cpu/memory/performance/capacity/utilization"?
│  └─ YES → performance (override)
│
├─ Contains "posture/assessment/compliance/risk/vulnerability"?
│  └─ YES → threat_assessment
│
└─ Otherwise → general_info
```

---

## Common Misclassification Scenarios (FIXED)

### ❌ WRONG: "show firewall rules" → troubleshooting
**Reason**: Contains "show" which is a display verb, not diagnostic  
**Correct**: policy_review → just display the rules

### ❌ WRONG: "unused rules" → threat_assessment
**Reason**: "unused rules" is a compliance/audit query asking for existing data  
**Correct**: policy_review → find and display unused rules

### ❌ WRONG: "why can't X connect" → security_investigation
**Reason**: This is about connectivity diagnosis, not threat hunting  
**Correct**: troubleshooting → diagnose connection failure

### ❌ WRONG: "show logs from IP X" → troubleshooting
**Reason**: Just displaying logs, not diagnosing a problem  
**Correct**: log_analysis → retrieve and show logs

---

## Response Style Guidelines

### policy_review Responses:
```
✓ Display data as tables/lists
✓ No interpretation or analysis
✓ Raw configuration values
✗ Don't suggest changes
✗ Don't analyze effectiveness
```

### troubleshooting Responses:
```
✓ Step-by-step diagnostic flow
✓ Root cause identification
✓ Correlation: logs → rules → network
✓ Fix recommendations
✗ Don't just show data without analysis
```

### security_investigation Responses:
```
✓ Threat event summary
✓ Severity assessment
✓ Attack vector analysis
✓ IOC extraction
✗ Don't include normal traffic
```

### log_analysis Responses:
```
✓ Traffic pattern summary
✓ Statistics and counts
✓ Top talkers/services
✗ Don't diagnose problems (use troubleshooting for that)
```

---

## Testing Checklist

Test each intent type with representative queries:

- [ ] policy_review: "show firewall rules" → displays rules table
- [ ] troubleshooting: "why can't 192.168.1.10 connect to 10.0.0.5" → diagnostic analysis
- [ ] security_investigation: "any threats last 24 hours" → threat event summary
- [ ] log_analysis: "show logs from 192.168.1.15" → log entries
- [ ] network_analysis: "show network topology" → network structure
- [ ] threat_assessment: "security posture assessment" → recommendations
- [ ] performance: "gateway CPU usage" → performance metrics
- [ ] general_info: "what can you do" → capabilities description

---

## Implementation Notes

The system uses a two-stage LLM architecture:
1. **Stage 1 (Intent Analyzer)**: Classifies query into intent type using comprehensive guidance
2. **Stage 2 (Technical Planner)**: Maps intent to appropriate MCP servers and generates execution plan

Each intent type has:
- Specific server allowlist/blocklist
- Custom instructions for LLM
- Appropriate response formatting
- Clear action directives (display vs analyze vs diagnose)
