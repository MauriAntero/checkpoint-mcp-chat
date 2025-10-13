# LLM Intent Detection Test Matrix
## Network Security Administrator Common Tasks

### ✅ **Currently Well-Handled Scenarios**

#### 1. **Threat Hunting & Security Investigation**
- **Queries**: "show suspicious activity", "find malware", "any IPS attacks", "threat prevention logs"
- **Current Behavior**: ✅ Triggers threat blade filters, uses management-logs with threat blade
- **LLM Understanding**: ✅ Recognizes as threat_assessment/security_investigation
- **Result Quality**: ✅ Focuses on security findings, not noise

#### 2. **Policy & Configuration Review**
- **Queries**: "show firewall rules", "review NAT configuration", "IPS profile settings", "access control policy"
- **Current Behavior**: ✅ Uses management/policy servers (quantum-management, threat-prevention)
- **LLM Understanding**: ✅ Recognizes as policy_review
- **Result Quality**: ✅ Formats rules as tables, shows configuration

#### 3. **Connectivity Troubleshooting** (FIXED TODAY)
- **Queries**: "why can't 192.168.1.15 reach 85.76.107.216", "vpn client connectivity issue", "connection failing"
- **Current Behavior**: ✅ Extracts IPs, filters logs, detects troubleshooting intent
- **LLM Understanding**: ✅ Recognizes as troubleshooting with special analysis context
- **Result Quality**: ✅ Analyzes traffic flow, NAT, drops/accepts (not threats)

#### 4. **VPN Analysis**
- **Queries**: "show vpn client connections", "vpn site-to-site status", "remote access vpn logs"
- **Current Behavior**: ✅ Distinguishes VPN client (regular logs) vs site-to-site (VPN blade)
- **LLM Understanding**: ✅ Recognizes as network_analysis or log_analysis
- **Result Quality**: ✅ Correct blade selection, proper log filtering

---

### ⚠️ **Potentially Problematic Scenarios**

#### 5. **Performance Analysis & Traffic Monitoring**
- **Queries**: 
  - "show high bandwidth traffic in last hour"
  - "top talkers from internal network"
  - "what applications are consuming most bandwidth"
  - "connection count per source IP"
  
- **Current Behavior**: 
  - ❓ May retrieve logs but lacks aggregation/sorting by bandwidth
  - ❓ No specific "top N" extraction logic
  - ❓ Logs don't always include bandwidth metrics
  
- **LLM Understanding**: Likely treats as log_analysis
- **Potential Issues**: 
  - CheckPoint logs may not include byte counts in all cases
  - No built-in aggregation/sorting for "top talkers"
  - LLM would need to manually count/aggregate from logs
  
- **Suggested Fix**: Add performance analysis intent detection + gateway CLI tools (cpstat, fw tab -t connections)

---

#### 6. **User/Source-Based Activity Tracking**
- **Queries**:
  - "show all traffic from user john.doe"
  - "what did admin account access today"
  - "activity from 10.1.1.50 in last 24 hours"
  
- **Current Behavior**:
  - ✅ IP extraction works (10.1.1.50)
  - ❓ Username extraction not implemented
  - ❓ No "user:" filter construction
  
- **LLM Understanding**: Likely treats as log_analysis
- **Potential Issues**:
  - IPs work via current filtering
  - Usernames would need extraction logic similar to IPs
  - CheckPoint logs may show orig_user, user, or identity_user fields
  
- **Suggested Fix**: Add username extraction + user: filter construction

---

#### 7. **Compliance & Audit Queries**
- **Queries**:
  - "show all blocked traffic today"
  - "what connections were dropped by rule 5"
  - "all accepted HTTPS traffic from external networks"
  - "compliance report: all drops from DMZ"
  
- **Current Behavior**:
  - ✅ Time frame detection works
  - ✅ Rule number could be extracted
  - ❌ No action filter (action:drop, action:accept)
  - ❌ No rule-specific filtering
  
- **LLM Understanding**: Treats as log_analysis or security_investigation
- **Potential Issues**:
  - "show blocked traffic" doesn't auto-add filter: action:drop
  - "dropped by rule 5" doesn't auto-add filter: rule:5
  - LLM gets ALL logs and must manually filter (inefficient)
  
- **Suggested Fix**: Extract action keywords (blocked→drop, accepted→accept, allowed→accept) and rule numbers

---

#### 8. **Application-Specific Troubleshooting**
- **Queries**:
  - "why is HTTPS inspection blocking google.com"
  - "SSL errors for cloudflare.com"
  - "certificate validation failures"
  - "TLS handshake errors from 192.168.1.100"
  
- **Current Behavior**:
  - ✅ HTTPS inspection blade filter works
  - ❓ Domain/URL extraction not implemented for log filtering
  - ✅ IP extraction works
  
- **LLM Understanding**: Treats as troubleshooting or security_investigation
- **Potential Issues**:
  - "google.com" not extracted and added to filter (dst:google.com or url:google.com)
  - Gets all HTTPS inspection logs instead of domain-specific
  
- **Suggested Fix**: Extract domains/URLs and add to log filters

---

#### 9. **Capacity Planning & Resource Analysis**
- **Queries**:
  - "how many concurrent connections on gateway"
  - "session count in last hour"
  - "CPU usage on firewall"
  - "memory consumption trends"
  
- **Current Behavior**:
  - ❌ No gateway performance metrics from logs
  - ❓ Would need gateway CLI tools (cpstat, fw ctl pstat, top)
  
- **LLM Understanding**: May treat as general_info (no clear data source)
- **Potential Issues**:
  - Logs don't contain gateway resource metrics
  - Needs quantum-gw-cli or quantum-gaia MCP servers with cpstat/monitoring commands
  
- **Suggested Fix**: Detect capacity/performance keywords → suggest/use gateway CLI tools

---

#### 10. **Time-Based Pattern Analysis**
- **Queries**:
  - "traffic patterns from 9am to 5pm yesterday"
  - "compare traffic volume this week vs last week"
  - "show connection spikes in last 7 days"
  
- **Current Behavior**:
  - ✅ Time frame extraction works for single periods
  - ❌ No support for time ranges (9am-5pm)
  - ❌ No comparative analysis (this week vs last week)
  
- **LLM Understanding**: Treats as log_analysis
- **Potential Issues**:
  - "9am to 5pm" not parsed (would get full day)
  - Comparative queries would need two separate log fetches
  - LLM must manually compare datasets
  
- **Suggested Fix**: Add time range parsing (HH:MM-HH:MM), support for comparative periods

---

### 🎯 **Priority Enhancements**

#### **High Priority** (Common Admin Tasks)
1. **Action Filter Extraction** (blocked/dropped/accepted/allowed)
   - Extract: "blocked" → `action:drop`, "accepted" → `action:accept`
   - Impact: Massively improves compliance/audit queries
   
2. **Rule Number Extraction**
   - Extract: "rule 5" → `rule:5`, "by rule 10" → `rule:10`
   - Impact: Enables precise rule-specific troubleshooting

3. **Domain/URL Extraction for Logs**
   - Extract: "google.com" → `dst:google.com OR url:google.com`
   - Impact: Application-specific troubleshooting

#### **Medium Priority** (Advanced Features)
4. **Username/User Filter Extraction**
   - Extract: "user john.doe" → `user:john.doe OR orig_user:john.doe`
   - Impact: User activity tracking

5. **Service/Port Extraction**
   - Extract: "port 443" → `service:443`, "SSH traffic" → `service:ssh`
   - Impact: Service-specific analysis

6. **Gateway Performance Intent Detection**
   - Keywords: "cpu", "memory", "connections", "sessions", "load", "performance"
   - Action: Suggest/use gateway CLI tools instead of logs
   - Impact: Capacity planning queries

#### **Low Priority** (Edge Cases)
7. **Time Range Parsing** (9am-5pm)
8. **Comparative Analysis** (this week vs last week)
9. **Bandwidth/Top-N Aggregation**

---

### 📝 **Recommendations**

1. **Immediate Action**: Add action/rule extraction to mcp_client_simple.py (similar to IP extraction)
2. **Quick Win**: Add domain extraction for application troubleshooting
3. **Analysis Enhancement**: Add performance/capacity intent detection → route to gateway tools
4. **Long-term**: Consider aggregation capabilities for "top N" queries

Would you like me to implement any of these enhancements?
