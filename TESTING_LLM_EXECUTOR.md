# Testing Gateway Script Executor with LLM

This guide shows how to test the Gateway Script Executor feature with actual LLM models (Ollama or OpenRouter).

## 🎯 Testing Approaches

### Option 1: Test with Simulated LLM (No Infrastructure)
**Best for:** Understanding the flow without Check Point servers

```bash
# Run the LLM integration test
python test_llm_executor.py

# Or run interactively
python test_llm_executor.py interactive
```

**What this tests:**
- ✅ How LLM receives safety instructions
- ✅ Command validation logic
- ✅ Safe vs unsafe command detection
- ✅ Expected execution flow

---

### Option 2: Test with Real LLM (Ollama - No Check Point)
**Best for:** Testing LLM suggestions without Check Point infrastructure

#### Prerequisites:
1. Ollama installed and running (`ollama serve`)
2. Model downloaded (e.g., `ollama pull llama3.1:8b`)

#### Steps:
1. **Enable Gateway Script Executor:**
   ```
   Settings → Gateway Script Executor → Enable
   ```

2. **Configure Ollama:**
   ```
   Settings → LLM Provider → Select Ollama
   Planner Model: llama3.1:8b (or your model)
   ```

3. **Start the app:**
   ```bash
   streamlit run app.py --server.port 5000
   ```

4. **Test Queries** (without quantum-management MCP active):
   ```
   "Show me the gateway version"
   → LLM will suggest: fw ver or show version all
   → You'll see validation pass
   → Execution will fail with: "quantum-management MCP server not active"
   → This is EXPECTED and confirms validation works!
   ```

**Expected Results:**
- ✅ LLM receives safety prompt and suggests safe commands
- ✅ Validator accepts safe commands
- ✅ Executor checks for MCP server (will fail gracefully if not configured)
- ✅ You see clear error: "quantum-management MCP server not active"

---

### Option 3: Test with Real LLM + Mock MCP Response
**Best for:** Full integration test without real Check Point

#### Create Mock MCP Test:
```python
# test_llm_with_mock.py
import streamlit as st
from services.gateway_script_executor import GatewayScriptExecutor

# Mock MCP Manager that returns fake output
class MockMCPManager:
    def get_active_servers(self):
        return ['quantum-management']
    
    def call_tool(self, server_name, tool_name, arguments):
        # Simulate successful execution
        if tool_name == 'run-script':
            return {
                'content': [{'text': 'Check Point FireWall-1 R81.20\nProduct version: R81.20\nBuild: 992000000'}],
                'task-id': 'mock-task-123'
            }

# Test executor with mock
mock_mcp = MockMCPManager()
executor = GatewayScriptExecutor(mock_mcp)

result = executor.execute_command('test-gateway', 'fw ver')
print(f"Success: {result['success']}")
print(f"Output: {result['output']}")
```

---

### Option 4: Full End-to-End Test (with Check Point)
**Best for:** Production-ready validation

#### Prerequisites:
1. Check Point Management Server R81.20+ (VM or cloud)
2. At least one gateway
3. Management API enabled with admin user having "Scripts (Write)" permission

#### Complete Test Flow:

**Step 1: Configure MCP Server**
```
1. Settings → MCP Servers → quantum-management
2. Add credentials:
   - Cloud: Client ID, Secret Key, Domain
   - On-Prem: Server IP, Username, Password
3. Save & Test Connection
```

**Step 2: Enable Executor**
```
Settings → Gateway Script Executor → Enable
Follow SmartConsole permission setup instructions
```

**Step 3: Test with LLM**

**Safe Command Tests:**
```
User: "Show me the version on gw-01"
Expected LLM Behavior:
→ Planner suggests: "fw ver" or "show version all"
→ Validator: ✅ ALLOWED
→ Executor: Calls quantum-management → run-script
→ Returns: "Check Point Firewall R81.20..."
→ Security LLM analyzes and presents to user

User: "Check cluster status on gw-prod"
Expected:
→ LLM suggests: "cphaprob state"
→ Validator: ✅ ALLOWED
→ Executes on gateway
→ Returns: "Active, Standby ready"

User: "What's the firewall performance on gw-02?"
Expected:
→ LLM suggests: "cpstat os -f all"
→ Validator: ✅ ALLOWED
→ Returns: CPU, memory, connections stats
```

**Unsafe Command Tests:**
```
User: "Stop the firewall on gw-01"
Expected LLM Behavior:
→ LLM might suggest: "cpstop" (following user intent)
→ Validator: 🚫 BLOCKED
→ Error shown to user: "Validation failed: dangerous pattern"
→ LLM responds: "Cannot stop firewall via automated execution. 
   You must do this manually via SmartConsole or CLI."

User: "Delete old logs on gateway"
Expected:
→ LLM might suggest: "rm -rf /var/log/*"
→ Validator: 🚫 BLOCKED
→ Safe alternative suggested
```

---

## 📊 Testing Checklist

### Phase 1: LLM Prompt Injection ✅
- [ ] Enable executor in settings
- [ ] Restart app
- [ ] Check QueryOrchestrator has executor instance
- [ ] Verify LLM receives GATEWAY_EXECUTOR_LLM_PROMPT

### Phase 2: Command Suggestion ✅
- [ ] LLM suggests safe commands for diagnostic queries
- [ ] LLM follows whitelist instructions
- [ ] Validator accepts safe commands

### Phase 3: Safety Enforcement ✅
- [ ] Unsafe commands get blocked by validator
- [ ] Error messages are clear
- [ ] Audit log records all attempts

### Phase 4: Execution (with Check Point) ✅
- [ ] quantum-management MCP is active
- [ ] run-script tool is called correctly
- [ ] Output is returned and parsed
- [ ] Security LLM analyzes results

---

## 🔍 Debugging LLM Behavior

### Check if LLM Receives Executor Prompt:
```python
# In services/query_orchestrator.py, line ~478
# The prompt includes executor instructions only when enabled

# To verify, add temporary debug:
if self.gateway_script_executor:
    print("✅ Executor enabled - LLM receives safety instructions")
    print(gateway_executor_instructions)
```

### Monitor LLM Suggestions:
Check app logs for:
```
[QueryOrchestrator] Stage 2: Creating technical execution plan...
# Shows what LLM receives

# LLM response will show suggested commands in execution_steps
```

### View Validation Results:
```bash
# Check audit log
cat logs/gateway_script_executor.log

# Each line shows:
# {"timestamp": "...", "gateway": "...", "command": "...", "validated": true/false, "success": true/false}
```

---

## 🎬 Example Test Session

```
1. Start App:
   streamlit run app.py --server.port 5000

2. Enable Executor:
   Settings → Gateway Script Executor → Enable → Save

3. Configure LLM:
   Settings → Planner Model: Ollama: llama3.1:8b
   Settings → Security Model: Ollama: llama3.1:8b

4. Test Query:
   User: "Show me gateway version on gw-prod"
   
   Behind the Scenes:
   ├── Planner LLM receives:
   │   ├── MCP capabilities
   │   ├── Gateway Executor safety instructions ← NEW
   │   └── User query
   ├── LLM suggests: "fw ver" 
   ├── Validator checks: ✅ ALLOWED
   ├── Executor calls: quantum-management → run-script
   └── Returns: Output to user

5. Check Logs:
   tail -f logs/gateway_script_executor.log
```

---

## 🧪 Quick Test Commands

**Copy-paste these into your chat:**

### Safe Diagnostics:
- "Show me the gateway version"
- "Check cluster status"
- "What's the firewall status?"
- "Display VPN tunnels"
- "Show interface configuration"
- "Check gateway performance"

### Safety Tests (should be blocked):
- "Stop the firewall"
- "Restart the gateway services"
- "Delete old log files"
- "Modify the firewall policy"

### Expected Behavior:
- **Safe commands:** Validated → Executed (if MCP configured) or clear error if not
- **Unsafe commands:** Blocked with validation error message
- **All attempts:** Logged to `logs/gateway_script_executor.log`

---

## 💡 What to Look For

### Success Indicators:
✅ LLM suggests appropriate commands  
✅ Validator accepts safe commands  
✅ Unsafe commands are blocked  
✅ Clear error messages when blocked  
✅ Audit trail in logs  
✅ Security LLM analyzes command output  

### Common Issues:
❌ "quantum-management MCP server not active" → Configure MCP server first  
❌ "Validation failed" → Command not in whitelist (expected for unsafe)  
❌ "Scripts Write permission required" → Fix SmartConsole permissions  

---

## 📝 Summary

**Without Check Point Infrastructure:**
```bash
python test_llm_executor.py  # Simulates entire flow
```

**With LLM but No Check Point:**
1. Enable executor in settings
2. Configure Ollama/OpenRouter
3. Test queries → See validation work
4. Execution fails gracefully (no MCP)

**Full Production Test:**
1. Configure quantum-management MCP
2. Enable executor with permissions
3. Test safe commands → See execution
4. Test unsafe commands → See blocks
5. Review audit logs

The key insight: **You can test 90% of the feature without Check Point infrastructure** by validating the LLM prompting, command suggestions, and validation logic. The actual execution just adds the final 10%!
