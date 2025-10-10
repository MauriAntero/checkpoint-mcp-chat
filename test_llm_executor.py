#!/usr/bin/env python3
"""
Test Gateway Script Executor with LLM Integration
This simulates the complete flow: User Query → LLM Planning → Command Validation → Execution
"""

import json
from services.gateway_script_executor import CommandValidator, GATEWAY_EXECUTOR_LLM_PROMPT

def simulate_llm_planning(user_query: str, with_executor_prompt: bool = True):
    """
    Simulate what the LLM sees and how it would respond
    """
    print(f"\n{'='*80}")
    print(f"USER QUERY: '{user_query}'")
    print(f"{'='*80}\n")
    
    # Show what the LLM receives
    if with_executor_prompt:
        print("📋 LLM RECEIVES THIS PROMPT:")
        print("-" * 80)
        print(GATEWAY_EXECUTOR_LLM_PROMPT)
        print("-" * 80)
    
    # Simulate LLM command suggestions based on query
    llm_suggestions = {
        "show gateway version": "fw ver",
        "check cluster status": "cphaprob state",
        "what's the firewall status": "fw stat",
        "show interfaces": "ifconfig",
        "display vpn tunnels": "vpn tu tlist",
        "check gateway performance": "cpstat os -f all",
        "show system info": "show version all",
        "stop the firewall": "cpstop",  # Unsafe - will be blocked
        "restart firewall": "cpstart",  # Unsafe - will be blocked
        "delete logs": "rm -rf /var/log/*",  # Unsafe - will be blocked
    }
    
    # Find matching suggestion
    suggested_command = None
    for query_pattern, command in llm_suggestions.items():
        if query_pattern in user_query.lower():
            suggested_command = command
            break
    
    if not suggested_command:
        suggested_command = "show version all"  # Default safe command
    
    print(f"\n🤖 LLM SUGGESTS COMMAND: '{suggested_command}'")
    
    # Validate the command
    validator = CommandValidator()
    is_safe, reason = validator.validate_command(suggested_command)
    
    print(f"\n🔒 VALIDATION LAYER:")
    print("-" * 80)
    if is_safe:
        print(f"✅ COMMAND ALLOWED")
        print(f"   Reason: {reason}")
        print(f"\n📡 Would execute via quantum-management MCP run-script:")
        print(f"   - Gateway: <gateway-name>")
        print(f"   - Command: {suggested_command}")
        print(f"   - Tool: run-script")
        print(f"\n📊 Expected Flow:")
        print(f"   1. Call MCP: quantum-management → run-script")
        print(f"   2. Receive output from gateway")
        print(f"   3. Security LLM analyzes output")
        print(f"   4. Present results to user")
    else:
        print(f"🚫 COMMAND BLOCKED")
        print(f"   Reason: {reason}")
        print(f"\n💡 What happens next:")
        print(f"   1. User sees: 'Cannot execute this command - validation failed'")
        print(f"   2. LLM suggests alternative approach")
        print(f"   3. No execution occurs - system stays safe")
    
    print("-" * 80)
    
    return {
        'query': user_query,
        'suggested_command': suggested_command,
        'is_safe': is_safe,
        'validation_reason': reason
    }

def test_llm_scenarios():
    """Test various user scenarios with LLM"""
    
    print("\n" + "="*80)
    print(" GATEWAY SCRIPT EXECUTOR - LLM INTEGRATION TEST")
    print("="*80)
    
    scenarios = [
        # Safe queries
        "Show me the gateway version",
        "Check if cluster is active",
        "What's the firewall status?",
        "Display VPN tunnels",
        "Show system performance",
        
        # Unsafe queries (should be blocked)
        "Stop the firewall",
        "Restart the gateway",
        "Delete old log files"
    ]
    
    results = []
    for scenario in scenarios:
        result = simulate_llm_planning(scenario, with_executor_prompt=False)
        results.append(result)
    
    # Summary
    print("\n" + "="*80)
    print(" TEST SUMMARY")
    print("="*80)
    
    safe_count = sum(1 for r in results if r['is_safe'])
    blocked_count = len(results) - safe_count
    
    print(f"\n✅ Safe commands allowed: {safe_count}/{len(results)}")
    print(f"🚫 Unsafe commands blocked: {blocked_count}/{len(results)}")
    
    print("\n📋 Detailed Results:")
    for r in results:
        status = "✅ ALLOWED" if r['is_safe'] else "🚫 BLOCKED"
        print(f"  {status} | '{r['query']}' → {r['suggested_command']}")
    
    # Show the actual prompt one time
    print("\n" + "="*80)
    print(" LLM SAFETY INSTRUCTIONS (Injected into Planner)")
    print("="*80)
    print(GATEWAY_EXECUTOR_LLM_PROMPT)

def test_specific_command():
    """Test a specific command interactively"""
    print("\n" + "="*80)
    print(" INTERACTIVE COMMAND TEST")
    print("="*80)
    
    while True:
        query = input("\nEnter user query (or 'quit' to exit): ")
        if query.lower() in ['quit', 'exit', 'q']:
            break
        
        simulate_llm_planning(query, with_executor_prompt=False)

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "interactive":
        test_specific_command()
    else:
        test_llm_scenarios()
        
        print("\n" + "="*80)
        print("\n💡 To test interactively, run: python test_llm_executor.py interactive")
        print("\n" + "="*80)
