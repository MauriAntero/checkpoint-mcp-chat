#!/usr/bin/env python3
"""
Quick validation test for Gateway Script Executor command validator
"""

from services.gateway_script_executor import CommandValidator

def test_safe_commands():
    """Test that documented safe commands pass validation"""
    validator = CommandValidator()
    
    # Test cases from README documentation
    test_commands = [
        # System info
        ("show version", True),
        ("fw ver", True),
        ("uptime", True),
        
        # Network
        ("ifconfig", True),
        ("show interfaces", True),
        ("netstat -rn", True),
        
        # Firewall
        ("fw stat", True),
        ("fw ctl pstat", True),
        ("fwaccel stat", True),
        
        # Cluster HA
        ("cphaprob state", True),
        ("cphaprob -a if", True),
        
        # Performance
        ("top -n 1", True),
        ("ps aux", True),
        ("cpstat os -f all", True),
        
        # VPN
        ("vpn tu tlist", True),
        ("cpstat vpn", True),
        
        # Logs (critical - these were failing before)
        ("cat $FWDIR/log/fw.elg", True),
        ("echo $FWDIR", True),
        ("echo $FWDIR/conf", True),
        
        # Unsafe commands (should be blocked)
        ("cpstop", False),
        ("kill -9 1234", False),
        ("rm -rf /tmp/test", False),
        ("fw unloadlocal", False),
        ("vpn shell", False),
        ("cat /etc/passwd", False),  # Not whitelisted path
        ("echo test > /tmp/output", False),  # Redirect
    ]
    
    print("Testing Gateway Script Executor Command Validator\n")
    print("=" * 60)
    
    passed = 0
    failed = 0
    
    for command, should_pass in test_commands:
        is_safe, reason = validator.validate_command(command)
        
        if is_safe == should_pass:
            status = "✓ PASS"
            passed += 1
        else:
            status = "✗ FAIL"
            failed += 1
        
        expected = "SAFE" if should_pass else "BLOCK"
        result = "SAFE" if is_safe else "BLOCK"
        
        print(f"{status} | Expected: {expected:5} | Got: {result:5} | {command}")
        if is_safe != should_pass:
            print(f"       Reason: {reason}")
    
    print("=" * 60)
    print(f"\nResults: {passed} passed, {failed} failed out of {len(test_commands)} tests")
    
    if failed == 0:
        print("✅ All validation tests passed!")
        return True
    else:
        print(f"❌ {failed} test(s) failed")
        return False

if __name__ == "__main__":
    success = test_safe_commands()
    exit(0 if success else 1)
