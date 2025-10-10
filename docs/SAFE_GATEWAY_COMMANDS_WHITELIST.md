# Check Point Gateway - Safe Read-Only Commands Whitelist

**Purpose:** This document contains ONLY safe, read-only diagnostic commands verified from Check Point official documentation (R81/R82 CLI Reference Guides). These commands cannot modify configurations, stop services, or disrupt traffic.

**Last Updated:** October 10, 2025  
**Sources:** Check Point R81/R82 CLI Reference Guide, Official SK Articles

---

## 🔒 Safety Guarantees

All commands in this whitelist:
- ✅ **Read-only** - Cannot modify any configuration
- ✅ **Non-destructive** - Cannot stop/restart services or processes
- ✅ **Non-disruptive** - Won't impact production traffic
- ✅ **Audit-safe** - Only retrieve information for diagnostics

---

## Command Categories

### 1. System Information & Status

#### CLISH Commands (Gaia Shell)
```bash
show version                        # OS version and build
show version all                    # Complete version details
show version os build
show version os edition
show hostname                       # System hostname
show uptime                         # System uptime
show asset all                      # Hardware/appliance information
show sysenv all                     # System environment (fans, temp, voltage, PSU)
show sysenv fans
show sysenv temp
show sysenv volt
show sysenv ps                      # Power supply status
show commands                       # List all available CLISH commands
show configuration                  # Full system configuration (read-only view)
```

#### Expert Mode Commands
```bash
uname -a                           # System kernel information
hostname                           # System hostname
date                              # Current date/time
uptime                            # System uptime and load
df -h                             # Disk space usage
free -m                           # Memory usage (in MB)
```

---

### 2. Network Information

#### CLISH Commands
```bash
show interfaces                    # List all interfaces (basic info)
show interfaces all               # Detailed information for all interfaces
show interface <name>             # Specific interface details
show configuration interface      # Interface configuration only
show route                        # Routing table
show ipv6 route                   # IPv6 routing table
show arp dynamic                  # ARP table
show dns all                      # DNS configuration
show ntp active                   # NTP status
show bonding groups               # Bond interface groups
```

#### Expert Mode Commands
```bash
ifconfig                          # Network interface configuration
ip addr show                      # IP address information
ip route show                     # Routing table
netstat -rn                       # Routing table (numeric)
netstat -i                        # Interface statistics
netstat -tulnp                    # Network connections and listening ports
arp -a                            # ARP table
```

---

### 3. Check Point Firewall Status

```bash
fw stat                           # Firewall status and policy info
fw stat -l                        # Long format firewall statistics
fw stat -s                        # Short format
fw ver                            # Firewall version and installed hotfixes
fw getifs                         # Configured interfaces with IP/netmask
fw ctl iflist                     # Detailed interface list
fw ctl pstat                      # Performance statistics (policy server)
fw ctl chain                      # List inspection chain modules
fw ctl conn                       # Show firewall connection modules
```

---

### 4. Connection Tables & Statistics

```bash
fw tab -s                         # List all kernel tables (summary)
fw tab -t connections -s          # Connection table statistics
fw tab -t connections -f          # Detailed connection table
fw tab -t <table_name>           # View specific kernel table
fw ctl conntab                    # Show current connections
fw ctl conntab -v                # Verbose connection output
```

---

### 5. SecureXL Acceleration

```bash
fwaccel stat                      # SecureXL status (IPv4)
fwaccel6 stat                     # SecureXL status (IPv6)
fwaccel stat -v                   # Verbose SecureXL status
fwaccel stats                     # General acceleration statistics
fwaccel stats -s                  # NAC statistics
fwaccel stats -d                  # Dropped packets statistics
fwaccel stats -p                  # SecureXL violations (F2F packets)
fwaccel stats -n                  # Network statistics
fwaccel stats -m                  # Multicast traffic statistics
fwaccel ver                       # Acceleration version
fwaccel conns                     # SecureXL connections table
```

---

### 6. Cluster High Availability (ClusterXL)

```bash
cphaprob state                    # Cluster state (Active/Standby)
cphaprob stat                     # List state of all HA members
cphaprob -a if                    # Monitored cluster interfaces status
cphaprob -ia list                 # Show FAILED Critical Devices (pnotes)
cphaprob -l list                  # List ALL pnotes (including OK state)
cphaprob list                     # Cluster history - last 20 failover events
cphaprob syncstat                 # Sync transport layer statistics
cphaprob ldstat                   # Sync serialization statistics
cphaprob mmagic                   # Cluster magic number
cphaprob show_bond                # Bond interfaces configuration
fw hastat                         # Local HA state
```

#### CLISH Commands
```bash
show cluster state                # Cluster state
show cluster members              # Cluster members information
show cluster members interfaces all
show cluster members ips          # Unique IPs per member
show routed cluster-mode state    # Routed cluster mode state
```

---

### 7. VPN & IPsec

```bash
vpn tu tlist                      # List all active VPN tunnels (read-only)
cpstat vpn                        # VPN daemon statistics
cpstat -f all vpn                 # Detailed VPN statistics
cpstat ike -f all                 # IKE daemon statistics
fw tab -t vpn_enc_domain_valid -f -u  # View encryption domains
```

**Note:** `vpn shell` is EXCLUDED - it opens an interactive maintenance shell with state-altering commands. VPN debug commands like `vpn debug on` are safe (user-space only) but generate large log files and are excluded from auto-execution.

---

### 8. Logging & Monitoring

```bash
fw log                            # View firewall logs
fw log -f                         # Follow/tail log in real-time
fw log -t <start> <end>          # Filter by timestamp
fw log -s <source_IP>            # Filter by source IP
fw log -d <dest_IP>              # Filter by destination IP
fw log -c <action>               # Filter by action (drop/accept)
fw log -n                         # Don't resolve hostnames
fw lslogs                         # List available log files and sizes
```

**Log File Locations (Read-Only):**
```bash
cat /var/log/messages             # System messages (last 100 lines recommended)
tail -100 /var/log/messages
cat $FWDIR/log/fw.elg            # Firewall logs
cat $FWDIR/log/vpnd.elg          # VPN daemon logs
cat $FWDIR/log/ike.elg           # IKE logs
cat $FWDIR/log/cpd.elg           # CPD (SIC) logs
```

---

### 9. Performance & Resource Monitoring

```bash
top -n 1                          # Single snapshot (non-interactive)
ps aux                            # Process list
vmstat 1 1                        # Virtual memory statistics (single snapshot)
free -m                           # Memory usage
cpstat os -f all                  # Complete system view (interfaces, routes, version, memory, CPU, disk)
cpstat os -f cpu                  # CPU utilization statistics
cpstat os -f multi_cpu           # CPU load distribution across cores
cpstat os -f memory              # Memory usage information
cpstat os -f ifconfig            # Interface table
cpstat os -f routing             # Routing table
cpstat os -f sensors             # Hardware sensors (temp/fan/voltage)
cpstat fw                         # Firewall blade statistics
cpstat fw -f policy              # Verbose policy information
cpstat fw -f sync                # Synchronization statistics
cpstat ha                         # HA state and statistics
cpstat blades                     # Top rule hits and connection counts
```

**Note:** Interactive versions (`top`, `cpview`, `vmstat` without `-n 1`) are EXCLUDED - they open interactive TUIs that can send signals or execute commands.

---

### 10. Check Point Services & Processes

```bash
cpwd_admin list                   # List all Check Point processes
cpwd_admin monitor_list          # List actively monitored processes
api status                        # API service status
cplic print                       # License information
```

---

### 11. Management & SIC

```bash
cpca_client lscert               # List certificates
```

---

### 12. Diagnostic Utilities

```bash
cpinfo                            # Collect diagnostic data bundle (read-only snapshot)
cpstat                            # List all available application flags
```

**Note:** `cpview` (interactive TUI) is EXCLUDED - it opens a full-screen monitoring interface with navigation controls.

---

## 🚫 Commands NOT in Whitelist (Unsafe - Modifying/Disruptive)

The following commands are **BLOCKED** as they can modify configuration or disrupt services:

### Service Control
- `cpstop` - Stops Check Point services
- `cpstart` - Starts Check Point services
- `cphastop` - Emergency cluster stop
- `api restart` - Restarts API service

### Firewall Control
- `fw unload` - Unloads firewall policy
- `fw load` - Loads firewall policy
- `fw kill` - Kills processes

### VPN Control
- `vpn shell` - Opens interactive maintenance shell with state-altering commands
- `vpn tu tlist del` - Deletes VPN tunnels
- `vpn tunnelutil` (option 0) - Deletes all IPsec/IKE SAs
- `vpn debug on` - Generates large log files (safe but excluded)

### Interactive Tools (Unsafe - Can Execute Commands)
- `top` (without -n 1) - Interactive TUI with signal sending capability
- `cpview` - Interactive full-screen monitoring TUI
- `vmstat` (without count limit) - Continuous interactive output
- `fw monitor` - High CPU impact and interactive output (excluded)

### Configuration Changes
- Any `set` command
- Any `add` command
- Any `delete` command
- `commit` operations
- `cpconfig` - Configuration wizard (interactive shell)

### File Operations
- `rm`, `rmdir`, `unlink` - File deletion
- `cp`, `mv`, `dd` - File operations
- `chmod`, `chown`, `chgrp` - Permission changes
- `mkfs`, `fdisk`, `parted` - Disk operations

### Process Control
- `kill`, `pkill`, `killall` - Process termination

### Debug Commands (High Impact)
- `fw ctl debug` - Kernel debug (can cause high load)
- `fwaccel stats -r` - Reset acceleration statistics

### Cluster Operations
- `clusterXL_admin down` - Disable cluster node

---

## Environment Variables (Safe to Read)

```bash
echo $FWDIR                       # FW-1 installation directory
echo $CPDIR                       # Check Point directory
echo $FWDIR/conf                  # Configuration directory path
echo $FWDIR/log                   # Logs directory path
```

---

## Additional Safety Notes

1. **All CLISH `show` commands are safe** - They are read-only by design
2. **Expert mode required** - Most `fw`, `cp`, and diagnostic commands require expert mode
3. **No command chaining** - Whitelist does not allow pipes (|), redirects (>), or command substitution ($(), `)
4. **Special characters blocked** - No use of `;`, `&`, `&&`, `||` for command chaining
5. **Single-snapshot only** - Commands like `top` must use `-n 1` for non-interactive single snapshots
6. **No interactive shells/menus/TUIs** - Commands that open interactive interfaces (e.g., `vpn shell`, `cpconfig`, `top`, `cpview`, `fw monitor`) are EXCLUDED - they can expose control sequences or state-altering operations
7. **Debug commands excluded** - Even safe user-space debug commands (e.g., `vpn debug on`) are excluded from auto-execution due to log file generation impact

---

## References

- **Check Point R81 CLI Reference Guide**: https://sc1.checkpoint.com/documents/R81/WebAdminGuides/EN/CP_R81_CLI_ReferenceGuide/
- **Check Point R82 CLI Reference Guide**: https://sc1.checkpoint.com/documents/R82/WebAdminGuides/EN/CP_R82_CLI_ReferenceGuide/
- **SK Articles**: sk92739 (cpinfo), sk25532 (fw log), sk30583 (fw monitor), sk33853 (vpn tu)
- **CLI Reference Card by Jens Roesen**: https://www.roesen.org/files/cp_cli_ref_card.pdf

---

## Audit Trail

**Compiled by:** AI Agent  
**Review Status:** Pending User Audit  
**Approval Date:** TBD  
**Approved by:** TBD

---

**End of Whitelist**
