# SOC Home Lab | Splunk SIEM Detection Engineering

A hands-on Security Operations Center home lab built to simulate real-world attacks, develop Splunk detection rules, and practice Tier 1 SOC analyst workflows including alert triage, incident documentation, and escalation procedures.

---

## Lab Environment

| Component | Details |
|-----------|---------|
| SIEM | Splunk Enterprise 10.2.2 |
| Host Machine | MacBook Pro (Apple Silicon) |
| Hypervisor | VMware Fusion |
| Storage | Samsung T7 SSD |
| Windows VM | Windows 11 — target / Splunk server |
| Linux VM | Ubuntu Linux — target / log source |
| Attack VM | Kali Linux — attacker |

---

## Attacks Simulated & Detections Built

### 1. Brute Force Credential Attack (Windows)
- Simulated failed login attempts generating Event ID 4625
- Built SPL detection rule triggering High severity alert on 5+ failures in 60 seconds
- Created 3-panel dashboard: attack timeline, failed login count, affected accounts
- **MITRE ATT&CK:** T1110 — Brute Force
- **Incident Report:** IR-2026-001

### 2. Nmap Reconnaissance (Network)
- Executed SYN scan from Kali Linux against Windows target
- Detected 8 firewall DROP events in Splunk confirming reconnaissance activity
- Built real-time alert: Nmap Reconnaissance Detected (High severity)
- **MITRE ATT&CK:** T1046 — Network Service Discovery
- **Incident Report:** IR-2026-002

### 3. Phishing Email Forensic Analysis
- Analyzed PayPal impersonation sample using emlAnalyzer and manual header inspection
- Extracted IOCs: typosquatted domain, mismatched Reply-To, originating IP, credential harvesting URL
- Investigated attacker infrastructure via VirusTotal — identified bulletproof hosting provider
- **MITRE ATT&CK:** T1566 — Phishing
- **Incident Report:** IR-2026-003

### 4. VPN Log Analysis — Impossible Travel Detection
- Ingested VPN logs and investigated user account connecting from 3 states across 4 IPs within 60 minutes
- Identified simultaneous sessions consistent with credential compromise
- Documented full escalation report following Tier 1 SOC procedures
- **MITRE ATT&CK:** T1078 — Valid Accounts

### 5. SSH Brute Force Attack (Linux)
- Executed SSH brute force from Kali Linux against Ubuntu target on port 22
- Generated 55 failed authentication events captured in auth.log
- Built SPL detection using rex field extraction to identify attacking IP
- Confirmed 0 successful logins — attack contained
- Built and saved SSH Brute Force Detection alert in Splunk
- **MITRE ATT&CK:** T1110 — Brute Force

---

## SPL Detection Rules

```splunk
# Windows Brute Force Detection
index=main sourcetype=WinEventLog:Security EventCode=4625
| stats count by Account_Name
| where count > 5

# SSH Brute Force Detection  
index="linux_auth" "Failed Password"
| rex "from (?P<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by src_ip
| where count > 5

# VPN Impossible Travel Detection
index=vpn_logs
| stats dc(source_state) as unique_states by UserName
| where unique_states > 1
```

---

## Log Sources

| Source | Type | Index |
|--------|------|-------|
| Windows Security Event Log | Windows Events | main |
| Windows Firewall Log | pfirewall.log | main |
| Linux auth.log | SSH authentication | linux_auth |
| VPN Logs | JSON | vpn_logs |

---

## Tools Used

- **Splunk Enterprise** — SIEM, detection, dashboards, alerts
- **SPL** — Search Processing Language for all detections
- **Kali Linux** — Nmap, SSH brute force simulation
- **emlAnalyzer** — Phishing email header analysis
- **VirusTotal** — IOC investigation and reputation analysis
- **MITRE ATT&CK Framework** — Detection mapping
- **NIST 800-53** — Control evaluation

---

## Certifications
- CompTIA Security+ CE
- Splunk Core Certified User (In Progress)
- TryHackMe SOC Level 1 (In Progress)
