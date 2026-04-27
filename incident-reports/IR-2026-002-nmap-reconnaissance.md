# IR-2026-002 | Nmap Reconnaissance: Network Service Discovery

**Date:** April 2026  
**Analyst:** Morgan Roberts  
**Severity:** High  
**Status:** Closed, Contained  
**MITRE ATT&CK:** T1046 Network Service Discovery

---

## Summary

An Nmap SYN scan was executed from the Kali Linux attack VM against the Windows 11 target machine. The scan identified port 445 (SMB) as open on the target. Eight firewall DROP events were detected in Splunk confirming reconnaissance activity from the attacker IP 192.168.96.131. A real-time Splunk alert was built and documented in this report.

---

## Environment

| Detail | Value |
|--------|-------|
| Target | Windows 11 MorganVM (192.168.96.129) |
| Attacker | Kali Linux 192.168.96.131 |
| Attack Tool | Nmap |
| Scan Type | SYN Scan (-sS) |
| Log Source | Windows Firewall Log (pfirewall.log) |
| Splunk Index | main |
| Sourcetype | winfirewall |

---

## Detection

Firewall DROP events detected from single external IP scanning multiple ports in rapid succession.

---

## Investigation

### Step 1: Confirm Firewall DROP Events
```splunk
index=main sourcetype=winfirewall action=DROP
| stats count by src_ip
```

**Result:** 8 DROP events from 192.168.96.131 confirmed

### Step 2: Identify Scanned Ports
```splunk
index=main sourcetype=winfirewall action=DROP src_ip="192.168.96.131"
| stats count by dst_port
```

**Result:** Multiple ports scanned, port 445 (SMB) identified as open

### Step 3: Analyze Scan Pattern
```splunk
index=main sourcetype=winfirewall action=DROP src_ip="192.168.96.131"
| timechart count span=1s
```

**Result:** Rapid sequential port scanning pattern confirmed, consistent with automated Nmap behavior

### Step 4: Verify Attack Source
```splunk
index=main sourcetype=winfirewall src_ip="192.168.96.131"
| stats count by action
```

**Result:** All traffic from 192.168.96.131 resulted in DROP, no successful connections established

---

## Key Findings

- Nmap SYN scan detected from Kali Linux VM at 192.168.96.131
- 8 firewall DROP events confirmed in Splunk
- Port 445 (SMB) identified as open on target
- Rapid sequential scanning pattern consistent with automated tooling
- No successful connections established, firewall contained the scan

---

## Port 445 Significance

Port 445 runs SMB (Server Message Block) used for Windows file sharing and network communications. This port has a critical vulnerability history:

| Threat | Description |
|--------|-------------|
| EternalBlue | NSA exploit targeting SMB, used in WannaCry ransomware |
| WannaCry | 2017 ransomware outbreak, spread via port 445 |
| NotPetya | 2017 destructive malware, also exploited SMB |

Discovery of open port 445 by an attacker would likely lead to exploitation attempts.

---

## Alert Configuration

| Setting | Value |
|---------|-------|
| Alert Name | Nmap Reconnaissance Detected |
| Severity | High |
| Threshold | Greater than 5 DROP events from single IP |
| Action | Add to Triggered Alerts |

---

## Recommendations

1. Block port 445 from all external and untrusted network segments
2. Apply MS17-010 patch if not already applied, closes EternalBlue vulnerability
3. Implement IDS/IPS rules to detect port scanning behavior
4. Restrict SMB to only necessary internal communications
5. Alert on any single IP generating more than 5 DROP events within 60 seconds

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|-----------|-----|
| Discovery | Network Service Discovery | T1046 |
| Reconnaissance | Active Scanning | T1595 |
