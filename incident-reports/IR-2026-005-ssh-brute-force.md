# IR-2026-005 | SSH Brute Force Attack — Linux

**Date:** April 26, 2026  
**Analyst:** Morgan Roberts  
**Severity:** High  
**Status:** Closed — Contained  
**MITRE ATT&CK:** T1110 — Brute Force

---

## Summary

A brute force attack was detected against the Ubuntu Linux target via SSH (port 22). The attacking host, identified as the Kali Linux VM at 192.168.96.131, generated 55 failed authentication attempts against a non-existent user account. No successful logins were recorded. The attack was detected using a custom Splunk SPL detection rule built on auth.log ingestion.

---

## Environment

| Detail | Value |
|--------|-------|
| Target | Ubuntu Linux — 192.168.96.132 |
| Attacker | Kali Linux — 192.168.96.131 |
| Protocol | SSH |
| Port | 22 |
| Log Source | /var/log/auth.log |
| Splunk Index | linux_auth |
| Sourcetype | linux_secure |

---

## Attack Timeline

| Time (UTC) | Event |
|------------|-------|
| 16:21:06 | First SSH connection attempt from 192.168.96.131 |
| 16:21:06 | Invalid user fakeuser detected |
| 16:21:07 | Failed password attempts begin |
| 16:21:24 | Connection closed after max authentication failures |
| 16:21:24 | New connection established — attack continues |
| 16:24:39 | Final authentication failure recorded |

---

## Investigation

### Step 1 — Confirm Failed Attempts
```splunk
index="linux_auth" "Failed Password"
```
**Result:** 55 failed password events confirmed

### Step 2 — Identify Attacking IP
```splunk
index="linux_auth" "Failed Password"
| rex "from (?P<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by src_ip
```
**Result:** 192.168.96.131 — 55 attempts

### Step 3 — Analyze Source Ports
```splunk
index="linux_auth" "Failed Password"
| rex "port (?P<src_port>\d+)"
| stats count by src_port
```
**Result:** 19 unique ephemeral source ports used, consistent with automated brute force tooling

### Step 4 — Check for Successful Logins
```splunk
index="linux_auth" "Accepted password"
```
**Result:** 0 successful authentications — attack did not succeed

### Step 5 — Brute Force Detection Rule
```splunk
index="linux_auth" "Failed Password"
| rex "from (?P<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by src_ip
| where count > 5
```
**Result:** 192.168.96.131 flagged with 55 attempts — exceeds threshold

---

## Findings

- Single attacking IP generated 55 failed SSH login attempts over approximately 3 minutes
- 19 unique source ports used indicating automated tooling
- Target account `fakeuser` does not exist on the system, all attempts failed at the user validation stage
- No successful authentication events detected
- Attack pattern consistent with MITRE ATT&CK T1110 — Brute Force via SSH

---

## Recommendations

1. Implement Fail2ban to automatically block IPs after repeated failures
2. Disable password-based SSH authentication — enforce key-based auth only
3. Restrict SSH access to trusted IP ranges via firewall rules
4. Consider moving SSH to a non-standard port to reduce automated scanning noise
5. Monitor auth.log continuously with the SSH Brute Force Detection alert saved in Splunk

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|-----------|-----|
| Credential Access | Brute Force | T1110 |
| Initial Access | External Remote Services | T1133 |
