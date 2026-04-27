# IR-2026-001 | Windows Brute Force Attack: Credential Access

**Date:** April 20, 2026  
**Analyst:** Morgan Roberts  
**Severity:** High  
**Status:** Closed, Contained  
**MITRE ATT&CK:** T1110 Brute Force

---

## Summary

A brute force credential attack was simulated against a Windows 11 target machine. The attacking process generated 9 Event ID 4625 (failed logon) events within 55 seconds targeting the account "fakeuser." The attack was detected using a custom Splunk SPL detection rule and High severity alert. No successful authentication events were recorded. A 3-panel Splunk dashboard was built to visualize the attack timeline and affected accounts.

---

## Environment

| Detail | Value |
|--------|-------|
| Target | Windows 11 MorganVM (192.168.96.129) |
| Attacker | Simulated locally via script |
| Log Source | Windows Security Event Log |
| Splunk Index | main |
| Sourcetype | WinEventLog:Security |
| Key Event ID | 4625 Failed Logon |

---

## Detection

Alert triggered on failed logon threshold. Initial triage search:

```splunk
index=main sourcetype=WinEventLog:Security EventCode=4625
```

---

## Investigation

### Step 1: Confirm Failed Logon Events
```splunk
index=main sourcetype=WinEventLog:Security EventCode=4625
| stats count by Account_Name
```

**Result:** 9 failed logon events targeting account "fakeuser" confirmed

### Step 2: Analyze Logon Type
```splunk
index=main sourcetype=WinEventLog:Security EventCode=4625
| stats count by Logon_Type Account_Name
```

**Result:** Logon Type 2 (Interactive) local logon attempt

### Step 3: Review Failure Reason
Key fields from expanded event:
- **Failure_Reason:** Unknown user name or bad password
- **Account_Name:** fakeuser
- **Logon_Type:** 2
- **Source_Network_Address:** ::1 (localhost)

### Step 4: Verify No Successful Logins
```splunk
index=main sourcetype=WinEventLog:Security EventCode=4624
Account_Name=fakeuser
```

**Result:** 0 successful logon events, attack did not succeed

### Step 5: Timeline Analysis
```splunk
index=main sourcetype=WinEventLog:Security EventCode=4625
| timechart count span=10s
```

**Result:** 9 failed events within 55 seconds, consistent with automated brute force behavior

---

## Dashboard Built

3-panel Splunk dashboard created to visualize the attack:

| Panel | Content |
|-------|---------|
| Panel 1 | Attack timeline, failed logins over time |
| Panel 2 | Total failed login count |
| Panel 3 | Recent login detail table, affected accounts |

---

## Alert Configuration

| Setting | Value |
|---------|-------|
| Alert Name | Failed Login Attempts |
| Schedule | Every 1 hour |
| Trigger | Number of results greater than 5 |
| Severity | High |
| Throttle | 60 minutes |

---

## Findings

- 9 Event ID 4625 events generated within 55 seconds
- Target account "fakeuser" does not exist, all attempts failed at user validation
- Logon Type 2 indicates local interactive attack
- No successful authentication events detected
- Attack pattern consistent with MITRE ATT&CK T1110 Brute Force

---

## Recommendations

1. Enforce account lockout policy after 5 failed attempts
2. Implement privileged account monitoring with lower thresholds
3. Disable local administrator accounts where possible
4. Enable Windows Defender Credential Guard
5. Monitor Event ID 4648 for explicit credential use alongside 4625

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|-----------|-----|
| Credential Access | Brute Force | T1110 |
| Defense Evasion | Valid Accounts | T1078 |
