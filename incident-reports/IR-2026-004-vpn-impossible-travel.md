# IR-2026-004 | VPN Impossible Travel: Credential Compromise

**Date:** April 2026  
**Analyst:** Morgan Roberts  
**Severity:** High  
**Status:** Escalated to Tier 2  
**MITRE ATT&CK:** T1078 Valid Accounts

---

## Summary

An impossible travel anomaly was detected on user account "James" during VPN log analysis. The account was observed connecting from three geographically separate states across four distinct IP addresses within a single day, including two simultaneous sessions within the same minute. This pattern is inconsistent with legitimate user activity and is highly indicative of credential compromise or unauthorized credential sharing.

---

## Environment

| Detail | Value |
|--------|-------|
| Log Source | VPN Logs |
| Splunk Index | vpn_logs |
| Sourcetype | json |
| Affected User | James |
| Investigation Period | January 1 to January 31, 2022 |
| Total Events | 156 |

---

## Detection

Alert fired on user account connecting from more than one state within the investigation window. Initial triage search:

```splunk
index=vpn_logs
| stats dc(source_state) as unique_states by UserName
| where unique_states > 1
```

---

## Investigation

### Step 1: Confirm the Anomaly
```splunk
index=vpn_logs UserName=James
| stats count by source_state
```

**Result:** 3 unique states: Maine, New York, Virginia

### Step 2: Build Full Timeline
```splunk
index=vpn_logs UserName=James
| stats earliest(_time) as First_Seen latest(_time) as Last_Seen count by Source_ip source_state
| rename Source_ip as IP_Address, source_state as State
| convert ctime(First_Seen) ctime(Last_Seen)
```

**Result:**

| IP Address | State | First Seen | Last Seen | Count |
|------------|-------|------------|-----------|-------|
| 107.90.227.121 | New York | 01/01/2022 08:18 | 01/31/2022 16:39 | 48 |
| 151.164.74.14 | Maine | 01/01/2022 07:34 | 01/16/2022 17:53 | 22 |
| 151.164.79.142 | Maine | 01/07/2022 07:52 | 01/31/2022 17:22 | 30 |
| 157.109.0.102 | Virginia | 01/01/2022 08:11 | 01/31/2022 17:35 | 56 |

### Step 3: Identify Simultaneous Sessions
Review of January 31, 2022 activity showed three separate IPs active within a 56-minute window:
- New York last seen 16:39
- Maine last seen 17:22
- Virginia last seen 17:35

Physical travel between these locations within 56 minutes is impossible, confirming the anomaly is not legitimate travel.

### Step 4: Analyze Session Actions
```splunk
index=vpn_logs UserName=James
| stats count by source_state action
```

Both `built` and `teardown` events observed across all three states, confirming active established sessions not just connection attempts.

### Step 5: Check Maine IP Abandonment
Maine IP `151.164.74.14` active January 1 through January 16 only, dropped off mid-month. Possible IP rotation or detection avoidance behavior.

---

## Findings

- User James connected from 3 states and 4 unique IPs throughout January 2022
- Simultaneous active sessions detected from multiple geographic locations on January 31
- One Maine IP abandoned mid-month, possible rotation behavior
- Pattern persisted for the entire month, not an isolated incident
- Consistent with credential compromise or unauthorized credential sharing

---

## Actions Taken: Tier 1

- Confirmed alert is not a false positive
- Reviewed 156 events across full January 2022 timeframe
- Documented full IP and state timeline
- Verified simultaneous session activity
- Escalated to Tier 2 for account suspension and credential reset

---

## Recommendations

1. Suspend James account pending user verification with manager
2. Force password reset and MFA re-enrollment
3. Review all data accessed during the anomaly period for potential exfiltration
4. Check other log sources for lateral movement from James account
5. Implement impossible travel alert rule permanently in Splunk

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|-----------|-----|
| Defense Evasion | Valid Accounts | T1078 |
| Initial Access | Valid Accounts | T1078 |
| Persistence | Valid Accounts | T1078 |
