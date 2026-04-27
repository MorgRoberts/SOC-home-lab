# SPL Detection Rules

A reference collection of all Splunk detection rules built in the SOC home lab. Each rule is mapped to the corresponding incident report and MITRE ATT&CK technique.

---

## 1. Windows Brute Force Detection

**Incident:** IR-2026-001  
**MITRE:** T1110 Brute Force  
**Log Source:** Windows Security Event Log  
**Index:** main  

```splunk
index=main sourcetype=WinEventLog:Security EventCode=4625
| stats count by Account_Name
| where count > 5
```

**With constraints (production version):**
```splunk
index=main sourcetype=WinEventLog:Security EventCode=4625 
Logon_Type IN (3,10)
| stats count by Account_Name Source_Network_Address
| where count > 5
```

**Alert settings:**
- Schedule: Every 1 hour
- Trigger: Number of results greater than 5
- Severity: High
- Throttle: 60 minutes

---

## 2. Nmap Reconnaissance Detection

**Incident:** IR-2026-002  
**MITRE:** T1046 Network Service Discovery  
**Log Source:** Windows Firewall Log  
**Index:** main  

```splunk
index=main sourcetype=winfirewall action=DROP
| stats count by src_ip
| where count > 5
```

**Alert settings:**
- Alert Name: Nmap Reconnaissance Detected
- Severity: High
- Threshold: Greater than 5 DROP events from single IP

---

## 3. VPN Impossible Travel Detection

**Incident:** IR-2026-004  
**MITRE:** T1078 Valid Accounts  
**Log Source:** VPN Logs  
**Index:** vpn_logs  

```splunk
index=vpn_logs
| stats dc(source_state) as unique_states by UserName
| where unique_states > 1
```

**Full investigation query:**
```splunk
index=vpn_logs UserName=James
| stats earliest(_time) as First_Seen latest(_time) as Last_Seen count by Source_ip source_state
| rename Source_ip as IP_Address, source_state as State
| convert ctime(First_Seen) ctime(Last_Seen)
```

---

## 4. SSH Brute Force Detection: Linux

**Incident:** IR-2026-005  
**MITRE:** T1110 Brute Force  
**Log Source:** Linux auth.log  
**Index:** linux_auth  

```splunk
index="linux_auth" "Failed Password"
| rex "from (?P<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by src_ip
| where count > 5
```

**Source port analysis:**
```splunk
index="linux_auth" "Failed Password"
| rex "port (?P<src_port>\d+)"
| stats count by src_port
```

**Successful login check:**
```splunk
index="linux_auth" "Accepted password"
```

**Alert settings:**
- Alert Name: SSH Brute Force Detection
- Schedule: Every 1 hour
- Trigger: Number of results greater than 0
- Severity: High
- Throttle: 60 minutes

---

## 5. General Investigation Queries

**Top source IPs across all logs:**
```splunk
index=* | top limit=10 src_ip
```

**Failed logins by hour trend analysis:**
```splunk
index=main sourcetype=WinEventLog:Security EventCode=4625
| timechart count span=1h
```

**User account activity summary:**
```splunk
index=main sourcetype=WinEventLog:Security
EventCode IN (4624, 4625, 4648, 4720)
| stats count by EventCode Account_Name
```

**Linux authentication summary:**
```splunk
index="linux_auth"
| stats count by host
| sort -count
```
