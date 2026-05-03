# Splunk Lookup Queries

A reference collection of SPL lookup queries built in the SOC home lab using the BOTS v1 dataset.

---

## 1. View Lookup Table Contents (inputlookup)

**Purpose:** Display all entries in a lookup CSV file directly  
**Index:** N/A  
**Dataset:** bad_ips.csv

```splunk
| inputlookup bad_ips.csv
```

---

## 2. Enrich Events with Threat Intelligence (lookup)

**Purpose:** Match source IPs against known bad IP list and tag with threat type  
**Index:** botsv1  
**MITRE:** T1078 Valid Accounts / T1110 Brute Force

```splunk
index=botsv1 src_ip=192.168.*
| lookup bad_ips.csv src_ip OUTPUT threat_type
| where isnotnull(threat_type)
| dedup src_ip
| table src_ip threat_type
```

---

## 3. Export Search Results to CSV (outputlookup)

**Purpose:** Save search results to a reusable CSV lookup file  
**Index:** botsv1  
**Log Source:** Windows Security Event Log

```splunk
index=botsv1 sourcetype="WinEventLog:Security"
| table EventCode Account_Name Type
| outputlookup EventCode.csv
```
```
