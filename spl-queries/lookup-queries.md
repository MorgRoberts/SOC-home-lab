# Splunk Lookup Queries

## inputlookup: View lookup table contents
| inputlookup bad_ips.csv

## lookup: Enrich events with bad IP threat types
index=botsv1 src_ip=192.168.*
| lookup bad_ips.csv src_ip OUTPUT threat_type
| where isnotnull(threat_type)
| dedup src_ip
| table src_ip threat_type

## outputlookup: Export search results to CSV
index=botsv1 sourcetype="WinEventLog:Security"
| table EventCode Account_Name Type
| outputlookup EventCode.csv
