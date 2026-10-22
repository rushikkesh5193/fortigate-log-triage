# Security Log Triage Report

- Input files: sample.log
- Events parsed: 20,175 (malformed lines skipped: 1)
- Incidents raised: 11  (critical 3, high 4, medium 4, low 0)

## Queue (work top to bottom)

| Ticket | Severity | Category | First seen | Source | Summary |
|---|---|---|---|---|---|
| INC-20261020-001 | CRITICAL | bruteforce | 2026-10-20 03:30:04 | 203.0.113.77 | Firewall admin brute force from 203.0.113.77 - FOLLOWED BY SUCCESSFUL LOGIN |
| INC-20261020-002 | CRITICAL | ips | 2026-10-20 10:15:00 | 203.0.113.140 | IPS: Apache.Log4j.Error.Log.Remote.Code.Execution from 203.0.113.140 (NOT blocked, vendor severity critical) |
| INC-20261020-003 | CRITICAL | c2 | 2026-10-20 15:00:01 | 10.10.1.88 | Internal host 10.10.1.88 COMMUNICATED with known-bad 203.0.113.250 |
| INC-20261020-004 | HIGH | exposure | 2026-10-20 09:40:00 | 203.0.113.99 | Internet host 203.0.113.99 reached RDP (3389) on 10.10.20.15 - session ACCEPTED |
| INC-20261020-005 | HIGH | malware | 2026-10-20 11:05:00 | 10.10.1.77 | Malware signature W32/Agent.ABC!tr on/for host 10.10.1.77 (blocked) |
| INC-20261020-006 | HIGH | exfiltration | 2026-10-20 13:00:00 | 10.10.1.42 | Unusual upload volume: 10.10.1.42 sent 629 MiB to external 192.0.2.250 |
| INC-20261020-007 | HIGH | scan | 2026-10-20 16:20:00 | 10.10.1.99 | host sweep (many hosts, few ports) from INTERNAL host 10.10.1.99 |
| INC-20261020-008 | MEDIUM | scan | 2026-10-20 02:14:00 | 203.0.113.50 | port scan (many ports, few hosts) from external host 203.0.113.50 |
| INC-20261020-009 | MEDIUM | bruteforce | 2026-10-20 04:10:00 | 198.51.100.9 | Firewall admin password spraying from 198.51.100.9 |
| INC-20261020-010 | MEDIUM | ips | 2026-10-20 10:20:00 | 203.0.113.141 | IPS: Apache.Log4j.Error.Log.Remote.Code.Execution from 203.0.113.141 (blocked, vendor severity critical) |
| INC-20261020-011 | MEDIUM | c2 | 2026-10-20 15:30:00 | 10.10.1.89 | Internal host 10.10.1.89 attempted contact with known-bad 203.0.113.250 (denied) |

## Incident tickets

### INC-20261020-001 - CRITICAL - Firewall admin brute force from 203.0.113.77 - FOLLOWED BY SUCCESSFUL LOGIN

- **Category:** bruteforce   **MITRE ATT&CK (indicative):** T1110.001
- **Window:** 2026-10-20 03:30:04 to 03:41:10   **Events:** 41
- **Source:** 203.0.113.77   **Target:** firewall admin interface
- **Details:** {"accounts_tried": ["admin", "administrator", "root"], "failed_logins": 40, "successful_login_after": true}
- **Recommended L1 action:** Treat as a possible account compromise: disable or reset the admin account, restrict admin access to trusted IPs, review config changes since the login, and escalate to L2 immediately.

Evidence (first log lines):

```
date=2026-10-20 time=03:30:04 devname="FGT-HQ-01" devid="FGT60F0000000001" logid="0100032002" type="event" subtype="system" level="alert" vd="root" eventtime=1792467004000000000 logdesc="Admin login failed" user="admin" ui="https(203.0.113.77)" action="login" status="failed" reason="passwd_invalid" msg="Administrator admin login failed from https(203.0.113.77)"
date=2026-10-20 time=03:30:17 devname="FGT-HQ-01" devid="FGT60F0000000001" logid="0100032002" type="event" subtype="system" level="alert" vd="root" eventtime=1792467017000000000 logdesc="Admin login failed" user="administrator" ui="https(203.0.113.77)" action="login" status="failed" reason="passwd_invalid" msg="Administrator administrator login failed from https(203.0.113.77)"
date=2026-10-20 time=03:41:10 devname="FGT-HQ-01" devid="FGT60F0000000001" logid="0100032001" type="event" subtype="system" level="information" vd="root" eventtime=1792467670000000000 logdesc="Admin login successful" user="admin" ui="https(203.0.113.77)" action="login" status="success" msg="Administrator admin logged in successfully from https(203.0.113.77)"
```

### INC-20261020-002 - CRITICAL - IPS: Apache.Log4j.Error.Log.Remote.Code.Execution from 203.0.113.140 (NOT blocked, vendor severity critical)

- **Category:** ips   **MITRE ATT&CK (indicative):** T1190
- **Window:** 2026-10-20 10:15:00 to 10:15:10   **Events:** 3
- **Source:** 203.0.113.140   **Target:** 10.10.20.10
- **Details:** {"attack": "Apache.Log4j.Error.Log.Remote.Code.Execution", "blocked": false, "vendor_severity": "critical"}
- **Recommended L1 action:** The attack was detected but not blocked: check the target host's logs for exploitation, confirm the signature action in the IPS profile, and escalate to L2 for possible compromise.

Evidence (first log lines):

```
date=2026-10-20 time=10:15:00 devname="FGT-HQ-01" devid="FGT60F0000000001" logid="0419016384" type="utm" subtype="ips" level="alert" vd="root" eventtime=1792491300000000000 srcip=203.0.113.140 dstip=10.10.20.10 action="detected" severity="critical" attack="Apache.Log4j.Error.Log.Remote.Code.Execution" direction="incoming" msg="web_misc: Apache.Log4j.Error.Log.Remote.Code.Execution."
date=2026-10-20 time=10:15:05 devname="FGT-HQ-01" devid="FGT60F0000000001" logid="0419016384" type="utm" subtype="ips" level="alert" vd="root" eventtime=1792491305000000000 srcip=203.0.113.140 dstip=10.10.20.10 action="detected" severity="critical" attack="Apache.Log4j.Error.Log.Remote.Code.Execution" direction="incoming" msg="web_misc: Apache.Log4j.Error.Log.Remote.Code.Execution."
date=2026-10-20 time=10:15:10 devname="FGT-HQ-01" devid="FGT60F0000000001" logid="0419016384" type="utm" subtype="ips" level="alert" vd="root" eventtime=1792491310000000000 srcip=203.0.113.140 dstip=10.10.20.10 action="detected" severity="critical" attack="Apache.Log4j.Error.Log.Remote.Code.Execution" direction="incoming" msg="web_misc: Apache.Log4j.Error.Log.Remote.Code.Execution."
```

### INC-20261020-003 - CRITICAL - Internal host 10.10.1.88 COMMUNICATED with known-bad 203.0.113.250

- **Category:** c2   **MITRE ATT&CK (indicative):** T1071
- **Window:** 2026-10-20 15:00:01 to 15:55:01   **Events:** 12
- **Source:** 10.10.1.88   **Target:** 203.0.113.250
- **Details:** {"attempts_denied": 0, "distinct_ports": ["8443"], "sessions_allowed": 12}
- **Recommended L1 action:** Possible command-and-control: isolate the host, capture memory/disk per procedure, block the destination, and escalate to L2/IR now.

Evidence (first log lines):

```
date=2026-10-20 time=15:00:01 devname="FGT-HQ-01" devid="FGT60F0000000001" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" eventtime=1792508401000000000 srcip=10.10.1.88 srcport=19066 srcintf="port1" srcintfrole="lan" dstip=203.0.113.250 dstport=8443 dstintf="wan1" dstintfrole="wan" sessionid=119960 proto=6 action="close" policyid=1 policytype="policy" service="tcp/8443" duration=2 sentbyte=600 rcvdbyte=900
date=2026-10-20 time=15:05:02 devname="FGT-HQ-01" devid="FGT60F0000000001" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" eventtime=1792508702000000000 srcip=10.10.1.88 srcport=27979 srcintf="port1" srcintfrole="lan" dstip=203.0.113.250 dstport=8443 dstintf="wan1" dstintfrole="wan" sessionid=119961 proto=6 action="close" policyid=1 policytype="policy" service="tcp/8443" duration=2 sentbyte=600 rcvdbyte=900
date=2026-10-20 time=15:10:00 devname="FGT-HQ-01" devid="FGT60F0000000001" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" eventtime=1792509000000000000 srcip=10.10.1.88 srcport=12124 srcintf="port1" srcintfrole="lan" dstip=203.0.113.250 dstport=8443 dstintf="wan1" dstintfrole="wan" sessionid=119962 proto=6 action="close" policyid=1 policytype="policy" service="tcp/8443" duration=2 sentbyte=600 rcvdbyte=900
```

### INC-20261020-004 - HIGH - Internet host 203.0.113.99 reached RDP (3389) on 10.10.20.15 - session ACCEPTED

- **Category:** exposure   **MITRE ATT&CK (indicative):** T1133
- **Window:** 2026-10-20 09:40:00 to 09:44:00   **Events:** 3
- **Source:** 203.0.113.99   **Target:** 10.10.20.15:3389
- **Details:** {"service": "RDP", "sessions": 3}
- **Recommended L1 action:** Remote-access/file-sharing services should not be reachable from the internet: find the firewall policy that allowed it (policyid in the log), confirm with the asset owner, and escalate for an emergency policy change. Check the destination host for signs of login attempts or compromise.

Evidence (first log lines):

```
date=2026-10-20 time=09:40:00 devname="FGT-HQ-01" devid="FGT60F0000000001" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" eventtime=1792489200000000000 srcip=203.0.113.99 srcport=26184 srcintf="wan1" srcintfrole="wan" dstip=10.10.20.15 dstport=3389 dstintf="port2" dstintfrole="dmz" sessionid=119927 proto=6 action="accept" policyid=1 policytype="policy" service="RDP" duration=90 sentbyte=5000 rcvdbyte=9000
date=2026-10-20 time=09:42:00 devname="FGT-HQ-01" devid="FGT60F0000000001" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" eventtime=1792489320000000000 srcip=203.0.113.99 srcport=45595 srcintf="wan1" srcintfrole="wan" dstip=10.10.20.15 dstport=3389 dstintf="port2" dstintfrole="dmz" sessionid=119928 proto=6 action="accept" policyid=1 policytype="policy" service="RDP" duration=90 sentbyte=5000 rcvdbyte=9000
date=2026-10-20 time=09:44:00 devname="FGT-HQ-01" devid="FGT60F0000000001" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" eventtime=1792489440000000000 srcip=203.0.113.99 srcport=9214 srcintf="wan1" srcintfrole="wan" dstip=10.10.20.15 dstport=3389 dstintf="port2" dstintfrole="dmz" sessionid=119929 proto=6 action="accept" policyid=1 policytype="policy" service="RDP" duration=90 sentbyte=5000 rcvdbyte=9000
```

### INC-20261020-005 - HIGH - Malware signature W32/Agent.ABC!tr on/for host 10.10.1.77 (blocked)

- **Category:** malware   **MITRE ATT&CK (indicative):** T1204
- **Window:** 2026-10-20 11:05:00 to 11:05:20   **Events:** 2
- **Source:** 10.10.1.77   **Target:** 192.0.2.77
- **Details:** {"blocked": true, "virus": "W32/Agent.ABC!tr"}
- **Recommended L1 action:** Blocked at the gateway, but the host tried to fetch malware: identify the user, check the endpoint AV/EDR for the same family and for the file on disk, and review how the download was triggered (phishing link, browsing).

Evidence (first log lines):

```
date=2026-10-20 time=11:05:00 devname="FGT-HQ-01" devid="FGT60F0000000001" logid="0211008192" type="utm" subtype="virus" level="warning" vd="root" eventtime=1792494300000000000 srcip=192.0.2.77 dstip=10.10.1.77 action="blocked" virus="W32/Agent.ABC!tr" direction="incoming" dtype="Virus" filename="invoice_update.exe" msg="File is infected with W32/Agent.ABC!tr."
date=2026-10-20 time=11:05:20 devname="FGT-HQ-01" devid="FGT60F0000000001" logid="0211008192" type="utm" subtype="virus" level="warning" vd="root" eventtime=1792494320000000000 srcip=192.0.2.77 dstip=10.10.1.77 action="blocked" virus="W32/Agent.ABC!tr" direction="incoming" dtype="Virus" filename="invoice_update.exe" msg="File is infected with W32/Agent.ABC!tr."
```

### INC-20261020-006 - HIGH - Unusual upload volume: 10.10.1.42 sent 629 MiB to external 192.0.2.250

- **Category:** exfiltration   **MITRE ATT&CK (indicative):** T1048
- **Window:** 2026-10-20 13:00:00 to 13:58:00   **Events:** 30
- **Source:** 10.10.1.42   **Target:** 192.0.2.250
- **Details:** {"received_mib": 0.572, "sent_mib": 629.4, "upload_to_download_ratio": 1100.0}
- **Recommended L1 action:** Check whether the user/host has a legitimate reason (backup, cloud sync, file share) and whether the destination is approved. If not, contact the asset owner, consider blocking the destination, and escalate as possible data exfiltration.

Evidence (first log lines):

```
date=2026-10-20 time=13:00:00 devname="FGT-HQ-01" devid="FGT60F0000000001" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" eventtime=1792501200000000000 srcip=10.10.1.42 srcport=5774 srcintf="port1" srcintfrole="lan" dstip=192.0.2.250 dstport=443 dstintf="wan1" dstintfrole="wan" sessionid=119930 proto=6 action="close" policyid=1 policytype="policy" service="HTTPS" duration=110 sentbyte=22000000 rcvdbyte=20000
date=2026-10-20 time=13:02:00 devname="FGT-HQ-01" devid="FGT60F0000000001" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" eventtime=1792501320000000000 srcip=10.10.1.42 srcport=4766 srcintf="port1" srcintfrole="lan" dstip=192.0.2.250 dstport=443 dstintf="wan1" dstintfrole="wan" sessionid=119931 proto=6 action="close" policyid=1 policytype="policy" service="HTTPS" duration=110 sentbyte=22000000 rcvdbyte=20000
date=2026-10-20 time=13:04:00 devname="FGT-HQ-01" devid="FGT60F0000000001" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" eventtime=1792501440000000000 srcip=10.10.1.42 srcport=43546 srcintf="port1" srcintfrole="lan" dstip=192.0.2.250 dstport=443 dstintf="wan1" dstintfrole="wan" sessionid=119932 proto=6 action="close" policyid=1 policytype="policy" service="HTTPS" duration=110 sentbyte=22000000 rcvdbyte=20000
```

### INC-20261020-007 - HIGH - host sweep (many hosts, few ports) from INTERNAL host 10.10.1.99

- **Category:** scan   **MITRE ATT&CK (indicative):** T1046
- **Window:** 2026-10-20 16:20:00 to 16:20:59   **Events:** 60
- **Source:** 10.10.1.99   **Target:** 60 hosts
- **Details:** {"distinct_hosts": 60, "distinct_ports": 1, "distinct_targets": 60}
- **Recommended L1 action:** Internal host scanning the network is a strong sign of compromise or an unapproved scanner: identify the asset owner, check for an approved scan window, isolate the host if unexplained and escalate to L2.

Evidence (first log lines):

```
date=2026-10-20 time=16:20:00 devname="FGT-HQ-01" devid="FGT60F0000000001" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" eventtime=1792513200000000000 srcip=10.10.1.99 srcport=60691 srcintf="port1" srcintfrole="lan" dstip=10.10.30.1 dstport=445 dstintf="port2" dstintfrole="dmz" sessionid=119975 proto=6 action="deny" policyid=0 policytype="policy" service="SMB" duration=0 sentbyte=0 rcvdbyte=0
date=2026-10-20 time=16:20:01 devname="FGT-HQ-01" devid="FGT60F0000000001" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" eventtime=1792513201000000000 srcip=10.10.1.99 srcport=29192 srcintf="port1" srcintfrole="lan" dstip=10.10.30.2 dstport=445 dstintf="port2" dstintfrole="dmz" sessionid=119976 proto=6 action="deny" policyid=0 policytype="policy" service="SMB" duration=0 sentbyte=0 rcvdbyte=0
date=2026-10-20 time=16:20:02 devname="FGT-HQ-01" devid="FGT60F0000000001" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" eventtime=1792513202000000000 srcip=10.10.1.99 srcport=58958 srcintf="port1" srcintfrole="lan" dstip=10.10.30.3 dstport=445 dstintf="port2" dstintfrole="dmz" sessionid=119977 proto=6 action="deny" policyid=0 policytype="policy" service="SMB" duration=0 sentbyte=0 rcvdbyte=0
```

### INC-20261020-008 - MEDIUM - port scan (many ports, few hosts) from external host 203.0.113.50

- **Category:** scan   **MITRE ATT&CK (indicative):** T1046
- **Window:** 2026-10-20 02:14:00 to 02:15:59   **Events:** 120
- **Source:** 203.0.113.50   **Target:** 10.10.20.10
- **Details:** {"distinct_hosts": 1, "distinct_ports": 120, "distinct_targets": 120}
- **Recommended L1 action:** Internet background scanning is common: confirm the traffic was denied, check the source against threat intel, and escalate only if followed by accepted sessions from the same IP.

Evidence (first log lines):

```
date=2026-10-20 time=02:14:00 devname="FGT-HQ-01" devid="FGT60F0000000001" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" eventtime=1792462440000000000 srcip=203.0.113.50 srcport=32461 srcintf="wan1" srcintfrole="wan" dstip=10.10.20.10 dstport=402 dstintf="port2" dstintfrole="dmz" sessionid=119807 proto=6 action="deny" policyid=0 policytype="policy" service="tcp/402" duration=0 sentbyte=0 rcvdbyte=0
date=2026-10-20 time=02:14:01 devname="FGT-HQ-01" devid="FGT60F0000000001" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" eventtime=1792462441000000000 srcip=203.0.113.50 srcport=60506 srcintf="wan1" srcintfrole="wan" dstip=10.10.20.10 dstport=917 dstintf="port2" dstintfrole="dmz" sessionid=119808 proto=6 action="deny" policyid=0 policytype="policy" service="tcp/917" duration=0 sentbyte=0 rcvdbyte=0
date=2026-10-20 time=02:14:02 devname="FGT-HQ-01" devid="FGT60F0000000001" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" eventtime=1792462442000000000 srcip=203.0.113.50 srcport=55121 srcintf="wan1" srcintfrole="wan" dstip=10.10.20.10 dstport=243 dstintf="port2" dstintfrole="dmz" sessionid=119809 proto=6 action="deny" policyid=0 policytype="policy" service="tcp/243" duration=0 sentbyte=0 rcvdbyte=0
```

### INC-20261020-009 - MEDIUM - Firewall admin password spraying from 198.51.100.9

- **Category:** bruteforce   **MITRE ATT&CK (indicative):** T1110.003
- **Window:** 2026-10-20 04:10:00 to 04:13:40   **Events:** 12
- **Source:** 198.51.100.9   **Target:** firewall admin interface
- **Details:** {"accounts_tried": ["admin", "backup", "fortinet", "guest", "root", "support"], "failed_logins": 12, "successful_login_after": false}
- **Recommended L1 action:** Confirm the source is external/untrusted, block it, enforce trusted-host restrictions and MFA on admin access, and watch for a later successful login.

Evidence (first log lines):

```
date=2026-10-20 time=04:10:00 devname="FGT-HQ-01" devid="FGT60F0000000001" logid="0100032002" type="event" subtype="system" level="alert" vd="root" eventtime=1792469400000000000 logdesc="Admin login failed" user="admin" ui="https(198.51.100.9)" action="login" status="failed" reason="passwd_invalid" msg="Administrator admin login failed from https(198.51.100.9)"
date=2026-10-20 time=04:10:20 devname="FGT-HQ-01" devid="FGT60F0000000001" logid="0100032002" type="event" subtype="system" level="alert" vd="root" eventtime=1792469420000000000 logdesc="Admin login failed" user="root" ui="https(198.51.100.9)" action="login" status="failed" reason="passwd_invalid" msg="Administrator root login failed from https(198.51.100.9)"
```

### INC-20261020-010 - MEDIUM - IPS: Apache.Log4j.Error.Log.Remote.Code.Execution from 203.0.113.141 (blocked, vendor severity critical)

- **Category:** ips   **MITRE ATT&CK (indicative):** T1190
- **Window:** 2026-10-20 10:20:00 to 10:20:05   **Events:** 2
- **Source:** 203.0.113.141   **Target:** 10.10.20.10
- **Details:** {"attack": "Apache.Log4j.Error.Log.Remote.Code.Execution", "blocked": true, "vendor_severity": "critical"}
- **Recommended L1 action:** Blocked by the firewall: record it, check the source reputation, and watch for the same source reaching other services.

Evidence (first log lines):

```
date=2026-10-20 time=10:20:00 devname="FGT-HQ-01" devid="FGT60F0000000001" logid="0419016384" type="utm" subtype="ips" level="alert" vd="root" eventtime=1792491600000000000 srcip=203.0.113.141 dstip=10.10.20.10 action="dropped" severity="critical" attack="Apache.Log4j.Error.Log.Remote.Code.Execution" direction="incoming" msg="web_misc: Apache.Log4j.Error.Log.Remote.Code.Execution."
date=2026-10-20 time=10:20:05 devname="FGT-HQ-01" devid="FGT60F0000000001" logid="0419016384" type="utm" subtype="ips" level="alert" vd="root" eventtime=1792491605000000000 srcip=203.0.113.141 dstip=10.10.20.10 action="dropped" severity="critical" attack="Apache.Log4j.Error.Log.Remote.Code.Execution" direction="incoming" msg="web_misc: Apache.Log4j.Error.Log.Remote.Code.Execution."
```

### INC-20261020-011 - MEDIUM - Internal host 10.10.1.89 attempted contact with known-bad 203.0.113.250 (denied)

- **Category:** c2   **MITRE ATT&CK (indicative):** T1071
- **Window:** 2026-10-20 15:30:00 to 15:31:00   **Events:** 3
- **Source:** 10.10.1.89   **Target:** 203.0.113.250
- **Details:** {"attempts_denied": 3, "distinct_ports": ["8443"], "sessions_allowed": 0}
- **Recommended L1 action:** The connection was denied, but the host is trying to reach a known-bad address: check the endpoint for malware and look for other destinations the host contacted.

Evidence (first log lines):

```
date=2026-10-20 time=15:30:00 devname="FGT-HQ-01" devid="FGT60F0000000001" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" eventtime=1792510200000000000 srcip=10.10.1.89 srcport=63756 srcintf="port1" srcintfrole="lan" dstip=203.0.113.250 dstport=8443 dstintf="wan1" dstintfrole="wan" sessionid=119972 proto=6 action="deny" policyid=0 policytype="policy" service="tcp/8443" duration=0 sentbyte=0 rcvdbyte=0
date=2026-10-20 time=15:30:30 devname="FGT-HQ-01" devid="FGT60F0000000001" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" eventtime=1792510230000000000 srcip=10.10.1.89 srcport=24288 srcintf="port1" srcintfrole="lan" dstip=203.0.113.250 dstport=8443 dstintf="wan1" dstintfrole="wan" sessionid=119973 proto=6 action="deny" policyid=0 policytype="policy" service="tcp/8443" duration=0 sentbyte=0 rcvdbyte=0
date=2026-10-20 time=15:31:00 devname="FGT-HQ-01" devid="FGT60F0000000001" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" eventtime=1792510260000000000 srcip=10.10.1.89 srcport=43826 srcintf="port1" srcintfrole="lan" dstip=203.0.113.250 dstport=8443 dstintf="wan1" dstintfrole="wan" sessionid=119974 proto=6 action="deny" policyid=0 policytype="policy" service="tcp/8443" duration=0 sentbyte=0 rcvdbyte=0
```

---
Categories: {'bruteforce': 2, 'c2': 2, 'exfiltration': 1, 'exposure': 1, 'ips': 2, 'malware': 1, 'scan': 2}
