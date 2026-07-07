# [CRIT] Magento security requires additional patch to fix sanitization vulnerability

**Source:** Snyk
**Published:** 2022-02-24
**Article:** https://snyk.io/blog/magento-vulnerability-cve-2022-24087-sanitization/

## Threat Profile

Snyk Blog In this article
Written by DeveloperSteve Coochin 
February 24, 2022
0 mins read As technology folks, we are often under a lot of pressure to fix some deployed code, update an infrastructure component, or patch some code. Often it's with little notice and needs to be done 5 minutes ago. The gamble with any “zero turnaround” is the rush to fix now vs. taking the time to test and check.
Recently, a critical patch was released for Magento Ecommerce , Magento Open Source, and Adobe Commerc…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2022-24086`
- **CVE:** `CVE-2022-24087`
- **IPv4 (defanged):** `45.134.20.11`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1071** — Application Layer Protocol
- **T1059** — Command and Scripting Interpreter
- **T1505.003** — Web Shell
- **T1059.004** — Unix Shell
- **T1071.001** — Web Protocols

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Magento CVE-2022-24086/24087 TrojanOrders checkout exploitation from known attacker IP

`UC_2572_2` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where (Web.src="45.134.20.11" OR (Web.http_method="POST" AND (Web.url="*getTemplateFilter*" OR Web.url="*addAfterFilterCallback*" OR Web.url="*trans *" OR Web.url="*{{*"))) AND (Web.url="*/checkout*" OR Web.url="*/rest/*/V1/guest-carts*" OR Web.url="*/customer/address*" OR Web.url="*/V1/carts*") by Web.src Web.dest Web.http_method Web.url Web.http_user_agent Web.status | `drop_dm_object_name(Web)` | convert ctime(firstTime) ctime(lastTime)
```

### Magento webshell drop (health_check.php / pub-media PHP) written by web-server process

`UC_2572_3` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_name="*.php" AND (Filesystem.file_path="*/pub/media/*" OR Filesystem.file_path="*/var/*" OR Filesystem.file_name="health_check.php")) by Filesystem.dest Filesystem.file_name Filesystem.file_path Filesystem.process_name | `drop_dm_object_name(Filesystem)` | search process_name IN ("php-fpm","php","httpd","apache2","nginx") | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName endswith ".php"
| where InitiatingProcessFileName has_any ("php-fpm", "php", "httpd", "apache2", "nginx")
| where FolderPath has_any ("/pub/media/", "/var/", "\\pub\\media\\") or FileName =~ "health_check.php"
| project Timestamp, DeviceName, FileName, FolderPath, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### Magento php-fpm/web-server spawning shell or download utility (CVE-2022-24086 RCE)

`UC_2572_4` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("php-fpm","php","httpd","apache2","nginx") AND Processes.process_name IN ("sh","bash","dash","curl","wget","python","python3","perl")) by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName has_any ("php-fpm", "php", "httpd", "apache2", "nginx")
| where FileName in~ ("sh", "bash", "dash", "curl", "wget", "python", "python3", "perl")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### Outbound or inbound connection to TrojanOrders C2/source IP 45.134.20.11

`UC_2572_5` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.src="45.134.20.11" OR All_Traffic.dest="45.134.20.11") by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP == "45.134.20.11"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl, Protocol
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2022-24086`, `CVE-2022-24087`

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `45.134.20.11`


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 6 use case(s) fired, 6 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
