# [HIGH] CISA orders feds to patch max severity Joomla plugin flaw by Friday

**Source:** BleepingComputer
**Published:** 2026-06-17
**Article:** https://www.bleepingcomputer.com/news/security/cisa-orders-feds-to-patch-max-severity-joomla-plugin-flaw-by-friday/

## Threat Profile

CISA orders feds to patch max severity Joomla plugin flaw by Friday 
By Sergiu Gatlan 
June 17, 2026
06:09 AM
0 
The U.S. Cybersecurity and Infrastructure Security Agency (CISA) has ordered federal agencies to patch a maximum-severity flaw in the Widget Factory Joomla Content Editor (JCE) plugin that is being actively exploited in the wild.
Tracked as CVE-2026-48907 , this vulnerability can be exploited by threat actors without privileges to achieve code execution via low-complexity attacks targ…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-48907`
- **IPv4 (defanged):** `107.149.130.5`
- **IPv4 (defanged):** `92.38.150.143`
- **IPv4 (defanged):** `45.153.129.241`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1071** — Application Layer Protocol
- **T1505.003** — Server Software Component: Web Shell
- **T1595.002** — Active Scanning: Vulnerability Scanning

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Joomla JCE profile.import unauthenticated RCE attempt (CVE-2026-48907)

`UC_27_2` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.url) as url values(Web.src) as src values(Web.status) as status from datamodel=Web.Web where Web.url="*com_jce*" AND (Web.url="*task=plugin*" OR Web.url="*profile*" OR Web.url="*imgmanager*" OR Web.url="*filemanager*") by Web.dest Web.http_method Web.user_agent | `drop_dm_object_name(Web)` | where status<400 OR status=200 | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where LocalPort in (80, 443, 8080, 8443)
| where RemoteIPType == "Public"
| where InitiatingProcessFileName in~ ("w3wp.exe","httpd.exe","apache2","nginx","php-fpm")
| where RemoteUrl has_any ("com_jce","index.php?option=com_jce","task=plugin","imgmanager","filemanager")
   or AdditionalFields has_any ("com_jce","profile.import")
| project Timestamp, DeviceName, RemoteIP, RemoteUrl, LocalPort, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Inbound HTTP from published CVE-2026-48907 JCE exploitation IPs

`UC_27_3` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_port) as dest_port values(All_Traffic.dest) as dest from datamodel=Network_Traffic.All_Traffic where All_Traffic.src in ("107.149.130.5","92.38.150.143","45.153.129.241") AND All_Traffic.dest_port in (80,443,8080,8443) by All_Traffic.src All_Traffic.action | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where ActionType in ("InboundConnectionAccepted","ConnectionSuccess","ConnectionFound")
| where RemoteIP in ("107.149.130.5","92.38.150.143","45.153.129.241")
| where LocalPort in (80, 443, 8080, 8443)
| project Timestamp, DeviceName, RemoteIP, RemotePort, LocalIP, LocalPort, InitiatingProcessFileName, InitiatingProcessCommandLine, ActionType
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-48907`

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `107.149.130.5`, `92.38.150.143`, `45.153.129.241`


## Why this matters

Severity classified as **HIGH** based on: CVE present, IOCs present, 4 use case(s) fired, 4 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
