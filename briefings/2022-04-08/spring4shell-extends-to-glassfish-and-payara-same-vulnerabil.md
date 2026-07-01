# [CRIT] Spring4Shell extends to Glassfish and Payara: same vulnerability, new exploit

**Source:** Snyk
**Published:** 2022-04-08
**Article:** https://snyk.io/blog/spring4shell-rce-vulnerability-glassfish-payara/

## Threat Profile

Snyk Blog In this article
Written by Brian Vermeer 
April 8, 2022
0 mins read Last week, we announced the discovery of Spring4Shell — a remote code execution (RCE) vulnerability in older versions of the spring-beans package. In our blog post Spring4Shell: The zero-day RCE in the Spring Framework explained , we showed how an old Tomcat exploit for CVE-2010-1622 became relevant again. Due to the nature of the problem, we expected that additional payloads could be created beyond this known Tomcat e…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2022-22965`
- **CVE:** `CVE-2010-1622`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1204.002** — User Execution: Malicious File
- **T1083** — File and Directory Discovery
- **T1003.008** — OS Credential Dumping: /etc/passwd and /etc/shadow

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Spring4Shell classLoader property injection via dirContext.docBase (Glassfish/Payara/Tomcat)

`UC_2186_2` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true allow_old_summaries=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where (Web.url="*class.module.classLoader*" OR Web.url="*dirContext.docBase*" OR Web.http_user_agent="*class.module.classLoader*") by Web.src Web.dest Web.http_method Web.url Web.status Web.http_user_agent
| `drop_dm_object_name(Web)`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

### Spring4Shell post-exploitation arbitrary file read (/etc/passwd via relocated docBase)

`UC_2186_3` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true allow_old_summaries=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where (Web.url="*/etc/passwd" OR Web.url="*/etc/shadow" OR Web.url="*/etc/passwd*" OR Web.url="*/WEB-INF/web.xml" OR Web.url="*/etc/hosts") by Web.src Web.dest Web.http_method Web.url Web.status
| `drop_dm_object_name(Web)`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

### Article-specific behavioural hunt — Spring4Shell extends to Glassfish and Payara: same vulnerability, new exploit

`UC_2186_1` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Spring4Shell extends to Glassfish and Payara: same vulnerability, new exploit ```
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/etc/passwd*")
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Spring4Shell extends to Glassfish and Payara: same vulnerability, new exploit
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/etc/passwd"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2022-22965`, `CVE-2010-1622`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 4 use case(s) fired, 4 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
