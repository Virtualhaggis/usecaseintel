# [CRIT] [GHSA / CRITICAL] GHSA-q6x4-v3qx-85qw: Budibase: SQL Injection via `multipleStatements: true`

**Source:** GitHub Security Advisories
**Published:** 2026-07-24
**Article:** https://github.com/advisories/GHSA-q6x4-v3qx-85qw

## Threat Profile

Budibase: SQL Injection via `multipleStatements: true`

## Summary
A critical SQL injection vulnerability was discovered in Budibase's MySQL integration that allows remote attackers to execute arbitrary SQL commands.

## Details
### Vulnerability Type
SQL Injection

### Description
The MySQL integration component in Budibase is configured with `multipleStatements: true`, enabling execution of multiple SQL statements in a single query. Attackers can inject malicious SQL commands through user inpu…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1005** — Data from Local System

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Stacked SQL-injection payload against Budibase datasource query API (multipleStatements)

`UC_73_0` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where Web.http_method IN ("POST","PUT") (Web.url="*/api/queries*" OR Web.url="*/api/datasources*" OR Web.uri_path="*/api/queries*" OR Web.uri_path="*/api/datasources*") (Web.url="*;*DROP TABLE*" OR Web.url="*;*DELETE *" OR Web.url="*INTO OUTFILE*" OR Web.url="*GRANT ALL*" OR Web.uri_query="*;*DROP TABLE*" OR Web.uri_query="*INTO OUTFILE*") by Web.src Web.dest Web.http_method Web.url Web.uri_path Web.status
| `drop_dm_object_name(Web)`
| sort - lastTime
```

### MySQL server (mysqld) writes exfil file via SELECT INTO OUTFILE on Budibase DB host

`UC_73_1` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Endpoint.Filesystem.process_name IN ("mysqld.exe","mysqld") AND (Endpoint.Filesystem.file_path="*/tmp/*" OR Endpoint.Filesystem.file_path="*/var/www/*" OR Endpoint.Filesystem.file_path="*\\Temp\\*" OR Endpoint.Filesystem.file_path="*\\inetpub\\*" OR Endpoint.Filesystem.file_name="*.csv" OR Endpoint.Filesystem.file_name="*.sql" OR Endpoint.Filesystem.file_name="*.txt") AND NOT (Endpoint.Filesystem.file_path="*/var/lib/mysql/*" OR Endpoint.Filesystem.file_path="*\\MySQL\\*\\Data\\*") by Endpoint.Filesystem.dest Endpoint.Filesystem.process_name Endpoint.Filesystem.file_path Endpoint.Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("mysqld.exe","mysqld")
| where ActionType == "FileCreated"
| where FolderPath has_any (@"\Temp\", "/tmp/", @"\inetpub\", "/var/www/", @"\www\") or FileName endswith ".csv" or FileName endswith ".sql" or FileName endswith ".txt"
| where not(FolderPath has_any ("/var/lib/mysql/", @"\MySQL\", @"\Data\"))
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessId, FolderPath, FileName, InitiatingProcessCommandLine
| sort by Timestamp desc
```


## Why this matters

Severity classified as **CRIT** based on: 2 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
