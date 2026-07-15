# [CRIT] [GHSA / CRITICAL] GHSA-hgjx-r89m-m7v4: FacturaScripts: Path traversal in UploadedFile::move() via getClientOriginalName() — arbitrary file write outside MyFiles/ leading to   RCE

**Source:** GitHub Security Advisories
**Published:** 2026-07-14
**Article:** https://github.com/advisories/GHSA-hgjx-r89m-m7v4

## Threat Profile

FacturaScripts: Path traversal in UploadedFile::move() via getClientOriginalName() — arbitrary file write outside MyFiles/ leading to   RCE

## Summary

`FacturaScripts\Core\UploadedFile::move($destiny, $destinyName)` concatenates `$destiny` and `$destinyName` without normalizing the resulting path. Every caller in the codebase passes `UploadedFile::getClientOriginalName()` — the unsanitized client-supplied filename — as `$destinyName`, so an authenticated user submitting a filename containing `…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1505.003** — Web Shell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### FacturaScripts traversal file-write: web-server drops PHP/.htaccess into Dinamic/Assets or node_modules

`UC_10_0` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*Dinamic/Assets*" OR Filesystem.file_path="*Dinamic\\Assets*" OR Filesystem.file_path="*node_modules*") AND (Filesystem.file_name=".htaccess" OR Filesystem.file_name="*.php" OR Filesystem.file_name="*.php3" OR Filesystem.file_name="*.php5" OR Filesystem.file_name="*.php7" OR Filesystem.file_name="*.php8" OR Filesystem.file_name="*.phtml" OR Filesystem.file_name="*.pht" OR Filesystem.file_name="*.phps" OR Filesystem.file_name="*.phar" OR Filesystem.file_name="*.txt" OR Filesystem.file_name="*.html") by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.user Filesystem.action | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("php-cgi.exe","php-fpm","php","httpd","apache2","w3wp.exe","nginx.exe","nginx")
| where FolderPath contains "Dinamic/Assets" or FolderPath contains @"Dinamic\Assets" or FolderPath contains "node_modules"
| extend FileExt = tolower(tostring(split(FileName, ".")[-1]))
| where FileName =~ ".htaccess" or FileExt in ("php","php3","php4","php5","php7","php8","pht","phtml","phps","phar","txt","html","htm","shtml")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessParentFileName, FolderPath, FileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### FacturaScripts .htaccess PHP-handler remap dropped into Dinamic/Assets (RCE enabler)

`UC_10_1` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_name=".htaccess" AND (Filesystem.file_path="*Dinamic/Assets*" OR Filesystem.file_path="*Dinamic\\Assets*" OR Filesystem.file_path="*node_modules*") by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.user Filesystem.action | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where FileName =~ ".htaccess"
| where InitiatingProcessFileName in~ ("php-cgi.exe","php-fpm","php","httpd","apache2","w3wp.exe","nginx.exe","nginx")
| where FolderPath contains "Dinamic/Assets" or FolderPath contains @"Dinamic\Assets" or FolderPath contains "node_modules"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, FileName, SHA256
| order by Timestamp desc
```

### FacturaScripts traversal payload retrieval: HTTP GET for non-static file under /Dinamic/Assets/ or /node_modules/

`UC_10_2` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where Web.http_method=GET (Web.url="*/Dinamic/Assets/*" OR Web.url="*/node_modules/*") (Web.url="*.php" OR Web.url="*.php5" OR Web.url="*.php7" OR Web.url="*.phtml" OR Web.url="*.pht" OR Web.url="*.phar" OR Web.url="*.txt" OR Web.url="*.htaccess") by Web.src Web.dest Web.url Web.status Web.http_user_agent | `drop_dm_object_name(Web)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```


## Why this matters

Severity classified as **CRIT** based on: 3 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
