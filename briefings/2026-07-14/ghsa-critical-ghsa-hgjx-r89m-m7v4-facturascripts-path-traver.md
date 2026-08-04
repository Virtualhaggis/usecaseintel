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

### FacturaScripts upload endpoint: path-traversal sequence in multipart filename

`UC_223_0` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where Web.http_method=POST (Web.url="*uploadfiles*" OR Web.url="*attachedfiles*" OR Web.uri_path="*uploadfiles*" OR Web.uri_path="*attachedfiles*") by Web.src Web.dest Web.url Web.uri_path Web.http_method Web.status Web.http_user_agent Web.user
| `drop_dm_object_name(Web)`
| where match(url,"(?i)(\.\./|\.\.%2f|\.\.%5c|\.\.\\)") OR match(uri_path,"(?i)(\.\./|\.\.%2f)")
| sort - lastTime
```

### FacturaScripts: PHP/.htaccess web-shell written into web-served Dinamic/Assets or node_modules

`UC_223_1` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.action=created (Filesystem.file_path="*Dinamic*Assets*" OR Filesystem.file_path="*node_modules*") (Filesystem.file_name="*.php" OR Filesystem.file_name="*.php3" OR Filesystem.file_name="*.php5" OR Filesystem.file_name="*.php7" OR Filesystem.file_name="*.php8" OR Filesystem.file_name="*.pht" OR Filesystem.file_name="*.phtml" OR Filesystem.file_name="*.phps" OR Filesystem.file_name="*.phar" OR Filesystem.file_name="*.htaccess") by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.process_guid Filesystem.user
| `drop_dm_object_name(Filesystem)`
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where (FolderPath has "Dinamic" and FolderPath has "Assets") or FolderPath has "node_modules"
| extend Ext = tolower(tostring(split(FileName, ".")[-1]))
| where Ext in ("php","php3","php4","php5","php7","php8","pht","phtml","phps","phar","htaccess")
| where InitiatingProcessFileName in~ ("httpd.exe","apache.exe","apache2","httpd","php.exe","php-cgi.exe","php-fpm","w3wp.exe","nginx.exe","caddy.exe")
| project Timestamp, DeviceName, FolderPath, FileName, Ext, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, SHA256
| order by Timestamp desc
```

### FacturaScripts RCE chain: .htaccess handler-remap override plus payload drop in same asset dir

`UC_223_2` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Endpoint.Filesystem where Filesystem.action=created (Filesystem.file_path="*Dinamic*Assets*" OR Filesystem.file_path="*node_modules*") by _time span=1s Filesystem.dest Filesystem.file_name Filesystem.file_path
| `drop_dm_object_name(Filesystem)`
| eval is_htaccess=if(match(file_name,"(?i)\.htaccess$"),1,0)
| eval is_payload=if(match(file_name,"(?i)\.(php[345678]?|pht|phtml|phps|phar|png|jpe?g|gif|txt)$"),1,0)
| bin _time span=2m
| stats sum(is_htaccess) as htaccess_writes sum(is_payload) as payload_writes values(file_name) as files min(_time) as firstTime max(_time) as lastTime by dest _time
| where htaccess_writes>=1 AND payload_writes>=1
| sort - lastTime
```

**Defender KQL:**
```kql
let win = 2m;
let webdirs = DeviceFileEvents
    | where Timestamp > ago(7d)
    | where (FolderPath has "Dinamic" and FolderPath has "Assets") or FolderPath has "node_modules"
    | where InitiatingProcessFileName in~ ("httpd.exe","apache.exe","apache2","httpd","php.exe","php-cgi.exe","php-fpm","w3wp.exe","nginx.exe","caddy.exe");
let htaccess = webdirs
    | where FileName =~ ".htaccess"
    | project DeviceName, HtTime = Timestamp, HtFolder = FolderPath, HtProc = InitiatingProcessFileName;
webdirs
| where FileName !~ ".htaccess"
| join kind=inner htaccess on DeviceName
| where Timestamp between (HtTime - win .. HtTime + win)
| project DeviceName, HtTime, HtFolder, HtProc, PayloadTime = Timestamp, PayloadFile = FileName, PayloadFolder = FolderPath, InitiatingProcessFileName, InitiatingProcessAccountName
| order by HtTime desc
```


## Why this matters

Severity classified as **CRIT** based on: 3 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
