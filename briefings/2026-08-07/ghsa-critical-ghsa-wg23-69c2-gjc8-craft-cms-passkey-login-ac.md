# [CRIT] [GHSA / CRITICAL] GHSA-wg23-69c2-gjc8: Craft CMS: Passkey login accepts replayed WebAuthn assertions

**Source:** GitHub Security Advisories
**Published:** 2026-08-07
**Article:** https://github.com/advisories/GHSA-wg23-69c2-gjc8

## Threat Profile

Craft CMS: Passkey login accepts replayed WebAuthn assertions

Craft CMS passkey login accepts WebAuthn requestOptions from the unauthenticated login request body and does not persist the updated credential counter returned by the WebAuthn assertion validator. A captured passkey login request body can therefore be replayed because the old challenge is accepted again, and the stored credential counter remains stale.

Craft CMS 5.10.3 and current `5.x` HEAD accept `PublicKeyCredentialRequestOption…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1176** — Browser Extensions
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1550** — Use Alternate Authentication Material
- **T1212** — Exploitation for Credential Access
- **T1078** — Valid Accounts

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Craft CMS passkey assertion replay: repeated POST to users/login-with-passkey

`UC_1_2` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, min(_time) as firstTime, max(_time) as lastTime, values(Web.status) as statuses, values(Web.http_user_agent) as user_agents from datamodel=Web where Web.http_method=POST Web.url="*login-with-passkey*" (Web.status=200 OR Web.status=302) by Web.src, Web.url, _time span=10m | `drop_dm_object_name(Web)` | where count>=2 | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | sort - count
```

### Craft passkey replay: identical request-body size reposted to login-with-passkey

`UC_1_3` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, dc(Web.src) as distinct_ips, values(Web.src) as src_ips, min(_time) as firstTime, max(_time) as lastTime from datamodel=Web where Web.http_method=POST Web.url="*login-with-passkey*" (Web.status=200 OR Web.status=302) Web.bytes_in>0 by Web.url, Web.bytes_in | `drop_dm_object_name(Web)` | where count>=2 | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | sort - count
```

### Suspicious browser extension installation

`UC_BROWSER_EXT` · phase: **install** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Registry
    where (Registry.registry_path="*\Software\Google\Chrome\Extensions\*"
        OR Registry.registry_path="*\Software\Microsoft\Edge\Extensions\*"
        OR Registry.registry_path="*\Software\Mozilla\Firefox\Extensions\*")
    by Registry.dest, Registry.registry_path, Registry.registry_value_data, Registry.registry_value_name, Registry.user
| `drop_dm_object_name(Registry)`
```

**Defender KQL:**
```kql
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName !endswith "$"
| where RegistryKey has_any ("\Software\Google\Chrome\Extensions\","\Software\Microsoft\Edge\Extensions\","\Software\Mozilla\Firefox\Extensions\")
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData,
          InitiatingProcessFileName, InitiatingProcessAccountName
```

### Infostealer — non-browser process accessing browser cookie/login DBs

`UC_BROWSER_STEALER` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Filesystem
    where (Filesystem.file_path="*\Google\Chrome\User Data\*\Login Data*"
        OR Filesystem.file_path="*\Google\Chrome\User Data\*\Cookies*"
        OR Filesystem.file_path="*\Microsoft\Edge\User Data\*\Login Data*"
        OR Filesystem.file_path="*\Mozilla\Firefox\Profiles\*\logins.json*"
        OR Filesystem.file_path="*\Mozilla\Firefox\Profiles\*\cookies.sqlite*")
      AND NOT Filesystem.process_name IN ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
    by Filesystem.dest, Filesystem.process_name, Filesystem.file_path, Filesystem.user
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName !endswith "$"
| where FolderPath has_any (@"\Google\Chrome\User Data\", @"\Microsoft\Edge\User Data\", @"\Mozilla\Firefox\Profiles\")
| where FileName in~ ("Login Data","Cookies","logins.json","cookies.sqlite")
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, FolderPath, FileName, ActionType
```


## Why this matters

Severity classified as **CRIT** based on: 4 use case(s) fired, 6 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
