# [CRIT] SvelteSpill: A Cache Deception Bug in SvelteKit + Vercel

**Source:** Aikido
**Published:** 2026-02-19
**Article:** https://www.aikido.dev/blog/sveltespill-cache-deception-sveltekit-vercel

## Threat Profile

Blog Vulnerabilities & Threats SvelteSpill: A Cache Deception Bug in SvelteKit + Vercel SvelteSpill: A Cache Deception Bug in SvelteKit + Vercel Written by Jorian Woltjer Published on: Feb 19, 2026 SvelteKit is a popular full-stack JavaScript framework, and Vercel is its most common deployment platform. What if we told you that all apps built using this combination were vulnerable to attackers reading responses from any route of other signed-in users?
Well, it’s true. This attack vector, called …

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-27118`

## MITRE ATT&CK Techniques

- **T1005** — Data from Local System
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1190** — Exploit Public-Facing Application
- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1606.001** — Forge Web Credentials: Web Cookies
- **T1213** — Data from Information Repositories

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] SvelteKit Vercel Adapter Cache Deception via __pathname Override (CVE-2026-27118)

`UC_397_5` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.url) as url values(Web.src) as src values(Web.http_user_agent) as ua values(Web.status) as status from datamodel=Web.Web where (Web.uri_path="/_app/immutable/*" OR Web.url="*/_app/immutable/*") (Web.uri_query="*__pathname=*" OR Web.url="*__pathname=*") by Web.dest Web.src Web.uri_path Web.uri_query | `drop_dm_object_name(Web)` | rex field=uri_query "__pathname=(?<rewritten_path>[^&]+)" | where isnotnull(rewritten_path) | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
// Defender XDR has no server-side web log table; this catches the
// phished-link delivery path (Safe Links) where the attacker mails
// the crafted URL to victims. Pair with web-tier rule above.
UrlClickEvents
| where Timestamp > ago(7d)
| where Url has "/_app/immutable/" and Url has "__pathname="
| extend RewrittenPath = extract(@"[?&]__pathname=([^&]+)", 1, Url)
| project Timestamp, AccountUpn, Url, RewrittenPath, ActionType, IsClickedThrough, IPAddress, NetworkMessageId, Workload
| order by Timestamp desc
```

### [LLM] Cache Deception Retrieval: Same /_app/immutable/ __pathname URL Hit by Multiple Distinct Clients

`UC_397_6` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count values(Web.src) as src_ips dc(Web.src) as distinct_clients values(Web.http_user_agent) as user_agents dc(Web.http_user_agent) as distinct_uas min(_time) as firstTime max(_time) as lastTime values(Web.status) as statuses from datamodel=Web.Web where (Web.uri_path="/_app/immutable/*" OR Web.url="*/_app/immutable/*") (Web.uri_query="*__pathname=*" OR Web.url="*__pathname=*") by Web.dest Web.uri_path Web.uri_query span=10m | `drop_dm_object_name` | where distinct_clients>=2 | rex field=uri_query "__pathname=(?<rewritten_path>[^&]+)" | convert ctime(firstTime) ctime(lastTime) | sort - distinct_clients
```

### Crypto-wallet file/keystore access by non-wallet process

`UC_CRYPTO_WALLET` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Filesystem
    where (Filesystem.file_path="*\Ethereum\keystore\*"
        OR Filesystem.file_path="*\Bitcoin\wallet.dat"
        OR Filesystem.file_path="*\Exodus\exodus.wallet*"
        OR Filesystem.file_path="*\Electrum\wallets\*"
        OR Filesystem.file_path="*\MetaMask\*"
        OR Filesystem.file_path="*\Phantom\*"
        OR Filesystem.file_path="*\Atomic\Local Storage\*")
      AND NOT Filesystem.process_name IN ("MetaMask.exe","Exodus.exe","Atomic.exe","electrum.exe","Bitcoin.exe","Phantom.exe")
    by Filesystem.dest, Filesystem.process_name, Filesystem.file_path, Filesystem.user
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName !endswith "$"
| where FolderPath has_any (@"\Ethereum\keystore\", @"\Bitcoin\", @"\Exodus\", @"\Electrum\wallets\", @"\MetaMask\", @"\Phantom\", @"\Atomic\Local Storage\")
| where InitiatingProcessFileName !in~ ("MetaMask.exe","Exodus.exe","Atomic.exe","electrum.exe","Bitcoin.exe","Phantom.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, FolderPath, FileName, ActionType
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

### Trusted vendor binary / installer launching unusual children

`UC_SUPPLY_CHAIN` · phase: **exploit** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.parent_process_name IN ("setup.exe","installer.exe","update.exe")
      AND Processes.process_name IN ("powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","wmic.exe","bitsadmin.exe")
    by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where InitiatingProcessFileName in~ ("setup.exe","installer.exe","update.exe")
| where FileName in~ ("powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","wmic.exe","bitsadmin.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

### Article-specific behavioural hunt — SvelteSpill: A Cache Deception Bug in SvelteKit + Vercel

`UC_397_4` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — SvelteSpill: A Cache Deception Bug in SvelteKit + Vercel ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("serverless.js","clo1dlt2.js","kqf6jjr8.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("serverless.js","clo1dlt2.js","kqf6jjr8.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — SvelteSpill: A Cache Deception Bug in SvelteKit + Vercel
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("serverless.js", "clo1dlt2.js", "kqf6jjr8.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("serverless.js", "clo1dlt2.js", "kqf6jjr8.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-27118`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 7 use case(s) fired, 8 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
