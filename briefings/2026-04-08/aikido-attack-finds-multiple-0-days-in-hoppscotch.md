# [HIGH] Aikido Attack finds multiple 0-days in Hoppscotch

**Source:** Aikido
**Published:** 2026-04-08
**Article:** https://www.aikido.dev/blog/ai-pentest-hoppscotch-vulnerabilities

## Threat Profile

Blog Vulnerabilities & Threats Aikido Attack finds multiple 0-days in Hoppscotch Aikido Attack finds multiple 0-days in Hoppscotch Written by Robbe Verwilghen Published on: Apr 8, 2026 Introduction Hoppscotch is an open-source API development ecosystem, similar to Postman, with over 100,000 monthly users. Two weeks ago, we set up a self-hosted instance and ran our AI pentest agents against it. They found two high-severity vulnerabilities and one medium-severity vulnerability, all present in vers…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1005** — Data from Local System
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1195.002** — Compromise Software Supply Chain
- **T1190** — Exploit Public-Facing Application
- **T1566.002** — Phishing: Spearphishing Link
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1185** — Browser Session Hijacking
- **T1213** — Data from Information Repositories
- **T1199** — Trusted Relationship

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Hoppscotch device-login open redirect token theft via localhost.* / sslip.io bypass

`UC_360_3` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where Web.url="*/device-login*" Web.url="*redirect_uri*" (Web.url="*localhost.*" OR Web.url="*sslip.io*") by Web.src Web.dest Web.url Web.user Web.http_user_agent
| `drop_dm_object_name(Web)`
| where NOT match(url, "redirect_uri=https?(:|%3A)(/|%2F){2}localhost(:|%3A|/|%2F)")
| convert ctime(firstTime) ctime(lastTime)
| table firstTime, lastTime, src, user, dest, url, http_user_agent, count
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl contains "/device-login"
| where RemoteUrl contains "redirect_uri"
| where RemoteUrl contains "localhost." or RemoteUrl contains "sslip.io"
| where InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","safari.exe","opera.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteUrl, RemoteIP, RemotePort
```

### [LLM] Hoppscotch Mock Server stored XSS via GraphQL updateRESTUserRequest content-type override

`UC_360_4` · phase: **exploit** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as graphqlTime from datamodel=Web where Web.url="*/graphql*" Web.http_method=POST by Web.src Web.user Web.url
| `drop_dm_object_name(Web)`
| join type=inner src [
    | tstats summariesonly=true count min(_time) as mockTime from datamodel=Web where Web.url="*/mock/*" Web.http_method=GET by Web.src Web.url Web.http_user_agent
    | `drop_dm_object_name(Web)`
    | rename url as mockUrl http_user_agent as mockUA
  ]
| where mockTime >= graphqlTime AND mockTime <= graphqlTime + 86400
| where match(mockUA, "(?i)(Mozilla|Chrome|Firefox|Safari|Edge)")
| table graphqlTime, mockTime, src, user, url, mockUrl, mockUA
```

**Defender KQL:**
```kql
let GraphqlPosts = DeviceNetworkEvents
    | where Timestamp > ago(7d)
    | where RemoteUrl contains "/graphql"
    | where InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","curl.exe","python.exe","node.exe")
    | project GraphqlTime=Timestamp, DeviceId, InitiatingProcessAccountName, GraphqlUrl=RemoteUrl;
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl contains "/mock/"
| where InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","safari.exe")
| join kind=inner GraphqlPosts on DeviceId
| where Timestamp between (GraphqlTime .. GraphqlTime + 24h)
| project Timestamp, GraphqlTime, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, MockUrl=RemoteUrl, GraphqlUrl
```

### [LLM] Hoppscotch cross-team request injection via moveRequest GraphQL with null nextRequestID

`UC_360_5` · phase: **exploit** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
index=* (sourcetype=nginx:plus:access OR sourcetype=hoppscotch:* OR sourcetype=waf:*)
  uri_path="*/graphql*" http_method=POST
  ("MoveTeamRequest" OR "moveRequest")
  "nextRequestID" "null"
  destCollID
| rex field=_raw "\"req\"\s*:\s*\"(?<reqId>[^\"]+)\""
| rex field=_raw "\"dest\"\s*:\s*\"(?<destCollId>[^\"]+)\""
| rex field=_raw "\"next\"\s*:\s*(?<nextVal>null|\"[^\"]*\")"
| where nextVal="null"
| stats count, values(reqId) as movedRequestIds, values(destCollId) as destCollIds, dc(destCollId) as uniqueDests, earliest(_time) as first, latest(_time) as last by src, user
| where count >= 1
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


## Why this matters

Severity classified as **HIGH** based on: 6 use case(s) fired, 10 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
