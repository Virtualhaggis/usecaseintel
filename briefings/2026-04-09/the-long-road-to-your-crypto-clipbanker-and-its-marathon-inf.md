<!-- curated:true -->
# [HIGH] The Long Road to Your Crypto: ClipBanker and Its Marathon Infection Chain

**Source:** Securelist (Kaspersky)
**Published:** 2026-04-09
**Article:** https://securelist.com/clipbanker-malware-distributed-via-trojanized-proxifier/119341/
**Curated:** Analyst-reviewed 2026-04-28

## Threat profile

Kaspersky tracks **ClipBanker** delivered via **trojanised Proxifier** — a legitimate proxy-tunnelling tool popular with developers working in secured / segmented network environments. The infection chain is **deliberately long** (~6 stages) to evade sandboxing and signature detection:

1. SEO-poisoned search results for "Proxifier download" lead users to fake mirror sites.
2. Trojanised Proxifier installer (`maper.info`, `chiaselinks.com`, `rlim.com`).
3. Dropper fetches stage-2 from **dead-drop dispensers** (pastebin / GitHub gists / snippet hosts) — the malware reads attacker config from a public paste rather than calling out to attacker-owned C2.
4. Stage-2 deploys ClipBanker — **clipboard-watching cryptocurrency-address swapper**: when the user copies a wallet address (BTC, ETH, etc.), the malware silently replaces it with the attacker's address before paste.
5. Victim sends crypto to attacker. Defender sees a normal "user copy-paste" event.

For enterprise SOCs, the developer-tool vector matters:
- **Proxifier is heavily used in regulated/segmented dev environments** — exactly the privileged-access workstations that handle API keys, signing keys, and crypto operations (treasury, custody, blockchain-engineering).
- The **dead-drop pattern** (legitimate platforms as C2) means traditional **destination-domain blocking is useless** — pastebin/github/gist are universally allowlisted.
- ClipBanker is **silent until the moment of theft**; there's no encryption / no obvious behavioural giveaway.

## Indicators of Compromise (high-fidelity only)

- **Attacker-controlled distribution domains** (block these):
  - `maper.info`, `chiaselinks.com`, `rlim.com`, `paste.kealper.com`, `git.parat.swiss`, `pinhole.rootcode.ru`
- **Dead-drop dispensers used by ClipBanker** (do NOT block — they're legitimate):
  - `pastebin.com`, `snippet.host`, `github.com`, `gist.github.com`
  - Hunt for **specific paste / gist URIs** referenced in the campaign (in the Securelist write-up body).
- **Hashes** (mix of SHA1 + MD5):
  - SHA1: `d85cef60cdb9e8d0f3cb3546de6ab657f9498ac7`
  - MD5: `107484d66423cb601f418344cd648f12`, `34a0f70ab100c47caaba7a5c85448e3d`, `7528bf597fd7764fcb7ec06512e073e0`, `8354223cd6198b05904337b5dff7772b`

## MITRE ATT&CK (analyst-validated)

- **T1583.008** — Acquire Infrastructure: Malvertising / SEO poisoning
- **T1204.002** — User Execution: Malicious File (the trojanised installer)
- **T1102.001** — Web Service: Dead Drop Resolver (pastebin / gist for stage-2 config)
- **T1115** — Clipboard Data (the core technique — clipboard monitor/swap)
- **T1657** — Financial Theft (cryptocurrency)
- **T1027** — Obfuscated Files or Information
- **T1071.001** — Application Layer Protocol: Web Protocols

## Recommended SOC actions (priority-ordered)

1. **Block the 6 attacker-controlled distribution domains** at egress today.
2. **Hash-match the SHA1 + 4 MD5** against EDR file/process events.
3. **Hunt for Proxifier installs originating from non-vendor sources** — see queries below. Legitimate Proxifier comes from `proxifier.com`; anything else is suspect.
4. **Brief crypto-handling and dev users**: SEO-poisoning is the entry vector. The fix is "always download dev tools from the vendor's primary domain, never a Google-search top result."
5. **Audit clipboard-monitoring telemetry** — your EDR may not surface clipboard-swap behaviour by default. ClipBanker requires opt-in clipboard auditing on most stacks.
6. **Treasury / crypto-ops process control**: enforce **address-confirmation step** in your wallet-send workflow. Even if clipboard is silently swapped, the step that requires manually re-entering or confirming the address visually catches the swap.

## Splunk SPL — Proxifier install from non-vendor source

```spl
| tstats `summariesonly` count
    from datamodel=Endpoint.Processes
    where (Processes.process_name="Proxifier*" OR Processes.process="*Proxifier*setup*"
        OR Processes.process="*Proxifier*.msi*")
      AND NOT Processes.process_path="*Program Files\\Proxifier*"
    by Processes.dest, Processes.user, Processes.process_name, Processes.process_path,
       Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

## Splunk SPL — outbound to attacker distribution domains

```spl
| tstats `summariesonly` count
    from datamodel=Web
    where Web.dest IN ("maper.info","chiaselinks.com","rlim.com","paste.kealper.com",
                        "git.parat.swiss","pinhole.rootcode.ru")
       OR Web.url="*maper.info*"
       OR Web.url="*paste.kealper.com*"
       OR Web.url="*pinhole.rootcode.ru*"
    by Web.src, Web.dest, Web.url, Web.user
| `drop_dm_object_name(Web)`
```

## Splunk SPL — file-hash IOC match

```spl
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.file_hash IN (
        "d85cef60cdb9e8d0f3cb3546de6ab657f9498ac7",
        "107484d66423cb601f418344cd648f12","34a0f70ab100c47caaba7a5c85448e3d",
        "7528bf597fd7764fcb7ec06512e073e0","8354223cd6198b05904337b5dff7772b")
    by Filesystem.dest, Filesystem.user, Filesystem.file_path,
       Filesystem.file_name, Filesystem.file_hash
| `drop_dm_object_name(Filesystem)`
```

## Defender KQL — Proxifier install path anomaly

```kql
DeviceProcessEvents
| where Timestamp > ago(60d)
| where FileName has "Proxifier" or ProcessCommandLine has "Proxifier"
| where FolderPath !startswith "C:\\Program Files\\Proxifier"
   and FolderPath !startswith "C:\\Program Files (x86)\\Proxifier"
| project Timestamp, DeviceName, AccountName, FolderPath, FileName,
          ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

## Defender KQL — outbound to ClipBanker distribution IOCs

```kql
DeviceNetworkEvents
| where Timestamp > ago(90d)
| where RemoteUrl has_any (
    "maper.info","chiaselinks.com","rlim.com","paste.kealper.com",
    "git.parat.swiss","pinhole.rootcode.ru")
| project Timestamp, DeviceName, AccountName, RemoteUrl, RemoteIP, RemotePort,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

## Defender KQL — hash match

```kql
let clipbankerHashes = dynamic([
    "d85cef60cdb9e8d0f3cb3546de6ab657f9498ac7",
    "107484d66423cb601f418344cd648f12","34a0f70ab100c47caaba7a5c85448e3d",
    "7528bf597fd7764fcb7ec06512e073e0","8354223cd6198b05904337b5dff7772b"]);
union DeviceFileEvents, DeviceProcessEvents
| where Timestamp > ago(60d)
| where SHA1 in~ (clipbankerHashes) or MD5 in~ (clipbankerHashes)
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, MD5, SHA1, ProcessCommandLine
| order by Timestamp desc
```

## Why this matters for your SOC

ClipBanker is the **2026 commodity-malware version of "live-off-the-clipboard"** — it's been around for 5+ years across many families, but Kaspersky's writeup makes the **dead-drop infection chain** explicit. Two takeaways:

1. **The dev-tool-via-SEO-poisoning vector is permanent.** Train your dev community to bookmark vendor domains and never trust Google's first result for a dev-tool download. Cohere Talos / Kaspersky / etc. publish updated SEO-poisoning IOCs every month — subscribe to those feeds.

2. **Pastebin / GitHub / gist as C2 dispenser** is the harder problem to solve at the network layer. The defence is at the **endpoint behaviour layer**: the malicious downloader is still a process making HTTPS requests from non-browser parents to legitimate dispensers. That's a different signal than blocking the destination — and it generalises to dozens of other malware families using the same pattern.

The 6 attacker domains + 5 hashes are operational today. The behavioural-detection investment is the medium-term work.

Table of Contents
Victims 
Conclusion 
Indicators of compromise 
Authors
Oleg Kupreev 
At the start of the year, a certain Trojan caught our eye due to its incredibly long infection chain. In most cases, it kicks off with a web search for “Proxifier”. Proxifiers are speciaized software designed to tunnel traffic for programs that do not natively support proxy servers. They are a go-to for making sure these apps are functional within secured development environments.
By coincidence, Proxifier is …

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `maper.info`
- **Domain (defanged):** `pastebin.com`
- **Domain (defanged):** `snippet.host`
- **Domain (defanged):** `chiaselinks.com`
- **Domain (defanged):** `rlim.com`
- **Domain (defanged):** `paste.kealper.com`
- **Domain (defanged):** `git.parat.swiss`
- **Domain (defanged):** `pinhole.rootcode.ru`
- **Domain (defanged):** `github.com`
- **Domain (defanged):** `gist.github.com`
- **SHA1:** `d85cef60cdb9e8d0f3cb3546de6ab657f9498ac7`
- **MD5:** `107484d66423cb601f418344cd648f12`
- **MD5:** `34a0f70ab100c47caaba7a5c85448e3d`
- **MD5:** `7528bf597fd7764fcb7ec06512e073e0`
- **MD5:** `8354223cd6198b05904337b5dff7772b`

## MITRE ATT&CK Techniques

- **T1005** — Data from Local System
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1053.005** — Scheduled Task
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1071** — Application Layer Protocol

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

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
| where FolderPath has_any ("\Ethereum\keystore\","\Bitcoin\","\Exodus\","\Electrum\wallets\","\MetaMask\","\Phantom\","\Atomic\Local Storage\")
| where InitiatingProcessFileName !in~ ("MetaMask.exe","Exodus.exe","Atomic.exe","electrum.exe","Bitcoin.exe","Phantom.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FolderPath, FileName, ActionType
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
| where FolderPath has_any ("\Google\Chrome\User Data\","\Microsoft\Edge\User Data\","\Mozilla\Firefox\Profiles\")
| where FileName in~ ("Login Data","Cookies","logins.json","cookies.sqlite")
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FolderPath, FileName, ActionType
```

### Scheduled task created with suspicious image / encoded args

`UC_SCHEDULED_TASK` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name="schtasks.exe" AND Processes.process="*/create*"
      AND (Processes.process="*powershell*" OR Processes.process="*cmd.exe*"
        OR Processes.process="*rundll32*" OR Processes.process="*-enc*"
        OR Processes.process="*FromBase64*" OR Processes.process="*\Users\Public*"
        OR Processes.process="*\AppData\*")
    by Processes.dest, Processes.user, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create"
| where ProcessCommandLine has_any ("powershell","cmd.exe","rundll32","-enc","FromBase64","\Users\Public","\AppData\")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
```

### PowerShell encoded / obfuscated command

`UC_PS_OBFUSCATED` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("powershell.exe","pwsh.exe")
      AND (Processes.process="*-enc *" OR Processes.process="*EncodedCommand*"
        OR Processes.process="*FromBase64String*" OR Processes.process="*-nop*"
        OR Processes.process="*-w hidden*" OR Processes.process="*Invoke-Expression*"
        OR Processes.process="*IEX(*" OR Processes.process="*DownloadString*"
        OR Processes.process="*Net.WebClient*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine matches regex @"(?i)(-enc|encodedcommand|frombase64string|-nop|-w\s+hidden|invoke-expression|iex\s*\(|downloadstring|net\.webclient)"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `maper.info`, `pastebin.com`, `snippet.host`, `chiaselinks.com`, `rlim.com`, `paste.kealper.com`, `git.parat.swiss`, `pinhole.rootcode.ru` _(+2 more)_

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `d85cef60cdb9e8d0f3cb3546de6ab657f9498ac7`, `107484d66423cb601f418344cd648f12`, `34a0f70ab100c47caaba7a5c85448e3d`, `7528bf597fd7764fcb7ec06512e073e0`, `8354223cd6198b05904337b5dff7772b`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 6 use case(s) fired, 7 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
