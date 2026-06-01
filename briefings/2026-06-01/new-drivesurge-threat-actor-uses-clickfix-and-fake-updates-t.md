# [MED] New DriveSurge Threat Actor Uses ClickFix and Fake Updates to Infect Website Visitors

**Source:** Cyber Security News
**Published:** 2026-06-01
**Article:** https://cybersecuritynews.com/new-drivesurge-threat-actor-uses-clickfix/

## Threat Profile

A newly identified threat actor named DriveSurge has been quietly compromising thousands of legitimate websites to push malware onto unsuspecting visitors. Using a combination of fake browser update pages and a social engineering trick known as ClickFix, this operation ran largely undetected until now. What makes DriveSurge especially dangerous is not just its scale, but [&#8230;] The post New DriveSurge Threat Actor Uses ClickFix and Fake Updates to Infect Website Visitors appeared first on Cyb…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `91.92.240.127`
- **IPv4 (defanged):** `46.226.166.57`
- **IPv4 (defanged):** `147.45.42.200`
- **IPv4 (defanged):** `147.45.42.205`
- **Domain (defanged):** `beacontrace.bond`
- **Domain (defanged):** `webgleam.info`
- **Domain (defanged):** `check.first-node.rocks`
- **Domain (defanged):** `cptoptious.com`
- **Domain (defanged):** `banerpanel.live`
- **Domain (defanged):** `testio.ecartdev.com`
- **Domain (defanged):** `maxintora.com`
- **Domain (defanged):** `newtdsone.shop`
- **Domain (defanged):** `captioto.com`
- **Domain (defanged):** `brightson.icu`
- **Domain (defanged):** `coverlink.icu`
- **Domain (defanged):** `datumprobe.icu`
- **Domain (defanged):** `eraggifts.icu`
- **Domain (defanged):** `keyview.icu`
- **Domain (defanged):** `traceglimpse.icu`
- **Domain (defanged):** `tracekey.icu`
- **Domain (defanged):** `ycyfugihih.cfd`
- **Domain (defanged):** `flixtrend.net`
- **Domain (defanged):** `cptoptions.com`
- **Domain (defanged):** `bseolized.com`
- **SHA256:** `90aecb370dfb1a99a1f7de0a9c6842ab1b664521fddea16b0ec9a91f322646fc`
- **SHA256:** `7aa15de93cf85729ddf970e8d7897f69ece3ca29608f73e784a9ba40c9cea18d`
- **SHA256:** `8ecc7108cd679316bf5900e84f19b256dc399902cdede646493f502ac872cc1a`
- **SHA256:** `e1ce4e6222396a58d13dddfe64c1dd21f1632bcbe11d1867d44bab4fc646883a`
- **SHA256:** `29ac78c51bcdfe68c64830bdeb6e41437dd55e2691149741c9b78be03b6c82ea`
- **SHA256:** `a84b032b49773c2318b11b1164d1aada69e940229aedbf8185c33fc7dd1d2cdf`
- **SHA256:** `0c62c11e910d7c0d6b6c9800b70e78bfd9220e1f78bd7bb34ae4c3646d05f6e5`
- **SHA256:** `428bd0b0ac36dfdd223b3953dbe61c0baf227f893310b03e7afe3111462019c6`

## MITRE ATT&CK Techniques

- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Phishing-link click correlated to endpoint execution

`UC_PHISH_LINK` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Phishing-link click that drives endpoint execution within 60s ```
| tstats `summariesonly` earliest(_time) AS click_time
    from datamodel=Web
    where Web.action="allowed"
    by Web.src, Web.user, Web.dest, Web.url
| `drop_dm_object_name(Web)`
| rename user AS recipient, dest AS clicked_domain, url AS clicked_url
| join type=inner recipient
    [| tstats `summariesonly` count
         from datamodel=Email.All_Email
         where All_Email.action="delivered" AND All_Email.url!="-"
         by All_Email.recipient, All_Email.src_user, All_Email.url, All_Email.subject
     | `drop_dm_object_name(All_Email)`
     | rex field=url "https?://(?<email_domain>[^/]+)"
     | rename recipient AS recipient]
| join type=inner src
    [| tstats `summariesonly` earliest(_time) AS exec_time
         values(Processes.process) AS exec_cmd, values(Processes.process_name) AS exec_proc
         from datamodel=Endpoint.Processes
         where Processes.parent_process_name IN ("chrome.exe","msedge.exe","firefox.exe",
                                                   "outlook.exe","brave.exe","arc.exe")
           AND Processes.process_name IN ("powershell.exe","pwsh.exe","cmd.exe","mshta.exe",
                                            "rundll32.exe","regsvr32.exe","wscript.exe",
                                            "cscript.exe","bitsadmin.exe","certutil.exe",
                                            "curl.exe","wget.exe")
         by Processes.dest, Processes.user
     | `drop_dm_object_name(Processes)`
     | rename dest AS src]
| eval delta_sec = exec_time - click_time
| where delta_sec >= 0 AND delta_sec <= 60
| table click_time, exec_time, delta_sec, recipient, src, src_user, subject,
        clicked_domain, clicked_url, exec_proc, exec_cmd
| sort - click_time
```

**Defender KQL:**
```kql
// Phishing-link click that drives endpoint execution within 60s.
// Far higher fidelity than "every clicked URL" — most legitimate clicks
// never spawn a non-browser child process, so the join eliminates the
// 99% of noise that makes a raw click query unactionable.
let LookbackDays = 7d;
let SuspectClicks = UrlClickEvents
    | where Timestamp > ago(LookbackDays)
    | where AccountName !endswith "$"
    | where ActionType in ("ClickAllowed","ClickedThrough")
    | join kind=inner (
        EmailEvents
        | where Timestamp > ago(LookbackDays)
        | where DeliveryAction == "Delivered"
        | where EmailDirection == "Inbound"
        | project NetworkMessageId, Subject, SenderFromAddress, SenderFromDomain,
                  RecipientEmailAddress, EmailTimestamp = Timestamp
      ) on NetworkMessageId
    | join kind=leftouter (
        EmailUrlInfo | project NetworkMessageId, Url, UrlDomain
      ) on NetworkMessageId, Url
    | project ClickTime = Timestamp, AccountUpn, IPAddress, Url, UrlDomain,
              Subject, SenderFromAddress, SenderFromDomain, RecipientEmailAddress,
              ActionType;
// Correlate to a non-browser child process spawned within 60 seconds on
// the recipient's device.
DeviceProcessEvents
| where Timestamp > ago(LookbackDays)
| where InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","firefox.exe",
                                         "outlook.exe","brave.exe","arc.exe")
| where FileName in~ ("powershell.exe","pwsh.exe","cmd.exe","mshta.exe",
                        "rundll32.exe","regsvr32.exe","wscript.exe","cscript.exe",
                        "bitsadmin.exe","certutil.exe","curl.exe","wget.exe")
| join kind=inner SuspectClicks on $left.AccountName == $right.AccountUpn
| where Timestamp between (ClickTime .. ClickTime + 60s)
| project ClickTime, ProcessTime = Timestamp,
          DelaySec = datetime_diff('second', Timestamp, ClickTime),
          DeviceName, AccountName, RecipientEmailAddress, SenderFromAddress,
          Subject, Url, UrlDomain, ActionType,
          FileName, ProcessCommandLine, InitiatingProcessFileName
| order by ClickTime desc
```

### Fake CAPTCHA / clipboard-injected PowerShell (ClickFix / FakeCaptcha)

`UC_FAKECAPTCHA` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.parent_process_name IN ("explorer.exe","RuntimeBroker.exe")
      AND Processes.process_name IN ("powershell.exe","pwsh.exe","mshta.exe")
      AND (Processes.process="*iex*" OR Processes.process="*Invoke-Expression*"
        OR Processes.process="*FromBase64*" OR Processes.process="*DownloadString*"
        OR Processes.process="*hxxp*" OR Processes.process="*curl*" OR Processes.process="*wget*")
    by Processes.dest, Processes.user, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where InitiatingProcessFileName in~ ("explorer.exe","RuntimeBroker.exe")
| where FileName in~ ("powershell.exe","pwsh.exe","mshta.exe")
| where ProcessCommandLine matches regex @"(?i)(iex|invoke-expression|frombase64|downloadstring|hxxp|curl |wget )"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessCommandLine
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `91.92.240.127`, `46.226.166.57`, `147.45.42.200`, `147.45.42.205`, `beacontrace.bond`, `webgleam.info`, `check.first-node.rocks`, `cptoptious.com` _(+16 more)_

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `90aecb370dfb1a99a1f7de0a9c6842ab1b664521fddea16b0ec9a91f322646fc`, `7aa15de93cf85729ddf970e8d7897f69ece3ca29608f73e784a9ba40c9cea18d`, `8ecc7108cd679316bf5900e84f19b256dc399902cdede646493f502ac872cc1a`, `e1ce4e6222396a58d13dddfe64c1dd21f1632bcbe11d1867d44bab4fc646883a`, `29ac78c51bcdfe68c64830bdeb6e41437dd55e2691149741c9b78be03b6c82ea`, `a84b032b49773c2318b11b1164d1aada69e940229aedbf8185c33fc7dd1d2cdf`, `0c62c11e910d7c0d6b6c9800b70e78bfd9220e1f78bd7bb34ae4c3646d05f6e5`, `428bd0b0ac36dfdd223b3953dbe61c0baf227f893310b03e7afe3111462019c6`


## Why this matters

Severity classified as **MED** based on: IOCs present, 4 use case(s) fired, 6 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
