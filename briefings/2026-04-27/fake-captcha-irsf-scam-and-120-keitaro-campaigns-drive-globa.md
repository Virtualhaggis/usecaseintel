<!-- curated:true -->
# [HIGH] Fake CAPTCHA IRSF Scam and 120 Keitaro Campaigns Drive Global SMS, Crypto Fraud

**Source:** The Hacker News
**Published:** 2026-04-27
**Article:** https://thehackernews.com/2026/04/fake-captcha-irsf-scam-and-120-keitaro.html
**Curated:** Analyst-reviewed 2026-04-28

## Threat profile

Infoblox reported a global telecom-fraud operation running **120 distinct campaigns** through the **Keitaro Traffic Distribution System** (a legitimate ad-tech tool abused for cyber-criminal traffic shaping). The hook is a **fake CAPTCHA / "verify you're human"** dialog that tricks the victim into one of two flows:

1. **IRSF (International Revenue Share Fraud)** — sending premium-rate SMS that invoices the victim's mobile carrier, profit kicked back to the actor leasing the destination number.
2. **Crypto wallet drainer / address swap** — clipboard-injection or wallet-connect phishing.

For enterprise SOC, the **IRSF angle is consumer-mobile**, but the **fake-CAPTCHA / ClickFix delivery pattern** is **the dominant 2025-2026 commodity malware delivery technique** — used by Lumma Stealer, Vidar, RedLine, AsyncRAT, Latrodectus, Amadey, and dozens of campaigns. Same actor toolkit, different payload.

We've upgraded severity to **HIGH** because:
- The ClickFix vector is the **#1 evasion technique** for endpoint AV in 2026 — execution comes from `explorer.exe` paste, bypassing email gateway entirely.
- 120 active Keitaro campaigns = systematic, well-funded operation that won't disappear.
- The detection logic for ClickFix is straightforward and high-fidelity if you have it.

## Indicators of Compromise

- _Specific Keitaro-driven landing-page domains and CAPTCHA-overlay infrastructure should be in the Infoblox blog body. Pull the canonical IOC list from there._
- Behavioural fingerprints (more durable):
  - User browses to a page → click "I'm not a robot" → receives a **paste this in Run / PowerShell** dialog.
  - `explorer.exe` (or `RuntimeBroker.exe` after Win+R) spawns `powershell.exe` with `-EncodedCommand`, `iex`, `Invoke-Expression`, `DownloadString`, or `Invoke-WebRequest`.

## MITRE ATT&CK (analyst-validated)

- **T1566.002** — Spearphishing Link (the lure to the fake CAPTCHA page)
- **T1204.001** — User Execution: Malicious Link
- **T1204.004** — User Execution: Malicious Copy and Paste (the ClickFix step)
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1027** — Obfuscated Files or Information (the encoded PS payloads)
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1657** — Financial Theft (in the IRSF / wallet-drainer variants)

## Recommended SOC actions (priority-ordered)

1. **Hunt ClickFix / FakeCaptcha clipboard-paste-PowerShell** — the queries below catch this entire class. Tune to your environment, deploy as alerting.
2. **Block / log Win+R execution** for non-IT users where possible (GPO `NoRun` for restricted user groups).
3. **Email + web filtering on ClickFix landing-page indicators** — Keitaro-routed traffic typically passes through chained redirects with telltale URL parameters (`tag=`, `cid=`, `affid=`).
4. **End-user training**: "no legitimate website asks you to paste anything into Win+R or PowerShell — if it does, close the tab and report."
5. **Browser-launched-PowerShell detection** — most legitimate browser activity should *never* spawn PowerShell.
6. **Watch for `mshta.exe` / `cmd.exe /c start`** chains from browser children — alternate ClickFix variants.

## Splunk SPL — ClickFix / FakeCaptcha clipboard-paste-PowerShell

```spl
| tstats `summariesonly` count
    from datamodel=Endpoint.Processes
    where Processes.parent_process_name IN ("explorer.exe","RuntimeBroker.exe","mshta.exe")
      AND Processes.process_name IN ("powershell.exe","pwsh.exe","mshta.exe","cmd.exe","wscript.exe")
      AND (Processes.process="*iex*" OR Processes.process="*Invoke-Expression*"
        OR Processes.process="*FromBase64*" OR Processes.process="*DownloadString*"
        OR Processes.process="*Invoke-WebRequest*" OR Processes.process="*hxxp*"
        OR Processes.process="*curl *" OR Processes.process="*wget *"
        OR Processes.process="*-EncodedCommand*" OR Processes.process="*-enc *")
    by Processes.dest, Processes.user, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

## Splunk SPL — browser-spawned PowerShell / mshta

```spl
| tstats `summariesonly` count
    from datamodel=Endpoint.Processes
    where Processes.parent_process_name IN ("chrome.exe","msedge.exe","firefox.exe",
                                              "brave.exe","opera.exe")
      AND Processes.process_name IN ("powershell.exe","pwsh.exe","mshta.exe","cmd.exe",
                                       "rundll32.exe","regsvr32.exe","wscript.exe")
    by Processes.dest, Processes.user, Processes.parent_process_name,
       Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
```

## Splunk SPL — encoded PowerShell from any source

```spl
| tstats `summariesonly` count
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("powershell.exe","pwsh.exe")
      AND (Processes.process="*-EncodedCommand*" OR Processes.process="*-enc *"
        OR Processes.process="*-NoP -W H *" OR Processes.process="*-WindowStyle Hidden*"
        OR Processes.process="*-NoProfile -ExecutionPolicy Bypass*")
    by Processes.dest, Processes.user, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

## Defender KQL — ClickFix / FakeCaptcha pattern

```kql
DeviceProcessEvents
| where Timestamp > ago(60d)
| where InitiatingProcessFileName in~ ("explorer.exe","RuntimeBroker.exe","mshta.exe")
| where FileName in~ ("powershell.exe","pwsh.exe","mshta.exe","cmd.exe","wscript.exe")
| where ProcessCommandLine matches regex
    @"(?i)(iex |invoke-expression|frombase64|downloadstring|invoke-webrequest|hxxp|curl |wget |-encodedcommand|-enc )"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

## Defender KQL — browser-spawned scripting children

```kql
DeviceProcessEvents
| where Timestamp > ago(60d)
| where InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","firefox.exe",
                                         "brave.exe","opera.exe","arc.exe")
| where FileName in~ ("powershell.exe","pwsh.exe","mshta.exe","cmd.exe",
                       "rundll32.exe","regsvr32.exe","wscript.exe","cscript.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName,
          FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by Timestamp desc
```

## Defender KQL — encoded PowerShell anywhere

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine matches regex
    @"(?i)(-encodedcommand|-enc |-nop -w h|-windowstyle hidden|-noprofile -executionpolicy bypass)"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

## Why this matters for your SOC

ClickFix / FakeCaptcha has **eaten the lunch** of email-gateway-detected phishing. The kill chain:
1. User browses normally → drive-by lure or malvertising redirect.
2. Page shows convincing "Cloudflare / reCAPTCHA / Verify you're human" overlay.
3. Instructions tell user to press `Win+R`, paste a "verification command" (PowerShell base64), and hit Enter.
4. Stage-1 downloader runs from `explorer.exe` parentage — bypasses every email-gateway and most legacy AV.
5. Stage-2 deploys whatever the operator wants — Lumma, Latrodectus, infostealer, ransomware loader.

The detection is **the same regardless of payload** — Keitaro / fake-captcha / ClickFix all funnel through the `explorer.exe → powershell.exe with iex` shape. Build the alert, tune for ~7 days, push to production. It's the single highest-leverage commodity-malware detection of 2026.
