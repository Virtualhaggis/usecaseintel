<!-- curated:true -->
# [HIGH] Alleged Silk Typhoon Hacker Extradited to US for Cyberespionage

**Source:** BleepingComputer
**Published:** 2026-04-27
**Article:** https://www.bleepingcomputer.com/news/security/alleged-silk-typhoon-hacker-extradited-to-us-for-cyberespionage/
**Curated:** Analyst-reviewed 2026-04-28

## Threat profile

A Chinese national was **extradited from Italy to the US** to face criminal charges for cyberespionage tied to **Silk Typhoon** (Microsoft's name for the China-aligned threat actor previously known as **Hafnium**, **APT60-adjacent**, **Iron Tiger**). Silk Typhoon is the actor most-publicly tied to the **2021 ProxyLogon Exchange Server zero-day chain** and has been continuously active against:
- US government agencies
- Defense industrial base
- Higher education / research labs
- Telecommunications and ISP infrastructure
- Healthcare and biotech (COVID-era IP theft)

The extradition itself is a legal milestone, not a new TTP — but the **DOJ indictment / unsealing typically includes detailed forensic IOCs** (domains, hashes, infrastructure attribution) that have operational value when published.

We've upgraded severity to **HIGH** because:
- Silk Typhoon's TTPs have been refined over years and span every common enterprise edge surface (Exchange, ADFS, FortiGate, Cisco ASA, Pulse VPN, F5).
- The extradition usually comes with **fresh DOJ IOCs** that should be added to your detection feed within days.
- Even a "historical" actor unsealing surfaces useful baselines — defenders should compare their telemetry against the indicted infrastructure once published.

## Indicators of Compromise

- _DOJ indictment will list specific infrastructure (domains, IPs, email accounts) and target organisations. Pull from the unsealed indictment when published._
- Cross-reference to Microsoft's Silk Typhoon profile (`learn.microsoft.com/en-us/security/threat-intelligence/silk-typhoon`) for known-good IOC bundle.
- Hunt focus: known Silk Typhoon TTPs across Exchange, edge VPN, ADFS, and on-prem-to-cloud pivot.

## MITRE ATT&CK (analyst-validated)

- **T1190** — Exploit Public-Facing Application (Exchange CVE-2021-26855 / 26857 / 26858 / 27065 chain, recent on-prem Exchange 0-days)
- **T1078** — Valid Accounts (post-exploit Exchange admin)
- **T1505.003** — Server Software Component: Web Shell (China Chopper / sccrass.aspx / pre-built ASPX shells)
- **T1059.001** — PowerShell
- **T1003** — OS Credential Dumping
- **T1133** — External Remote Services
- **T1583** — Acquire Infrastructure (rotating C2 domains)

## Recommended SOC actions (priority-ordered)

1. **Pull historic Exchange / ADFS / VPN web-shell hunts.** Silk Typhoon's signature is *web shells on internet-facing servers* — even old foothholds should be hunted retrospectively. ProxyLogon hashes are well-known but small variants persist.
2. **Audit your edge-device population for Silk Typhoon TTPs.** Cisco ASA / FortiGate / Pulse / F5 / Citrix — all classic targets. Cross-reference with the FIRESTARTER briefing (also Cisco-focused).
3. **Watch DOJ / DOJ-CIPCS / FBI IC3 advisories for the next 2-4 weeks.** The unsealing typically generates a new IOC bundle.
4. **Hunt China Chopper / common-aspx-shell footprints** on every IIS instance. This is bread-and-butter that often surfaces dormant footholds from old intrusions.
5. **Audit your Exchange (on-prem) patch posture.** If you still run on-prem Exchange, your patch cadence is your primary control against this actor.

## Splunk SPL — China Chopper / common ASPX web-shell pattern

```spl
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action="created"
      AND (Filesystem.file_name="*.aspx" OR Filesystem.file_name="*.ashx"
        OR Filesystem.file_name="*.asmx" OR Filesystem.file_name="*.cshtml")
      AND (Filesystem.file_path="*\\inetpub\\wwwroot\\*"
        OR Filesystem.file_path="*\\Exchange\\FrontEnd\\HttpProxy\\*"
        OR Filesystem.file_path="*\\Exchange\\ClientAccess\\*"
        OR Filesystem.file_path="*\\Exchange\\OWA\\*")
      AND NOT Filesystem.process_name IN ("msiexec.exe","TrustedInstaller.exe","msdeploy.exe",
                                            "ExSetup.exe","Update.exe")
    by Filesystem.dest, Filesystem.process_name, Filesystem.file_path,
       Filesystem.file_name, Filesystem.user
| `drop_dm_object_name(Filesystem)`
```

## Splunk SPL — IIS / Exchange spawning suspicious children

```spl
| tstats `summariesonly` count
    from datamodel=Endpoint.Processes
    where Processes.parent_process_name IN ("w3wp.exe","UMWorkerProcess.exe","UmService.exe",
                                              "UMWorkerRole.exe")
      AND Processes.process_name IN ("cmd.exe","powershell.exe","wscript.exe","cscript.exe",
                                       "net.exe","whoami.exe","systeminfo.exe","tasklist.exe",
                                       "wmic.exe","reg.exe")
    by Processes.dest, Processes.user, Processes.parent_process_name,
       Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
```

## Splunk SPL — credential dumping on Exchange / DC servers

```spl
| tstats `summariesonly` count
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("ntdsutil.exe","procdump.exe","procdump64.exe")
        OR Processes.process="*lsass*"
        OR Processes.process="*ntds.dit*"
        OR Processes.process="*\\Active Directory\\NTDS\\*"
        OR Processes.process="*-pn lsass*"
        OR Processes.process="*reg save *system*"
        OR Processes.process="*reg save *security*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process,
       Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

## Splunk SPL — outbound from Exchange / ADFS to non-Microsoft destinations

```spl
| tstats `summariesonly` count
    from datamodel=Network_Traffic.All_Traffic
    where (All_Traffic.src_category IN ("exchange","adfs","mail-server","cas","mbx")
        OR All_Traffic.app="*Exchange*")
      AND All_Traffic.action="allowed"
      AND All_Traffic.dest_category!="internal"
      AND All_Traffic.dest!="*microsoft.com*"
      AND All_Traffic.dest!="*office365.com*"
      AND All_Traffic.dest!="*office.com*"
      AND All_Traffic.dest!="*outlook.com*"
    by All_Traffic.src, All_Traffic.dest, All_Traffic.dest_port
| `drop_dm_object_name(All_Traffic)`
```

## Defender KQL — web-shell file creation on IIS / Exchange paths

```kql
DeviceFileEvents
| where Timestamp > ago(180d)
| where ActionType == "FileCreated"
| where FileName endswith ".aspx" or FileName endswith ".ashx"
     or FileName endswith ".asmx" or FileName endswith ".cshtml"
| where FolderPath has_any ("\\inetpub\\wwwroot\\","\\Exchange\\FrontEnd\\HttpProxy\\",
                              "\\Exchange\\ClientAccess\\","\\Exchange\\OWA\\")
| where InitiatingProcessFileName !in~ ("msiexec.exe","TrustedInstaller.exe","msdeploy.exe",
                                          "ExSetup.exe","Update.exe","github-runner.exe")
| project Timestamp, DeviceName, AccountName, FolderPath, FileName,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

## Defender KQL — Exchange / IIS spawning shells

```kql
DeviceProcessEvents
| where Timestamp > ago(180d)
| where InitiatingProcessFileName in~ ("w3wp.exe","UMWorkerProcess.exe","UmService.exe")
| where FileName in~ ("cmd.exe","powershell.exe","wscript.exe","cscript.exe","net.exe",
                       "whoami.exe","systeminfo.exe","tasklist.exe","wmic.exe","reg.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName,
          FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by Timestamp desc
```

## Defender KQL — credential-dump tooling on AD / Exchange

```kql
DeviceProcessEvents
| where Timestamp > ago(180d)
| where (FileName in~ ("ntdsutil.exe","procdump.exe","procdump64.exe","mimikatz.exe"))
     or (ProcessCommandLine has_any ("lsass","ntds.dit","Active Directory\\NTDS",
                                       "reg save HKLM\\SYSTEM","reg save HKLM\\SECURITY"))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

## Why this matters for your SOC

The extradition itself is a legal event; the **operational value is in the IOCs that the DOJ unsealing typically reveals**. Track the indictment — when it lands, the document will list specific:
- Email addresses used for spear-phishing.
- Domains used for C2 staging.
- Service-account names targeted.
- Compromised victim organisations.

That data has **immediate hunt value** — you compare against your telemetry. Beyond the immediate IOCs, the queries above are durable Silk Typhoon hunting baselines. The web-shell-on-IIS query in particular catches not just Silk Typhoon but every Chinese / Iranian / Russian APT operating against on-prem Exchange in 2025-2026.
