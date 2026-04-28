<!-- curated:true -->
# [HIGH] Cross-Tenant Helpdesk Impersonation to Data Exfiltration: A Human-Operated Intrusion Playbook

**Source:** Microsoft Security Blog
**Published:** 2026-04-18
**Article:** https://www.microsoft.com/en-us/security/blog/2026/04/18/crosstenant-helpdesk-impersonation-data-exfiltration-human-operated-intrusion-playbook/
**Curated:** Analyst-reviewed 2026-04-28

## Threat profile

Microsoft details a **human-operated intrusion** technique that's now common across multiple actor sets (Storm-1811 / Black Basta affiliates, Octo Tempest, recent Scattered Spider engagements):

1. Attacker creates a **lookalike Microsoft 365 tenant** with display names like "IT Support", "Helpdesk", "Service Desk", or victim-org-name.
2. Initiates **external Teams chat** with target user (legitimate cross-tenant collaboration).
3. **Impersonates IT** via the chat ("we're seeing alerts on your endpoint, can you accept this Quick Assist session?").
4. Convinces user to install / accept **RMM tool** (Quick Assist, AnyDesk, ScreenConnect, Atera, Splashtop) — granting hands-on-keyboard access.
5. Uses legitimate admin tooling (PsExec, WMI, RDP, BITS, scheduled tasks) to move laterally and exfiltrate.

This bypasses email gateway, doesn't require credentials at the start, and uses Microsoft's own collaboration features. The "trust signals" are inverted — the attacker is *more* trusted because they came via Teams (perceived internal channel).

We've upgraded severity to **HIGH** because the technique is **actively in use** by multiple ransomware affiliates and the **detection requires Teams + endpoint + identity correlation** that most SOCs haven't wired together.

## Indicators of Compromise

- _No specific IOCs — this is a behavioural / TTP class. Microsoft cites Storm-1811 / Octo Tempest / similar; consult Microsoft Threat Intelligence advisories for active actor-attributed IOCs._
- Telemetry signals: external Teams chat from "IT/helpdesk-named" sender, recent RMM install, anomalous Quick Assist execution.

## MITRE ATT&CK (analyst-validated)

- **T1566.004** — Phishing: Spearphishing Voice (the Teams call/chat is functionally vishing)
- **T1566** — Phishing
- **T1219** — Remote Access Software (the RMM install)
- **T1078.004** — Valid Accounts: Cloud Accounts (the lookalike tenant)
- **T1583.006** — Acquire Infrastructure: Web Services (free trial M365 tenant)
- **T1656** — Impersonation
- **T1102.002** — Web Service: Bidirectional Communication (Teams as comms channel)
- **T1021.001** — Remote Services: RDP (post-compromise lateral movement)

## Recommended SOC actions (priority-ordered)

1. **Block external Teams collaboration unless explicitly allowed.** Configure Teams external access (`Allow specific external domains only`) and Teams federation lists. This is the most important structural fix; everything below is detection if you can't enforce this.
2. **Hunt all external Teams chats from sender display names containing "helpdesk", "IT", "support", "admin"** — see queries.
3. **Hunt new Quick Assist sessions** initiated by external users.
4. **Hunt RMM tool installs** that don't match your sanctioned list (most enterprises sanction one — anything else is suspicious).
5. **Audit Conditional Access for cross-tenant access settings** — enforce *Block external Teams users from initiating chats* unless on allow-list.
6. **Train end-users**: "your IT department will never reach you via Teams from an outside tenant; if it happens, hang up and call IT yourself."

## Splunk SPL — external Teams chat from helpdesk-named sender

```spl
`o365_management_activity`
  Workload=MicrosoftTeams Operation IN ("MessageSent","MeetingParticipantsAdded","ChatCreated")
  ExternalParticipants=*
| where match(SenderDisplayName,
    "(?i)(help.?desk|it.?support|service.?desk|tech.?support|it.?team|sysadmin|administrator|security.?team)")
| stats count, dc(RecipientUpn) AS targets, earliest(_time) AS firstTime, latest(_time) AS lastTime,
        values(RecipientUpn) AS recipients
        by SenderUpn, SenderDisplayName, SenderTenant
| sort - count
```

## Splunk SPL — RMM tool installed on non-helpdesk endpoint

```spl
| tstats `summariesonly` count min(_time) AS firstTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe",
        "Kaseya.exe","kaseya-agent.exe","ZoomConnector.exe","Mikogo-Service.exe")
      AND NOT Processes.user_category IN ("helpdesk","it","sysadmin")
    by Processes.dest, Processes.user, Processes.process_name, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

## Splunk SPL — Quick Assist invocation

```spl
| tstats `summariesonly` count
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("quickassist.exe","QuickAssist.exe")
      OR Processes.process="*ms-quick-assist:*"
    by Processes.dest, Processes.user, Processes.process_name, Processes.process,
       Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

## Splunk SPL — post-RMM admin protocol movement

```spl
| tstats `summariesonly` count
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("PsExec.exe","PsExec64.exe","wmic.exe","mshta.exe",
                                       "powershell.exe","cmd.exe","bitsadmin.exe","schtasks.exe")
      AND (Processes.process="*\\\\*\\admin$*"
        OR Processes.process="*\\\\*\\c$*"
        OR Processes.process="*Invoke-Command*-ComputerName*"
        OR Processes.process="*New-PSSession*"
        OR Processes.process="*Enter-PSSession*"
        OR Processes.process="*/node:*"
        OR Processes.process="*/s:*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
```

## Defender KQL — external Teams chat with helpdesk-named sender

```kql
CloudAppEvents
| where Timestamp > ago(30d)
| where Application == "Microsoft Teams"
| where ActionType in ("MessageSent","ChatCreated","MeetingParticipantsAdded")
| extend SenderDisplayName = tostring(RawEventData.SenderDisplayName),
         IsExternal = tostring(RawEventData.ExternalParticipants),
         SenderUpn = tostring(RawEventData.SenderUpn)
| where IsExternal != "" and IsExternal != "[]"
| where SenderDisplayName matches regex
    @"(?i)(help.?desk|it.?support|service.?desk|tech.?support|it.?team|sysadmin|administrator|security.?team)"
| summarize msgs = count(),
            firstSeen = min(Timestamp), lastSeen = max(Timestamp),
            recipients = make_set(AccountUpn)
            by SenderDisplayName, SenderUpn
| order by msgs desc
```

## Defender KQL — Quick Assist session initiation

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("quickassist.exe","QuickAssist.exe")
   or ProcessCommandLine has "ms-quick-assist:"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

## Defender KQL — RMM install on non-IT user host

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("anydesk.exe","teamviewer.exe","teamviewer_service.exe",
                       "screenconnect.clientservice.exe","connectwisecontrol.clientservice.exe",
                       "atera_agent.exe","splashtopstreamer.exe","rustdesk.exe","ninjaone.exe",
                       "kaseya.exe","kaseya-agent.exe","zoomconnector.exe","mikogo-service.exe")
| join kind=leftouter (DeviceInfo
    | where DeviceCategory !has_any ("helpdesk","it","sysadmin")
    | project DeviceName) on DeviceName
| project Timestamp, DeviceName, DeviceCategory, AccountName, FileName,
          ProcessCommandLine, InitiatingProcessCommandLine
| order by Timestamp desc
```

## Defender KQL — RMM-then-PsExec chain (90 minutes)

```kql
let rmmStarts = DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where FileName in~ ("anydesk.exe","teamviewer.exe","screenconnect.clientservice.exe",
                           "quickassist.exe","atera_agent.exe","splashtopstreamer.exe","rustdesk.exe")
    | project DeviceName, AccountName, RmmTime = Timestamp, RmmName = FileName;
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("psexec.exe","psexec64.exe","wmic.exe","powershell.exe","cmd.exe")
| where ProcessCommandLine has_any ("\\\\","admin$","c$","Invoke-Command","Enter-PSSession","/node:","/s:")
| join kind=inner rmmStarts on DeviceName
| where Timestamp between (RmmTime .. RmmTime + 90m)
| project DeviceName, AccountName, RmmName, RmmTime, Timestamp,
          FileName, ProcessCommandLine
| order by Timestamp desc
```

## Why this matters for your SOC

This intrusion class is **the Microsoft-365-era social-engineering update to phishing emails**. The defender stack — email gateway, anti-phishing, AV — is calibrated to the wrong channel. Teams external-collab + Quick Assist + Microsoft-supplied RMM is **all native, all signed, all expected** from a tooling perspective. The only fix points are:
1. **Block external Teams chat** (org-policy; the highest-leverage control)
2. **Detect cross-tenant helpdesk-named senders** (the queries above)
3. **Train users to refuse Teams-initiated IT support**

If your CA policy still allows arbitrary external Teams collab, that's a one-week project, and it eliminates this entire intrusion class for your tenant.
