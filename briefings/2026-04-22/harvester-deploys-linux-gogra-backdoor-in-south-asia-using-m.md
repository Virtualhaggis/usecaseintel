<!-- curated:true -->
# [HIGH] Harvester Deploys Linux GoGra Backdoor in South Asia Using Microsoft Graph API

**Source:** The Hacker News
**Published:** 2026-04-22
**Article:** https://thehackernews.com/2026/04/harvester-deploys-linux-gogra-backdoor.html
**Curated:** Analyst-reviewed 2026-04-28

## Threat profile

**Harvester** APT (Symantec/Carbon Black tracking) has shipped a **Linux variant** of its **GoGra** backdoor. Critically, GoGra uses **legitimate Microsoft Graph API endpoints and Outlook mailboxes as a covert C2 channel** — i.e., the malware reads attacker commands from emails in a Graph-API-accessible mailbox and writes results back the same way.

This is the **most operationally consequential** detection-evasion pattern of the last 18 months:
- C2 traffic flows to `graph.microsoft.com` and `outlook.office365.com` — endpoints **every enterprise allowlists by default**.
- Traditional perimeter blocking (proxies, IDS, DNS sinkholes) is useless: the destination is your own tenant or any Microsoft tenant.
- TLS interception doesn't help — Graph API traffic is normal-looking JSON over HTTPS.
- The malware appears as a regular Microsoft 365 client.

The Linux variant is significant because it lands GoGra on **build servers, web servers, container hosts, and developer workstations** — places where Microsoft 365 client traffic is *unexpected* and where AV/EDR coverage is typically thinner than on Windows endpoints.

We've upgraded severity to **HIGH** because the **C2-via-Graph-API class is a generalised threat**, not just Harvester. Multiple actors (APT29 / NOBELIUM, Mustang Panda, FIN groups) use the same channel.

## Indicators of Compromise

- _Specific GoGra Linux hashes + the mailbox addresses used as drop boxes should appear in the Symantec / Carbon Black Threat Hunter Team write-up._
- Hunt for **Linux processes making outbound HTTPS to `graph.microsoft.com` / `login.microsoftonline.com`** — anomalous on most non-developer Linux hosts.

## MITRE ATT&CK (analyst-validated)

- **T1071.001** — Application Layer Protocol: Web Protocols (HTTPS to Graph)
- **T1102.002** — Web Service: Bidirectional Communication (the mailbox-as-C2 pattern)
- **T1567** — Exfiltration Over Web Service
- **T1573.002** — Encrypted Channel: Asymmetric Cryptography (TLS to Microsoft endpoints)
- **T1078.004** — Valid Accounts: Cloud Accounts (the mailbox the attacker controls)
- **T1583.006** — Acquire Infrastructure: Web Services (free Microsoft tenant for C2)

## Recommended SOC actions (priority-ordered)

1. **Inventory Linux hosts that *should* talk to `graph.microsoft.com`.** This is a small list — usually just identity-sync hosts and a couple of dev workstations. **Everything else doing it is suspicious by default.**
2. **Hunt the Graph C2 pattern.** Build queries below — Linux + outbound to Microsoft Graph + non-Outlook process is the high-fidelity signal.
3. **Audit your Conditional Access policies.** If a non-corporate-tenant token can access Graph from your network without CA challenge, you have the structural exposure.
4. **Look for OAuth app consents** in your tenant from the past 6 months — Graph C2 often relies on a legitimate-looking OAuth app the attacker registered.
5. **Block at egress (selectively).** For Linux subnets that have no business reason to reach Microsoft 365, block the Microsoft 365 IP ranges.

## Splunk SPL — Linux process with HTTPS to graph.microsoft.com

```spl
| tstats `summariesonly` count
    from datamodel=Network_Traffic.All_Traffic
    where All_Traffic.action="allowed"
      AND (All_Traffic.dest="*graph.microsoft.com*"
        OR All_Traffic.dest="*login.microsoftonline.com*"
        OR All_Traffic.dest="*outlook.office365.com*")
    by All_Traffic.src, All_Traffic.dest, All_Traffic.dest_port,
       All_Traffic.app, All_Traffic.process_name
| `drop_dm_object_name(All_Traffic)`
| join type=inner src
    [| tstats `summariesonly` count from datamodel=Endpoint.Processes
         where Processes.os="Linux"
         by Processes.dest
     | `drop_dm_object_name(Processes)`
     | rename dest as src
     | fields src]
```

## Splunk SPL — Graph API access from non-Outlook process on any host

```spl
| tstats `summariesonly` count
    from datamodel=Network_Traffic.All_Traffic
    where All_Traffic.action="allowed"
      AND All_Traffic.dest="*graph.microsoft.com*"
      AND All_Traffic.process_name!="OUTLOOK.EXE"
      AND All_Traffic.process_name!="ms-teams.exe"
      AND All_Traffic.process_name!="onedrive.exe"
      AND All_Traffic.process_name!="msedge.exe"
      AND All_Traffic.process_name!="chrome.exe"
      AND All_Traffic.process_name!="firefox.exe"
    by All_Traffic.src, All_Traffic.process_name, All_Traffic.dest, All_Traffic.user
| `drop_dm_object_name(All_Traffic)`
| sort - count
```

## Splunk SPL — DNS to graph endpoints from Linux DNS resolver

```spl
| tstats `summariesonly` count
    from datamodel=Network_Resolution.DNS
    where DNS.query IN ("graph.microsoft.com","login.microsoftonline.com","outlook.office365.com")
    by DNS.src, DNS.query, DNS.answer
| `drop_dm_object_name(DNS)`
| stats sum(count) AS queries by src, query
| sort - queries
```

## Defender KQL — Linux/server outbound to Graph

```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any ("graph.microsoft.com","login.microsoftonline.com",
                            "outlook.office365.com","outlook.office.com")
| join kind=inner (DeviceInfo
    | where OSPlatform has_any ("Linux","Ubuntu","RHEL","CentOS","Debian","Server")
    | project DeviceName, OSPlatform) on DeviceName
| where InitiatingProcessFileName !in~ ("OUTLOOK.EXE","ms-teams.exe","onedrive.exe",
                                          "msedge.exe","chrome.exe","firefox.exe","Teams.exe")
| project Timestamp, DeviceName, OSPlatform, RemoteUrl,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

## Defender KQL — OAuth app consents (Graph C2 enabler)

```kql
CloudAppEvents
| where Timestamp > ago(180d)
| where ActionType in ("Consent to application.","Add OAuth2PermissionGrant.",
                        "Add delegated permission grant.")
| extend AppId = tostring(RawEventData.ModifiedProperties[0].NewValue)
| extend Initiator = tostring(RawEventData.ActorIpAddress)
| project Timestamp, AccountObjectId, AccountDisplayName, AppId, Initiator,
          ActionType, RawEventData
| order by Timestamp desc
```

## Defender KQL — anomalous Graph API tokens from new IPs

```kql
AADSignInEventsBeta
| where Timestamp > ago(30d)
| where AppDisplayName has_any ("Microsoft Graph","Office 365 Exchange Online",
                                  "Microsoft Office Authentication Broker")
| where ResourceDisplayName has "Graph"
| summarize tokenCount = count(),
            uniqueIPs = dcount(IPAddress),
            firstSeen = min(Timestamp), lastSeen = max(Timestamp)
            by AccountObjectId, AccountUpn, IPAddress, Country
| where uniqueIPs == 1 and tokenCount > 50
| order by tokenCount desc
```

## Why this matters for your SOC

Graph-API-as-C2 is **the perimeter-bypass technique that's actually working in 2025-2026**. The reason is structural: Microsoft Graph traffic is a permanently allowlisted destination on every enterprise network, the JSON traffic looks like every other Office 365 client, and the auth tokens come from valid OAuth flows. **The defence is not at the network layer — it's at identity and process-context layers**:

- *Which host* is talking to Graph? (Linux servers shouldn't be.)
- *Which process* is making the call? (Not `python` / `node` / `bash` / `curl` on most hosts.)
- *Which OAuth app* is the token bound to? (Look for unfamiliar app registrations.)

If your SOC isn't already monitoring Graph-API access patterns from a host-process perspective, this article is the forcing function. Harvester is one actor — the technique is the threat.
