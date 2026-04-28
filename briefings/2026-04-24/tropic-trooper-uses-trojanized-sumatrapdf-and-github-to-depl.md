<!-- curated:true -->
# [HIGH] Tropic Trooper Uses Trojanized SumatraPDF and GitHub to Deploy AdaptixC2

**Source:** The Hacker News
**Published:** 2026-04-24
**Article:** https://thehackernews.com/2026/04/tropic-trooper-uses-trojanized.html
**Curated:** Analyst-reviewed 2026-04-28

## Threat profile

**Tropic Trooper** (a.k.a. KeyBoy, Pirate Panda, Earth Centaur) — a long-running China-aligned APT — is running a campaign against Chinese-speaking targets using a **multi-stage chain**:

1. **Trojanised SumatraPDF reader** as the initial-stage dropper (DLL side-load via legitimate signed binary).
2. **GitHub** abused as a hosted-payload distribution / C2-staging channel.
3. **AdaptixC2** Beacon (an open-source C2 framework, like Sliver / Mythic / Havoc) deployed as the post-exploitation agent.
4. **VS Code Tunnels** abused for **remote access** — VS Code's official remote-tunnel feature, which routes through `*.vscode.dev` / Microsoft infrastructure.

Three things make this campaign technically interesting and broadly applicable:

- **VS Code Tunnels as C2/RAT** is the same playbook several ransomware affiliates and APTs are now running — Microsoft signed, allowlisted, encrypted, hard to block.
- **GitHub as payload host** abuses the most-allowlisted SaaS in the developer world.
- **AdaptixC2** is open-source — expect adoption to spread faster than detection.

We've upgraded severity to **HIGH** — the **VS Code Tunnel + GitHub-as-payload combination is generic and detectable**, but the detection is universally absent in mid-tier SOC tooling.

## Indicators of Compromise

- _Specific trojanised SumatraPDF hashes, GitHub repos hosting payloads, and VS Code Tunnel IDs are in the Zscaler ThreatLabz blog when published._
- **Behavioural fingerprints** (more durable than hashes):
  - `SumatraPDF.exe` running from `%TEMP%`, `%APPDATA%`, or `Downloads` rather than `Program Files`.
  - `code.exe tunnel` / `code-tunnel.exe` execution on hosts where it's unexpected.
  - Outbound to `*.tunnels.api.visualstudio.com`, `*.global.rel.tunnels.api.visualstudio.com`, `*.devtunnels.ms`.
  - GitHub raw / blob URL fetches for `.exe` / `.dll` / `.zip` from suspect repos.

## MITRE ATT&CK (analyst-validated)

- **T1574.002** — DLL Side-Loading (the SumatraPDF chain)
- **T1102.001** — Web Service: Dead Drop Resolver (GitHub used to fetch C2 config / payload)
- **T1102.002** — Web Service: Bidirectional Communication (the C2 channel itself)
- **T1219** — Remote Access Software (VS Code Tunnels)
- **T1572** — Protocol Tunneling (VS Code Tunnels function as encrypted tunnel)
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1027** — Obfuscated Files or Information
- **T1059.001** — Command and Scripting Interpreter: PowerShell (frequently used in the side-load chain)

## Recommended SOC actions (priority-ordered)

1. **Block / detect VS Code Tunnels.** If your dev community doesn't use them, block at egress. If they do, alert when established by non-developer endpoints.
2. **Hunt SumatraPDF execution from non-`Program Files` paths** — see queries.
3. **Hunt GitHub raw-content fetches for binaries** by non-developer processes (PowerShell, certutil, bitsadmin downloading `.exe` / `.dll` from `raw.githubusercontent.com`).
4. **Hunt AdaptixC2 indicators.** AdaptixC2 has documented HTTP-header fingerprints and JA3/JA4 hashes — pull from public threat-research blogs.
5. **Audit your developer-tool footprint.** VS Code is on most engineering laptops; tunnels can be initiated by *any* user who has VS Code installed.
6. **Update DLP / proxy rules.** GitHub + VS Code tunnel domains are typical "allow without inspection" zones — review whether that posture still serves your risk tolerance.

## Splunk SPL — VS Code Tunnel execution

```spl
| tstats `summariesonly` count
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("code.exe","code","code-tunnel.exe","code-server.exe")
         AND (Processes.process="*tunnel*"
           OR Processes.process="*serve-web*"))
       OR Processes.process="*devtunnel*"
       OR Processes.process="*vscode-server*"
    by Processes.dest, Processes.user, Processes.process_name, Processes.process,
       Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

## Splunk SPL — outbound to VS Code Tunnel infrastructure

```spl
| tstats `summariesonly` count
    from datamodel=Network_Traffic.All_Traffic
    where (All_Traffic.dest="*tunnels.api.visualstudio.com*"
        OR All_Traffic.dest="*global.rel.tunnels.api.visualstudio.com*"
        OR All_Traffic.dest="*devtunnels.ms*"
        OR All_Traffic.dest="*tunnel.vscode.dev*")
    by All_Traffic.src, All_Traffic.dest, All_Traffic.dest_port,
       All_Traffic.process_name, All_Traffic.user
| `drop_dm_object_name(All_Traffic)`
| sort - count
```

## Splunk SPL — SumatraPDF in non-standard path

```spl
| tstats `summariesonly` count
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("SumatraPDF.exe","SumatraPDF-portable.exe")
      AND (Processes.process_path="*\\AppData\\*"
        OR Processes.process_path="*\\Temp\\*"
        OR Processes.process_path="*\\Users\\Public\\*"
        OR Processes.process_path="*\\Downloads\\*"
        OR Processes.process_path="*\\ProgramData\\*")
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process_path, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

## Splunk SPL — GitHub raw binary download by non-developer process

```spl
| tstats `summariesonly` count
    from datamodel=Web
    where (Web.url="*raw.githubusercontent.com*" OR Web.url="*github.com/*/raw/*"
        OR Web.url="*objects.githubusercontent.com*")
      AND (Web.url="*.exe" OR Web.url="*.dll" OR Web.url="*.zip"
        OR Web.url="*.iso" OR Web.url="*.bin" OR Web.url="*.so")
      AND Web.user_agent IN ("*PowerShell*","*WinHttp*","*BITS*","*curl*","*wget*","*certutil*")
    by Web.src, Web.user, Web.url, Web.user_agent, Web.process_name
| `drop_dm_object_name(Web)`
```

## Defender KQL — VS Code Tunnel execution

```kql
DeviceProcessEvents
| where Timestamp > ago(60d)
| where (FileName in~ ("code.exe","code","code-tunnel.exe","code-server.exe")
         and ProcessCommandLine has_any ("tunnel","serve-web"))
     or ProcessCommandLine has_any ("devtunnel","vscode-server tunnel")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

## Defender KQL — outbound to VS Code tunnel domains

```kql
DeviceNetworkEvents
| where Timestamp > ago(60d)
| where RemoteUrl has_any ("tunnels.api.visualstudio.com",
                            "global.rel.tunnels.api.visualstudio.com",
                            "devtunnels.ms",
                            "tunnel.vscode.dev")
| project Timestamp, DeviceName, AccountName, RemoteUrl, RemoteIP, RemotePort,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

## Defender KQL — SumatraPDF anomalous path

```kql
DeviceProcessEvents
| where Timestamp > ago(60d)
| where FileName in~ ("SumatraPDF.exe","SumatraPDF-portable.exe")
| where FolderPath has_any ("\\AppData\\","\\Temp\\","\\Users\\Public\\",
                             "\\Downloads\\","\\ProgramData\\")
| project Timestamp, DeviceName, AccountName, FolderPath, FileName,
          ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

## Defender KQL — GitHub raw binary download by LOLbin

```kql
DeviceNetworkEvents
| where Timestamp > ago(60d)
| where RemoteUrl has_any ("raw.githubusercontent.com",
                            "objects.githubusercontent.com")
| where RemoteUrl matches regex @"\.(exe|dll|zip|iso|bin|so|7z|msi)$"
| where InitiatingProcessFileName in~ ("powershell.exe","pwsh.exe","cmd.exe","certutil.exe",
                                         "bitsadmin.exe","curl.exe","wget.exe","mshta.exe",
                                         "rundll32.exe","regsvr32.exe")
| project Timestamp, DeviceName, AccountName, RemoteUrl, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

## Why this matters for your SOC

The "**Microsoft-signed-tunnel-as-C2**" pattern (VS Code Tunnels, Cloudflare Tunnels, ngrok, GitHub Codespaces, Tailscale) is the **dominant 2026 RAT-evasion technique**. It works because:
- The traffic terminates on the vendor's allowlisted domain.
- The tunnel client is a signed, expected binary (`code.exe`, `cloudflared.exe`, etc.).
- TLS interception is generally not deployed against these domains.
- The traffic content is end-to-end encrypted.

The detections above are *the* high-value baseline for this class. If you're not already alerting on `code tunnel` execution, build that rule **this week** — it costs nothing, fires on multiple actor sets (Tropic Trooper today, Akira and Black Basta affiliates last quarter), and tunes easily because legitimate tunnel use is rare.
