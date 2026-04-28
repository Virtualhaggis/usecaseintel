<!-- curated:true -->
# [MED] Self-Propagating Supply Chain Worm Hijacks npm Packages to Steal Developer Tokens

**Source:** The Hacker News
**Published:** 2026-04-22
**Article:** https://thehackernews.com/2026/04/self-propagating-supply-chain-worm.html
**Curated:** Analyst-reviewed 2026-04-28

## Threat profile

A worm-style malicious npm package self-replicates by stealing the **npm publisher's auth token** from `~/.npmrc` (or env), then **republishing itself into other packages owned by the compromised account**. Each newly-infected package becomes a new launch pad. This is a worm pattern, not a one-off package compromise.

The blast radius is shaped by the social graph: a maintainer with 50 packages becomes 50 vectors in one infection. Downstream consumers of any of those packages then run the postinstall script and contribute their tokens.

## Indicators of Compromise

- _Specific package names + hashes are in the article body / GitHub Advisory / Socket.dev report._
- Suspect any developer or CI host where `npm install` ran in the affected window AND `~/.npmrc` (or `NPM_TOKEN`) was present.

## MITRE ATT&CK (analyst-validated)

- **T1195.002** — Compromise Software Supply Chain
- **T1552.001** — Credentials In Files (`~/.npmrc`)
- **T1552.005** — Credentials in CI/CD Variables (`NPM_TOKEN`)
- **T1059.007** — JavaScript (postinstall scripts)
- **T1041** — Exfiltration Over C2 Channel

## Recommended SOC actions (priority-ordered)

1. **Audit `npm install` activity in CI runners and developer machines** for the affected window.
2. **Rotate every npm publisher token** for any maintainer who installed unverified packages recently.
3. **Pull the affected package list** from Socket.dev / Snyk / GitHub Advisories and add to your blocklist.
4. **Hunt for outbound connections from `node` / `npm` processes** during package install events — exfiltration usually happens at install time.
5. **Audit your published packages** for unauthorised version bumps in the affected window.

## Splunk SPL — npm install with outbound network

```spl
| tstats `summariesonly` count earliest(_time) AS first_seen latest(_time) AS last_seen
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("npm","npm.cmd","node","node.exe","yarn","pnpm")
      AND (Processes.process="*install*" OR Processes.process="*postinstall*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process,
       Processes.parent_process_name
| `drop_dm_object_name(Processes)`
| `security_content_ctime(first_seen)`
```

## Splunk SPL — `.npmrc` access by non-npm processes

```spl
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.file_name=".npmrc"
      AND NOT Filesystem.process_name IN ("npm","npm.cmd","node","node.exe","yarn","pnpm")
    by Filesystem.dest, Filesystem.process_name, Filesystem.file_path, Filesystem.user
| `drop_dm_object_name(Filesystem)`
```

## Defender KQL — npm install + suspicious outbound

```kql
let recentInstalls = DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where FileName in~ ("npm.cmd","npm","node.exe","node","yarn","pnpm")
    | where ProcessCommandLine has_any ("install","postinstall")
    | project DeviceName, InstallTime = Timestamp, InstallCmd = ProcessCommandLine;
DeviceNetworkEvents
| where Timestamp > ago(7d) and RemoteIPType == "Public"
| join kind=inner recentInstalls on DeviceName
| where Timestamp between (InstallTime .. InstallTime + 5m)
| where InitiatingProcessFileName in~ ("node.exe","node","npm.cmd","npm")
| project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl,
          InitiatingProcessFileName, InstallCmd
| order by Timestamp desc
```

## Defender KQL — `.npmrc` accessed by non-developer process

```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName == ".npmrc"
| where InitiatingProcessFileName !in~ ("npm.cmd","npm","node.exe","node","yarn.cmd","yarn","pnpm")
| project Timestamp, DeviceName, AccountName, FolderPath,
          InitiatingProcessFileName, InitiatingProcessCommandLine, ActionType
| order by Timestamp desc
```

## Why this matters for your SOC

A self-propagating supply-chain worm scales **exponentially** off compromised maintainer accounts — yesterday's small story can be tomorrow's "every CI in the company is exfiltrating tokens." The right defensive posture isn't reactive (block specific packages), it's structural:

- Use scoped `NPM_TOKEN` with publish-only privileges on dedicated build accounts
- Run `npm install --ignore-scripts` in CI where feasible
- Audit `.npmrc` reads on developer endpoints
- Treat `~/.npmrc` like a private SSH key
