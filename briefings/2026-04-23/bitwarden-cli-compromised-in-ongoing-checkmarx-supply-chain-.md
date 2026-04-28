<!-- curated:true -->
# [MED] Bitwarden CLI Compromised in Ongoing Checkmarx Supply Chain Campaign

**Source:** The Hacker News
**Published:** 2026-04-23
**Article:** https://thehackernews.com/2026/04/bitwarden-cli-compromised-in-ongoing.html
**Curated:** Analyst-reviewed 2026-04-28

## Threat profile

The npm-distributed Bitwarden CLI was **trojanised** as part of a wider Checkmarx-tracked supply-chain campaign. Bitwarden CLI is what users and CI/CD systems run to fetch secrets from a Bitwarden vault — i.e., it has **direct access to every credential in the vault**. A trojanised version that exfiltrates secrets is **catastrophic** for any team using it.

This isn't a CVE — it's a **package compromise**. The malicious version was distributed through the official npm registry. Detection is therefore not "patch the vuln," it's "find every host that pulled the bad version."

## Indicators of Compromise

- _Specific malicious version + hash should be in the article body / Checkmarx report; pull from there once the post-incident IOC list lands._
- Suspect any host that ran `npm install` for `@bitwarden/cli` (or similar) during the affected window.

## MITRE ATT&CK (analyst-validated)

- **T1195.002** — Compromise Software Supply Chain
- **T1552.001** — Credentials In Files (the Bitwarden vault is the high-value target)
- **T1555** — Credentials from Password Stores
- **T1041** — Exfiltration Over C2 Channel (where the stolen secrets go)

## Recommended SOC actions (priority-ordered)

1. **Inventory every host that has Bitwarden CLI installed.** Look for `bw` binary or `@bitwarden/cli` in npm package lists. Include developer laptops, CI runners, build agents.
2. **Rotate every secret accessed by Bitwarden CLI** during the affected window. If you can't determine the exact window, rotate everything that's been touched in the last 30 days.
3. **Block the affected versions** in your npm registry / SBOM tooling.
4. **Hunt for outbound traffic** from any host running `bw` to anywhere not on your allowlist.

## Splunk SPL — Bitwarden CLI process activity

```spl
| tstats `summariesonly` count min(_time) AS firstTime max(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("bw","bw.exe","node.exe","node")
           AND (Processes.process="*bitwarden*"
                OR Processes.process="*@bitwarden/cli*"))
    by Processes.dest, Processes.user, Processes.process_name, Processes.process,
       Processes.parent_process_name
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
```

## Splunk SPL — outbound from build / CI hosts

```spl
| tstats `summariesonly` count earliest(_time) AS first_seen latest(_time) AS last_seen
    from datamodel=Network_Traffic.All_Traffic
    where All_Traffic.src_category IN ("ci","build","developer","jenkins","gitlab-runner")
      AND All_Traffic.action="allowed"
      AND All_Traffic.dest_category!="internal"
    by All_Traffic.src, All_Traffic.dest, All_Traffic.dest_port
| `drop_dm_object_name(All_Traffic)`
| stats sum(count) AS sessions, dc(dest) AS unique_dests, max(last_seen) AS last_seen by src
| where unique_dests > 5
| sort - sessions
```

## Defender KQL — Bitwarden CLI process executions

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("bw.exe","bw","node.exe","node")
| where ProcessCommandLine has_any ("bitwarden","@bitwarden/cli")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

## Defender KQL — outbound network from build hosts

```kql
let buildHosts = dynamic(["jenkins-01","gitlab-runner-01","ci-runner-02"]);  // adapt
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where DeviceName in (buildHosts)
| where RemoteIPType == "Public"
| where ActionType == "ConnectionSuccess"
| where InitiatingProcessFileName in~ ("bw.exe","node.exe","node")
| project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

## Why this matters for your SOC

A compromised secret manager CLI is a **credential firehose** — every `bw get password ...` call routes a plaintext secret through the trojaned binary. The exfiltration window may have started days before the bad package was discovered. **The remediation isn't "remove the bad version" — it's "rotate every secret the affected hosts touched."** That's a project, not a patch. Engage your secret-rotation playbook today; treat the npm package removal as the easy part.
