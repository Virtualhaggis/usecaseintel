<!-- curated:true -->
# [HIGH] Malicious KICS Docker Images and VS Code Extensions Hit Checkmarx Supply Chain

**Source:** The Hacker News
**Published:** 2026-04-22
**Article:** https://thehackernews.com/2026/04/malicious-kics-docker-images-and-vs.html
**Curated:** Analyst-reviewed 2026-04-28

## Threat profile

Unknown attackers **overwrote existing tags** in the official **`checkmarx/kics`** Docker Hub repository — including `v2.1.20` and `alpine` — and introduced a rogue `v2.1.21` tag that doesn't match any official release. KICS (Keeping Infrastructure as Code Secure) is Checkmarx's open-source IaC scanner; it's pulled by **CI pipelines**, **dev workstations**, and **build runners** — exactly the privileged environments attackers want.

Tag overwriting on a public registry is the **worst-case** supply chain pattern: pinned image references (`checkmarx/kics:alpine`) silently pull the malicious version on the next CI run. Most teams pin to floating tags (`latest`, `alpine`, major versions) rather than digests, so they're exposed without realising.

We've upgraded severity to **HIGH** because:
- KICS is a security-tooling image — runs in privileged build context with secret access (cloud creds, registry tokens, signing keys).
- Tag overwrite means existing, validated CI configs become attack vectors with **no code change required**.
- This pairs with the Bitwarden/Checkmarx supply-chain campaign one day later — same actor or coordinated wave.

## Indicators of Compromise

- `checkmarx/kics:v2.1.20` (overwritten — historical tag now points to malicious image)
- `checkmarx/kics:alpine` (overwritten)
- `checkmarx/kics:v2.1.21` (rogue, non-official tag)
- _Specific image digests of the malicious revisions should be in the Socket.dev advisory — pull them from there as ground truth, not from this briefing._
- VS Code extensions linked to the same campaign — extension IDs in the article body / Checkmarx advisory.

## MITRE ATT&CK (analyst-validated)

- **T1195.002** — Compromise Software Supply Chain
- **T1195.001** — Compromise Software Dependencies and Development Tools (the VS Code extensions)
- **T1610** — Deploy Container (the malicious KICS image runs in CI)
- **T1552.001** — Credentials In Files (CI runners typically expose `.docker/config.json`, `.npmrc`, `~/.aws/credentials`)
- **T1552.005** — Credentials in CI/CD Variables
- **T1041** — Exfiltration Over C2 Channel

## Recommended SOC actions (priority-ordered)

1. **Inventory every CI pipeline that pulls `checkmarx/kics`.** Search GitLab/GitHub/Jenkins config repos for the string `checkmarx/kics`. This is the single most important action — until you know which pipelines used it, you don't know your exposure.
2. **Pin to digest, not tag.** Move from `checkmarx/kics:alpine` to `checkmarx/kics@sha256:...` for known-good revisions. This eliminates the tag-overwrite class.
3. **Rotate every credential ever touched by an affected CI runner** — registry tokens, cloud keys, signing keys, GitHub PATs, npm tokens.
4. **Pull image manifest histories** from your registry (Docker Hub or local mirror) and audit when `kics` tags last shifted digests. Anything between mid-April and the disclosure window is suspect.
5. **Hunt VS Code extension marketplace logs** if you have an SBOM / dev-machine inventory tool — the article says extensions were also part of the campaign.
6. **Audit container egress from build hosts** — KICS doesn't need outbound network beyond pulling rule packs; anything beyond that is suspicious.

## Splunk SPL — CI runners pulling the affected image

```spl
| tstats `summariesonly` count
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("docker","docker.exe","podman","containerd","ctr",
                                       "kubectl","helm","skopeo")
      AND (Processes.process="*checkmarx/kics*"
        OR Processes.process="*kics:v2.1.20*"
        OR Processes.process="*kics:v2.1.21*"
        OR Processes.process="*kics:alpine*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process,
       Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

## Splunk SPL — outbound from build hosts during scan windows

```spl
| tstats `summariesonly` count
    from datamodel=Network_Traffic.All_Traffic
    where All_Traffic.src_category IN ("ci","build","jenkins","gitlab-runner","github-runner")
      AND All_Traffic.action="allowed"
      AND All_Traffic.dest_category!="internal"
      AND All_Traffic.dest_category!="container-registry"
    by All_Traffic.src, All_Traffic.dest, All_Traffic.dest_port
| `drop_dm_object_name(All_Traffic)`
| stats sum(count) AS sessions, dc(dest) AS unique_dests by src
| where unique_dests > 5
| sort - sessions
```

## Splunk SPL — credential file reads from inside container processes

```spl
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.process_name IN ("kics","kics.exe","docker","containerd-shim","runc")
      AND Filesystem.action="read"
      AND (Filesystem.file_name=".npmrc"
        OR Filesystem.file_name="config.json"
        OR Filesystem.file_path="*\\.aws\\*"
        OR Filesystem.file_path="*\\.docker\\*"
        OR Filesystem.file_path="*\\.kube\\*"
        OR Filesystem.file_path="*/root/.config/*")
    by Filesystem.dest, Filesystem.process_name, Filesystem.file_path
| `drop_dm_object_name(Filesystem)`
```

## Defender KQL — KICS image pulls

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("docker.exe","docker","podman","kubectl.exe","helm.exe","skopeo.exe")
| where ProcessCommandLine has_any ("checkmarx/kics","kics:v2.1.20","kics:v2.1.21","kics:alpine")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

## Defender KQL — VS Code extension installs (dev machines)

```kql
DeviceFileEvents
| where Timestamp > ago(60d)
| where FolderPath has "\\.vscode\\extensions\\"
| where ActionType in ("FileCreated","FileModified")
| where FileName in~ ("package.json","extension.js","extension.ts")
| summarize installs = count(),
            extensions = make_set(extract("\\\\extensions\\\\([^\\\\]+)", 1, FolderPath))
            by DeviceName
| where installs > 3
| order by installs desc
```

## Defender KQL — outbound from build runners

```kql
let buildHosts = DeviceInfo
    | where DeviceCategory has_any ("ci","build","runner")
       or DeviceName has_any ("jenkins","gitlab-runner","github-runner","build-")
    | project DeviceName;
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where DeviceName in (buildHosts)
| where RemoteIPType == "Public"
| where ActionType == "ConnectionSuccess"
| where RemoteUrl !has_any ("docker.io","ghcr.io","quay.io","gcr.io","mcr.microsoft.com",
                              "registry.gitlab.com","npmjs.org","github.com")
| project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

## Why this matters for your SOC

Tag overwrite on an established public image is **worse than a typosquat** — typosquats can be caught by careful naming review; tag overwrites silently weaponise infrastructure that has been working for months. The KICS image is *security tooling*, which makes the irony pointed: the thing your CI uses to validate IaC is now the malicious payload. The structural fix is **digest pinning** across the entire image supply chain, not tag pinning. If your CI configs use any floating tag (`latest`, major-version, channel names) for any third-party image, you have the same exposure pattern — KICS is just the version that got compromised this week. Treat this as the forcing function to convert your image references to digests.
