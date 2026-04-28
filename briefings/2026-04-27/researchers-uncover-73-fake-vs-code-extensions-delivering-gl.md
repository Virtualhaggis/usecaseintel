<!-- curated:true -->
# [HIGH] Researchers Uncover 73 Fake VS Code Extensions Delivering GlassWorm v2 Malware

**Source:** The Hacker News
**Published:** 2026-04-27
**Article:** https://thehackernews.com/2026/04/researchers-uncover-73-fake-vs-code.html
**Curated:** Analyst-reviewed 2026-04-28

## Threat profile

THN's reporting on the same **GlassWorm v2** campaign covered in the paired BleepingComputer briefing of 2026-04-27 — **73 cloned/fake VS Code extensions** in **OpenVSX**, with **6 confirmed malicious** and the remaining 67 acting as **"sleepers"** that turn malicious on a future update.

This is a **defender-confirmation** report — Koi Security identified the cluster, multiple research teams (THN + BleepingComputer + likely Snyk / Aikido) are validating independently. For a SOC, treat the two articles as the same advisory:

- **One incident** — GlassWorm v2 campaign on OpenVSX.
- **73 extensions** — cloned versions of legitimate ones (typosquats with similar names + author display).
- **6 confirmed live malicious**, **67 dormant** — meaning the affected population is uncertain because dormant extensions can become live at any time.

We've upgraded severity to **HIGH** for the same reasons as the paired BleepingComputer briefing — Cursor/VSCodium adoption, sleeper-extension pattern, unsandboxed Node.js access on dev endpoints.

## Indicators of Compromise

- _The 73 extension publisher / name list is in the Koi Security blog (and mirrored in THN + BleepingComputer reporting). Pull the canonical list from Koi Security or the linked researcher write-up._
- Cross-reference with paired briefing: `briefings/2026-04-27/glassworm-malware-attacks-return-via-73-openvsx-sleeper-exte.md` for full detection content.

## MITRE ATT&CK (analyst-validated)

- **T1195.001** — Compromise Software Dependencies and Development Tools
- **T1059.007** — JavaScript / Node.js (extension execution context)
- **T1552.001** — Credentials In Files (`.env`, `.aws`, `.npmrc`)
- **T1567** — Exfiltration Over Web Service
- **T1656** — Impersonation (the cloned-name typosquatting tactic)

## Recommended SOC actions (priority-ordered)

1. **Use the detection package from the paired briefing** (`briefings/2026-04-27/glassworm-malware-attacks-return-via-73-openvsx-sleeper-exte.md`) — same campaign, same queries, same response.
2. **Pull the 73-extension list** from the Koi Security write-up. Cross-reference against installed extensions on dev workstations.
3. **Treat dormant clones as currently malicious.** The "sleeper" pattern means *any* of the 67 could turn live in a routine update; the operational stance is "uninstall now, re-evaluate after publisher attestation."
4. **Brief the dev community.** The cloned-extension trick succeeds because devs install based on look + popularity. Train them: install only from publisher-verified extensions, especially in Cursor / VSCodium where OpenVSX is the default registry.
5. **Enterprise extension allowlisting.** If you have Cursor / VSCodium in regulated roles (security, infra, SRE, finance-eng), enforce an allowlist via MDM / endpoint config.

## Splunk SPL — VS Code / Cursor extension install activity

Use the queries from the paired briefing — same campaign, queries are the same. Direct link: `briefings/2026-04-27/glassworm-malware-attacks-return-via-73-openvsx-sleeper-exte.md`.

```spl
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where (Filesystem.file_path="*\\.vscode\\extensions\\*"
        OR Filesystem.file_path="*\\.cursor\\extensions\\*"
        OR Filesystem.file_path="*\\.vscodium\\extensions\\*"
        OR Filesystem.file_path="*/.vscode/extensions/*"
        OR Filesystem.file_path="*/.cursor/extensions/*")
      AND Filesystem.action="created"
      AND Filesystem.file_name="package.json"
    by Filesystem.dest, Filesystem.user, Filesystem.file_path, _time
| `drop_dm_object_name(Filesystem)`
| rex field=file_path "extensions[\\\\/](?<extension_id>[^\\\\/]+)"
| stats values(extension_id) AS installed_extensions, dc(extension_id) AS count by dest, user
```

## Defender KQL — VS Code / Cursor extension install activity

```kql
DeviceFileEvents
| where Timestamp > ago(60d)
| where ActionType == "FileCreated"
| where FolderPath has_any ("\\.vscode\\extensions\\","\\.cursor\\extensions\\",
                              "\\.vscodium\\extensions\\","/.vscode/extensions/",
                              "/.cursor/extensions/")
| where FileName == "package.json"
| extend extensionId = extract(@"(?:\\|/)extensions(?:\\|/)([^\\/]+)", 1, FolderPath)
| summarize installs = count(),
            firstSeen = min(Timestamp), lastSeen = max(Timestamp),
            extensions = make_set(extensionId, 200)
            by DeviceName, AccountName
| order by installs desc
```

## Why this matters for your SOC

The two briefings (THN + BleepingComputer) are the **same campaign reported by two outlets** — they should be read together, with one set of detections and one response plan. The takeaway from having two independent confirmations is **operational maturity**: the GlassWorm cluster is now well-documented enough that you should expect:
- A canonical IOC bundle from at least one supply-chain security vendor (Snyk, Aikido, Socket.dev, Koi Security).
- Removal of the confirmed-malicious 6 from OpenVSX within days.
- The dormant 67 to remain available longer, requiring **organisational uninstall** rather than relying on registry takedown.

Review your dev-host extension footprint this week, even if no employee has self-reported issue. Devs typically don't notice silent updates.
