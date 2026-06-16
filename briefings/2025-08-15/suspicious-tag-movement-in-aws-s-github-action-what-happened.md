# [HIGH] Suspicious Tag Movement in AWS’s GitHub Action: What Happened and Why It Matters

**Source:** StepSecurity
**Published:** 2025-08-15
**Article:** https://www.stepsecurity.io/blog/suspicious-tag-movement-in-aws-github-action

## Threat Profile

Back to Blog Threat Intel Suspicious Tag Movement in AWS’s GitHub Action: What Happened and Why It Matters How an AWS release rollback triggered the same red flags as a supply chain attack — and why treating every tag movement as suspicious is key to protecting your CI/CD pipelines Shubham Malik View LinkedIn August 14, 2025
Share on X Share on X Share on LinkedIn Share on Facebook Follow our RSS feed 
Table of Contents Loading nav... 
On 4th August 2025, an unusual event occurred in AWS’s popul…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2025-30066`
- **CVE:** `CVE-2025-30154`
- **SHA1:** `0e58ed8671d6b60d0890c21b07f8835ace038e67`
- **SHA1:** `f0d342d24037bb11d26b9bd8496e0808ba32e9ec`

## MITRE ATT&CK Techniques

- **T1195.002** — Compromise Software Supply Chain
- **T1190** — Exploit Public-Facing Application
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1554** — Compromise Host Software Binary
- **T1199** — Trusted Relationship
- **T1078** — Valid Accounts
- **T1552.004** — Unsecured Credentials: Private Keys / CI Secrets

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Tag deletion/repointing on critical GitHub Action repositories (configure-aws-credentials v4.3.0 pattern)

`UC_821_3` · phase: **weapon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
`summariesonly` | tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Change.user) as actor values(Change.src) as src_ip values(Change.object) as ref from datamodel=Change where Change.vendor_product="GitHub" (Change.action="deleted" OR Change.action="delete") (Change.object_category="tag" OR Change.object="refs/tags/*") Change.object_path IN ("aws-actions/configure-aws-credentials","tj-actions/*","reviewdog/*","actions/*") by Change.object_path Change.object Change.action | `drop_dm_object_name(Change)` | rex field=object "refs/tags/(?<tag_name>v?\d+(\.\d+){0,2})$" | where isnotnull(tag_name) | eval _is_buggy_aws_v430=if(object_path="aws-actions/configure-aws-credentials" AND tag_name="v4.3.0", 1, 0)
```

### Internal workflows pulling aws-actions/configure-aws-credentials@v4.3.0 during the buggy-release window

`UC_821_4` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
`summariesonly` | tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Change.user) as triggered_by values(Change.object_path) as workflow_repo from datamodel=Change where Change.vendor_product="GitHub" Change.action="workflow_run" earliest="08/04/2025:17:49:00" latest="08/04/2025:20:47:00" by Change.object_path Change.object | `drop_dm_object_name(Change)` | join type=left object_path [ search index=github_workflows ("aws-actions/configure-aws-credentials@v4.3.0" OR "aws-actions/configure-aws-credentials@59b44184") | stats values(uses) as pinned_uses by repo | rename repo as object_path ] | where isnotnull(pinned_uses)
```

### Trusted vendor binary / installer launching unusual children

`UC_SUPPLY_CHAIN` · phase: **exploit** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.parent_process_name IN ("setup.exe","installer.exe","update.exe")
      AND Processes.process_name IN ("powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","wmic.exe","bitsadmin.exe")
    by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where InitiatingProcessFileName in~ ("setup.exe","installer.exe","update.exe")
| where FileName in~ ("powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","wmic.exe","bitsadmin.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2025-30066`, `CVE-2025-30154`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `0e58ed8671d6b60d0890c21b07f8835ace038e67`, `f0d342d24037bb11d26b9bd8496e0808ba32e9ec`


## Why this matters

Severity classified as **HIGH** based on: CVE present, IOCs present, 5 use case(s) fired, 8 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
