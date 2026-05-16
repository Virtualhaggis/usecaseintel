# [CRIT] [GHSA / CRITICAL] GHSA-pvmv-cwg8-v6c8: Zebra v4.4.0 still accepts V5 SIGHASH_SINGLE without a corresponding output

**Source:** GitHub Security Advisories
**Published:** 2026-05-08
**Article:** https://github.com/advisories/GHSA-pvmv-cwg8-v6c8

## Threat Profile

Zebra v4.4.0 still accepts V5 SIGHASH_SINGLE without a corresponding output

# Consensus Divergence in V5 Transparent SIGHASH_SINGLE With No Corresponding Output

## Summary

Zebra failed to enforce a ZIP-244 consensus rule for V5 transparent transactions: when an input is signed with `SIGHASH_SINGLE` and there is no transparent output at the same index as that input, validation must fail. Zebra instead asked the underlying sighash library to compute a digest, and that library produced a digest …

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1133** — External Remote Services

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Vulnerable Zebra (zebrad) v4.4.0 node running on managed endpoint — GHSA-pvmv-cwg8-v6c8

`UC_130_0` · phase: **recon** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.process_path) as path values(Processes.user) as user from datamodel=Endpoint.Processes where (Processes.process_name="zebrad" OR Processes.process_name="zebrad.exe") by Processes.dest Processes.parent_process_name | `drop_dm_object_name(Processes)` | rex field=cmdline "(?i)(?<zebra_version_arg>--version|-V)\b" | eval needs_patch_check=if(isnotnull(zebra_version_arg),"verify_output_for_4.4.0","unknown_version_runtime") | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
// Hunt managed hosts running Zcash Foundation's zebrad node — flag for version verification vs 4.4.1+ fix
let ZebraProcs = DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where FileName =~ "zebrad" or FileName =~ "zebrad.exe"
    | summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Executions=count(),
                SampleCmd=any(ProcessCommandLine), SampleParent=any(InitiatingProcessFileName),
                SamplePath=any(FolderPath), SampleUser=any(AccountName)
                by DeviceId, DeviceName;
let ZebraInv = DeviceTvmSoftwareInventory
    | where SoftwareName has "zebra" or SoftwareVendor has "zcash"
    | summarize InventoryVersion=any(SoftwareVersion), InventoryVendor=any(SoftwareVendor) by DeviceId;
ZebraProcs
| join kind=leftouter ZebraInv on DeviceId
| extend VulnerableVersionMatch = iff(InventoryVersion startswith "4.4.0", "VULNERABLE_4.4.0", iff(isempty(InventoryVersion), "version_unknown_verify_manually", "check_against_4.4.1"))
| project FirstSeen, LastSeen, DeviceName, SampleUser, SamplePath, SampleCmd, SampleParent, Executions, InventoryVersion, VulnerableVersionMatch
| order by FirstSeen asc
```


## Why this matters

Severity classified as **CRIT** based on: 1 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
