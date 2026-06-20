# [CRIT] [GHSA / CRITICAL] GHSA-wfqx-gjrf-g28r: Crossplane: Signature verification TOCTOU allows installing unverified package content via mutable tag

**Source:** GitHub Security Advisories
**Published:** 2026-06-19
**Article:** https://github.com/advisories/GHSA-wfqx-gjrf-g28r

## Threat Profile

Crossplane: Signature verification TOCTOU allows installing unverified package content via mutable tag

## Summary

Crossplane allows package signature verification to be configured via the `ImageConfig` mechanism. When enabled, the package manager uses cosign to verify that packages are correctly signed before pulling and installing them.

When a package is installed using a tag reference (e.g., a semantic version), a malicious OCI registry could serve a correctly signed image for verification,…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1562** — Impair Defenses
- **T1562.001** — Disable or Modify Tools
- **T1195.002** — Compromise Software Supply Chain

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Crossplane ImageConfig modified to remove cosign signature verification (GHSA-wfqx-gjrf-g28r)

`UC_8_0` · phase: **weapon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count, min(_time) as first_seen, max(_time) as last_seen, values(Change.object_attrs) as attrs, values(Change.change_type) as change_type from datamodel=Change where Change.object_category="kubernetes_resource" AND Change.object="imageconfigs.pkg.crossplane.io" AND Change.action IN ("updated","modified") by Change.user, Change.object_id, Change.src | `drop_dm_object_name(Change)` | where NOT match(mvjoin(attrs," "), "(?i)cosign|signatures|verification")
```

### Crossplane ImageConfig CRD deletion (signature verification policy removal)

`UC_8_1` · phase: **weapon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count, min(_time) as first_seen, max(_time) as last_seen from datamodel=Change where Change.object_category="kubernetes_resource" AND Change.object="imageconfigs.pkg.crossplane.io" AND Change.action="deleted" by Change.user, Change.object_id, Change.src | `drop_dm_object_name(Change)`
```

### Crossplane Provider/Configuration/Function installed via mutable tag (no digest)

`UC_8_2` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count, min(_time) as first_seen, max(_time) as last_seen, values(Change.object_path) as packages from datamodel=Change where Change.object_category="kubernetes_resource" AND Change.object IN ("providers.pkg.crossplane.io","configurations.pkg.crossplane.io","functions.pkg.crossplane.io") AND Change.action IN ("created","updated") by Change.user, Change.object_id, Change.src | `drop_dm_object_name(Change)` | eval pkg_str=mvjoin(packages,";") | where NOT match(pkg_str, "@sha256:[0-9a-f]{64}")
```

### Vulnerable Crossplane core version deployed in cluster (GHSA-wfqx-gjrf-g28r affected)

`UC_8_3` · phase: **recon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count, min(_time) as first_seen, max(_time) as last_seen, values(Change.object_path) as images from datamodel=Change where Change.object_category="kubernetes_resource" AND Change.object IN ("deployments","pods") AND Change.action IN ("created","updated") by Change.user, Change.object_id | `drop_dm_object_name(Change)` | eval img_str=mvjoin(images,";") | where match(img_str, "crossplane/crossplane:(v?(1\.([0-9]|1[0-9]|2[01])\.[0-9]+(-rc\.[0-9]+)?|2\.[0-2]\.[0-2]|2\.3\.[0-2]|2\.3\.0-rc\.[0-9]+))(\b|$)")
```

**Defender KQL:**
```kql
DeviceTvmSoftwareInventory
| where Timestamp > ago(7d)
| where SoftwareVendor =~ "crossplane" and SoftwareName has "crossplane"
| where SoftwareVersion matches regex @"^(1\.([0-9]|1[0-9]|2[01])\.[0-9]+(-rc\.[0-9]+)?|2\.[0-2]\.[0-2]|2\.3\.[0-2]|2\.3\.0-rc\.[0-9]+)$"
| project Timestamp, DeviceName, SoftwareVendor, SoftwareName, SoftwareVersion, EndOfSupportStatus
```

### Crossplane skipSignatureVerification bypass flag set on ImageConfig/Provider (GHSA-wfqx-gjrf-g28r)

`UC_8_4` · phase: **weapon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count, min(_time) as first_seen, max(_time) as last_seen, values(Change.object_attrs) as attrs from datamodel=Change where Change.object_category="kubernetes_resource" AND Change.object IN ("imageconfigs.pkg.crossplane.io","providers.pkg.crossplane.io","configurations.pkg.crossplane.io","functions.pkg.crossplane.io") AND Change.action IN ("created","updated","modified") by Change.user, Change.object_id, Change.src | `drop_dm_object_name(Change)` | where match(mvjoin(attrs," "), "(?i)skipsignatureverification[\"\s:=]+true")
```


## Why this matters

Severity classified as **CRIT** based on: 5 use case(s) fired, 3 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
