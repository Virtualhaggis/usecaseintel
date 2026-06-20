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

- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1562.001** — Impair Defenses: Disable or Modify Tools
- **T1036.003** — Masquerading: Rename Legitimate Utilities

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Crossplane Package installed via mutable tag reference (GHSA-wfqx-gjrf-g28r vulnerable condition)

`UC_6_0` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
sourcetype="kube:apiserver:audit" objectRef.apiGroup="pkg.crossplane.io" objectRef.resource IN ("configurations","providers","functions") verb IN ("create","update") stage="ResponseComplete"
| rename objectRef.resource AS resource, objectRef.name AS name, requestObject.spec.package AS package_ref, user.username AS user
| where isnotnull(package_ref) AND NOT match(package_ref, "@sha256:[a-f0-9]{64}")
| stats count, min(_time) AS first_seen, max(_time) AS last_seen, values(package_ref) AS package_refs, values(user) AS users by resource, name
| eval mitigation="Pin spec.package to @sha256:<digest> per GHSA-wfqx-gjrf-g28r"
```

### Crossplane ImageConfig modified to remove or weaken cosign signature verification

`UC_6_1` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
sourcetype="kube:apiserver:audit" objectRef.apiGroup="pkg.crossplane.io" objectRef.resource="imageconfigs" verb IN ("update","patch","delete") stage="ResponseComplete"
| rename objectRef.name AS imageconfig_name, user.username AS user, requestObject.spec.verification AS new_verification, requestObject.spec.matchImages{}.prefix AS new_matches
| eval verification_removed=if(verb=="delete" OR isnull(new_verification) OR new_verification=="", 1, 0)
| where verification_removed=1
| stats count, min(_time) AS first_seen, values(imageconfig_name) AS imageconfigs, values(user) AS users, values(verb) AS verbs, values(new_matches) AS prefixes by user
| eval rationale="ImageConfig verification block removed - TOCTOU mitigation disabled"
```

### ECR PutImage re-tag on tag reference seconds before Crossplane package pull (TOCTOU swap window)

`UC_6_2` · phase: **weapon** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count, values(All_Changes.user) AS users, values(All_Changes.src) AS src_ips, values(All_Changes.object) AS repositories, values(All_Changes.object_attrs) AS attrs
  FROM datamodel=Change.All_Changes
  WHERE All_Changes.vendor_product="AWS CloudTrail"
        All_Changes.command="PutImage"
        All_Changes.status="success"
  BY _time span=10s, All_Changes.object
| `drop_dm_object_name(All_Changes)`
| rex field=attrs "imageTag=(?<image_tag>[^,}]+)"
| rex field=attrs "imageDigest=(?<image_digest>sha256:[a-f0-9]{64})"
| where isnotnull(image_tag) AND image_tag!="latest_immutable_placeholder"
| eval crossplane_referenced=if(match(image_tag, "^(v\d+\.\d+\.\d+|main|latest)$"), 1, 0)
| where crossplane_referenced=1
| stats values(image_tag) AS tags, values(image_digest) AS digests, dc(image_digest) AS distinct_digests, values(users) AS actors by repositories
| where distinct_digests > 1
```

### Vulnerable Crossplane core version running in cluster (GHSA-wfqx-gjrf-g28r affected range)

`UC_6_3` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
sourcetype="kube:apiserver:audit" objectRef.apiGroup="apps" objectRef.resource="deployments" verb IN ("create","update","patch") stage="ResponseComplete"
| spath input=requestObject path=spec.template.spec.containers{}.image output=images
| mvexpand images
| where match(images, "crossplane\/crossplane")
| rex field=images "crossplane\/crossplane:v?(?<major>\d+)\.(?<minor>\d+)\.(?<patch>\d+)(?<suffix>[-\w\.]*)?"
| eval vulnerable=case(
    major=1 AND (minor<21 OR (minor=21 AND patch=0 AND like(suffix, "-rc%"))), 1,
    major=2 AND minor=2 AND patch<=2, 1,
    major=2 AND minor=3 AND patch<=2, 1,
    1==1, 0)
| where vulnerable=1
| rename objectRef.name AS deployment, objectRef.namespace AS namespace
| stats values(images) AS observed_images, max(_time) AS last_seen by namespace, deployment
| eval fix_versions="Upgrade to crossplane 2.3.3 or 2.2.3 (or v1 fixed branch)"
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "crossplane" or FileName =~ "crossplane"
| where ProcessVersionInfoProductName has_cs "crossplane" or InitiatingProcessVersionInfoProductName has_cs "crossplane"
| extend Version = coalesce(ProcessVersionInfoProductVersion, InitiatingProcessVersionInfoProductVersion)
| where isnotempty(Version)
| extend Parts = split(Version, ".")
| extend Major = toint(Parts[0]), Minor = toint(Parts[1]), Patch = toint(Parts[2])
| where (Major == 1 and Minor <= 21)
     or (Major == 2 and Minor == 2 and Patch <= 2)
     or (Major == 2 and Minor == 3 and Patch <= 2)
| project Timestamp, DeviceName, Version, FolderPath, InitiatingProcessCommandLine
| summarize arg_max(Timestamp, *) by DeviceName, Version
```


## Why this matters

Severity classified as **CRIT** based on: 4 use case(s) fired, 3 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
