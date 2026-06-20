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

- **T1195.002** — Compromise Software Supply Chain
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1190** — Exploit Public-Facing Application

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Crossplane Package CRD installed with mutable tag reference (GHSA-wfqx-gjrf-g28r precondition)

`UC_5_0` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Change.object_attrs) as object_attrs values(Change.user) as user from datamodel=Change where Change.object_category="kubernetes" Change.action IN ("created","modified") (Change.object="providers.pkg.crossplane.io" OR Change.object="configurations.pkg.crossplane.io" OR Change.object="functions.pkg.crossplane.io") by Change.object, Change.object_id
| `drop_dm_object_name("Change")`
| search object_attrs="*package:*" NOT object_attrs="*@sha256:*"
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

### Vulnerable Crossplane control-plane version running in cluster (GHSA-wfqx-gjrf-g28r)

`UC_5_1` · phase: **weapon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count values(Change.object_attrs) as object_attrs latest(_time) as lastTime from datamodel=Change where Change.object_category="kubernetes" Change.object="pods" (Change.object_attrs="*crossplane/crossplane:*" OR Change.object_attrs="*xpkg.crossplane.io/crossplane/crossplane:*") by Change.object_id, Change.object_path
| `drop_dm_object_name("Change")`
| rex field=object_attrs "crossplane/crossplane:(?<crossplane_version>v?[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?)"
| where isnotnull(crossplane_version)
| eval vulnerable=case(match(crossplane_version,"^v?2\.3\.(0-rc\.\d+|0|1|2)$"),"yes", match(crossplane_version,"^v?2\.(0|1|2)\."),"yes", match(crossplane_version,"^v?1\."),"yes", true(),"no")
| where vulnerable="yes"
| table object_path, crossplane_version, lastTime
```


## Why this matters

Severity classified as **CRIT** based on: 2 use case(s) fired, 3 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
