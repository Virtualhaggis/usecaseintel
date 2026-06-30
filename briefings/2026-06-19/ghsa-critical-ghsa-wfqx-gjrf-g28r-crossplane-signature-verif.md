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

- **T1195.002** — Compromise Software Supply Chain: Compromise Software Dependencies and Development Tools
- **T1562.001** — Impair Defenses: Disable or Modify Tools

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Crossplane package installed by mutable tag instead of immutable digest

`UC_106_0` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
sourcetype="kube:apiserver:audit" objectRef.apiGroup="pkg.crossplane.io" (objectRef.resource="providers" OR objectRef.resource="configurations" OR objectRef.resource="functions") (verb="create" OR verb="update" OR verb="patch")
| rename requestObject.spec.package as package_ref, objectRef.name as object_name, objectRef.resource as kind, user.username as username
| where isnotnull(package_ref) AND NOT match(package_ref, "@sha256:")
| stats min(_time) as firstTime, max(_time) as lastTime, values(username) as username, values(sourceIPs{}) as src_ips by package_ref, kind, object_name
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

### Crossplane ImageConfig signature-verification policy deleted or weakened

`UC_106_1` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
sourcetype="kube:apiserver:audit" objectRef.apiGroup="pkg.crossplane.io" objectRef.resource="imageconfigs" (verb="delete" OR verb="deletecollection" OR verb="update" OR verb="patch")
| rename objectRef.name as imageconfig_name, user.username as username, verb as action, userAgent as user_agent
| spath input=_raw path=requestObject.spec.verification output=verification_spec
| eval verification_present=if(isnull(verification_spec) OR verification_spec="", "no", "yes")
| table _time, username, action, imageconfig_name, user_agent, verification_present, sourceIPs{}
| sort - _time
```


## Why this matters

Severity classified as **CRIT** based on: 2 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
