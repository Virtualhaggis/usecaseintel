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
- **T1562** — Impair Defenses

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Crossplane package installed using mutable tag reference (TOCTOU-exploitable pattern)

`UC_5_0` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
index=k8s_audit objectRef.apiGroup="pkg.crossplane.io" objectRef.resource IN (configurations,providers,functions) verb IN (create,update,patch) requestObject.spec.package=* NOT requestObject.spec.package="*@sha256:*" | table _time user.username verb objectRef.namespace objectRef.name requestObject.spec.package userAgent | sort - _time
```

### Crossplane ImageConfig signature verification disabled or modified

`UC_5_1` · phase: **weapon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
index=k8s_audit objectRef.apiGroup="pkg.crossplane.io" objectRef.resource="imageconfigs" verb IN (create,update,patch,delete) | spath input=requestObject path=spec.verification.provider output=verify_provider | spath input=requestObject path=spec.verification.cosign.authorities{}.keyless output=keyless | where isnull(verify_provider) OR verify_provider="none" OR verb="delete" OR isnull(keyless) | table _time user.username verb objectRef.name verify_provider userAgent | sort - _time
```

### OCI manifest digest divergence between Crossplane signature verify and image pull

`UC_5_2` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
index=crossplane (msg="signature verified" OR msg="image pulled") | rex field=msg "digest=(?<digest>sha256:[a-f0-9]+)" | rex field=msg "package=(?<package>\S+)" | eval phase=if(searchmatch("signature verified"),"verify","pull") | stats earliest(eval(if(phase=="verify",digest,null))) AS verified_digest latest(eval(if(phase=="pull",digest,null))) AS pulled_digest by package host | where isnotnull(verified_digest) AND isnotnull(pulled_digest) AND verified_digest!=pulled_digest
```

### Crossplane package install completes with signature or content mismatch

`UC_5_3` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
index=crossplane msg="package install complete" | rex field=msg "package=(?<package>\S+)" | rex field=msg "verified_digest=(?<verified_digest>sha256:[a-f0-9]+)" | rex field=msg "installed_digest=(?<installed_digest>sha256:[a-f0-9]+)" | rex field=msg "signature_valid=(?<signature_valid>true|false)" | where verified_digest!=installed_digest OR signature_valid="false" | table _time package verified_digest installed_digest signature_valid host
```

### Rapid OCI mutable-tag overwrite during Crossplane install window

`UC_5_4` · phase: **weapon** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
index=oci_registry action IN (tag_update, manifest_push) | stats range(_time) AS span_seconds values(action) AS actions values(digest) AS digests count by repository tag | where mvcount(digests)>=2 AND span_seconds<60
```


## Why this matters

Severity classified as **CRIT** based on: 5 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
