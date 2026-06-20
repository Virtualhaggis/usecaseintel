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
- **T1036** — Masquerading
- **T1190** — Exploit Public-Facing Application
- **T1562** — Impair Defenses
- **T1562.001** — Disable or Modify Tools

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Crossplane mutable-tag package pull correlated with OCI registry tag overwrite

`UC_7_0` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
index=k8s sourcetype=kube:apiserver:audit objectRef.apiGroup="pkg.crossplane.io" objectRef.resource IN ("providers", "configurations", "functions") verb IN ("create", "update") | rex field=requestObject.spec.package "^(?<registry>[^/]+)/(?<repo>.+):(?<tag>[^@]+)$" | where isnotnull(tag) AND NOT match(tag, "^sha256:") | table _time user.username objectRef.namespace objectRef.name registry repo tag | join type=inner repo [ search index=cloudtrail eventSource="ecr.amazonaws.com" eventName IN ("PutImage", "BatchPutImage") | rename requestParameters.repositoryName as repo requestParameters.imageTag as tag | table _time repo tag userIdentity.arn sourceIPAddress ] | eval delta_seconds=abs(_time - _time1) | where delta_seconds < 600 | table _time repo tag user.username userIdentity.arn sourceIPAddress delta_seconds
```

### Vulnerable Crossplane control-plane version deployed in cluster

`UC_7_1` · phase: **weapon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count from datamodel=Endpoint.Processes where Processes.process_name="crossplane" AND (Processes.process="*v2.3.0*" OR Processes.process="*v2.3.1*" OR Processes.process="*v2.3.2*" OR Processes.process="*v2.2.0*" OR Processes.process="*v2.2.1*" OR Processes.process="*v2.2.2*" OR Processes.process="*v1.20*" OR Processes.process="*v1.21.0-rc*") by Processes.dest Processes.process_name Processes.process | `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceTvmSoftwareInventory
| where SoftwareName has "crossplane"
| where (SoftwareVersion startswith "2.3." and SoftwareVersion !in ("2.3.3", "2.3.4", "2.3.5"))
     or (SoftwareVersion startswith "2.2." and SoftwareVersion !in ("2.2.3", "2.2.4", "2.2.5"))
     or (SoftwareVersion startswith "1." and SoftwareVersion !startswith "1.21.0")
     or SoftwareVersion == "1.21.0-rc.0"
| project Timestamp, DeviceName, SoftwareVendor, SoftwareName, SoftwareVersion
| order by Timestamp desc
```

### Crossplane ImageConfig signature verification policy modified or removed

`UC_7_2` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
index=k8s sourcetype=kube:apiserver:audit objectRef.apiGroup="pkg.crossplane.io" objectRef.resource="imageconfigs" verb IN ("update", "patch", "delete", "create") | eval verification_present=if(isnotnull('requestObject.spec.verification.cosign') OR isnotnull('requestObject.spec.verification.provider'), "yes", "no") | where verb="delete" OR verification_present="no" | table _time user.username sourceIPs objectRef.namespace objectRef.name verb verification_present
```

### Crossplane cosign verification success followed by mismatched image digest at pull

`UC_7_3` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
index=k8s (sourcetype=kube:container:crossplane OR sourcetype=kubelet) | rex "image=(?<pkg>[^ ]+:[^@ ]+)@?(?<digest>sha256:[0-9a-f]{64})?" | rex "(?<action>verified|pulled|signature)" | stats values(digest) as digests dc(digest) as digest_count by pkg host | where digest_count > 1 AND isnotnull(pkg) | table host pkg digests digest_count
```

### OCI registry tag overwrite within seconds of Crossplane package reconciliation

`UC_7_4` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
index=cloudtrail eventSource="ecr.amazonaws.com" eventName IN ("PutImage", "BatchPutImage") | rename requestParameters.repositoryName as repo requestParameters.imageTag as tag | join type=inner repo tag [ search index=k8s sourcetype=kube:apiserver:audit objectRef.apiGroup="pkg.crossplane.io" verb IN ("create", "update", "patch") | rex field=requestObject.spec.package "^[^/]+/(?<repo>.+):(?<tag>[^@]+)$" | where isnotnull(tag) AND NOT match(tag, "^sha256:") | table _time repo tag user.username objectRef.name ] | eval delta_seconds=abs(_time - _time1) | where delta_seconds < 120 | table _time repo tag userIdentity.arn sourceIPAddress user.username objectRef.name delta_seconds
```

### Crossplane Provider or Configuration installed by mutable tag reference

`UC_7_5` · phase: **weapon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
index=k8s sourcetype=kube:apiserver:audit objectRef.apiGroup="pkg.crossplane.io" objectRef.resource IN ("providers", "configurations", "functions") verb IN ("create", "update") | eval pkg=mvindex(split('requestObject.spec.package', "@"), 0) | eval has_digest=if(match('requestObject.spec.package', "@sha256:[0-9a-f]{64}$"), "yes", "no") | where has_digest="no" | table _time user.username objectRef.namespace objectRef.name objectRef.resource requestObject.spec.package
```


## Why this matters

Severity classified as **CRIT** based on: 6 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
