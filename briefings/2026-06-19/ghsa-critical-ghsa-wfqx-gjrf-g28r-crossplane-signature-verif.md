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

- **T1562.001** — Impair Defenses: Disable or Modify Tools
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1036** — Masquerading

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Crossplane ImageConfig CR modified to weaken cosign signature verification

`UC_6_0` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
index=* (sourcetype=kube:apiserver:audit OR sourcetype="kube:audit") objectRef.apiGroup="pkg.crossplane.io" objectRef.resource="imageconfigs" verb IN ("create","update","patch") stage="ResponseComplete"
| spath input=requestObject path=spec output=spec
| eval spec_l=lower(spec)
| where match(spec_l, "(skipsignatureverification|verifyconfigref|verification|cosign)")
| table _time user.username objectRef.name verb spec sourceIPs{}
| sort - _time
```

**Defender KQL:**
```kql
// Defender XDR does not natively ingest Kubernetes API audit; pivot via CloudAppEvents when AKS app connector is enabled.
CloudAppEvents
| where Timestamp > ago(7d)
| where Application has_any ("Kubernetes","Azure Kubernetes Service","AKS")
| where ActionType has_any ("update","patch","create")
| where RawEventData has "pkg.crossplane.io" and RawEventData has "imageconfigs"
| where RawEventData has_any ("skipSignatureVerification","verifyConfigRef","cosign","verification")
| project Timestamp, AccountDisplayName, IPAddress, ActionType, ObjectName, RawEventData
| order by Timestamp desc
```

### Crossplane package installed via mutable tag reference (not image digest)

`UC_6_1` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
index=* (sourcetype=kube:apiserver:audit OR sourcetype="kube:audit") objectRef.apiGroup="pkg.crossplane.io" objectRef.resource IN ("providers","configurations","functions","providerrevisions","configurationrevisions","functionrevisions") verb IN ("create","update") stage="ResponseComplete"
| spath input=requestObject path=spec.package output=pkg
| where isnotnull(pkg) AND NOT match(pkg, "@sha256:[0-9a-f]{64}")
| table _time user.username objectRef.namespace objectRef.name objectRef.resource pkg verb
| sort - _time
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where Application has_any ("Kubernetes","Azure Kubernetes Service","AKS")
| where ActionType has_any ("create","update")
| where RawEventData has "pkg.crossplane.io" and RawEventData has_any ("providers","configurations","functions")
| extend Pkg = extract(@"""package""\s*:\s*""([^""]+)""", 1, tostring(RawEventData))
| where isnotempty(Pkg) and Pkg !contains "@sha256:"
| project Timestamp, AccountDisplayName, IPAddress, ActionType, ObjectName, Pkg
| order by Timestamp desc
```

### OCI registry digest divergence between Crossplane cosign verify and image pull

`UC_6_2` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
index=* sourcetype IN ("harbor:access","ecr:access","ghcr:access","oci:registry","distribution:registry") uri_path="*/manifests/*" status=200
| rex field=uri_path "(?<repo>.+)/manifests/(?<reference>[^/?#]+)"
| eval is_tag=if(match(reference, "^sha256:"),0,1)
| eval digest=coalesce('response.headers.Docker-Content-Digest','docker_content_digest','content_digest')
| search clientip="*" user_agent IN ("crossplane*","go-containerregistry*","cosign/*")
| where is_tag=1 AND isnotnull(digest)
| stats min(_time) as first_seen max(_time) as last_seen dc(digest) as digest_count values(digest) as digests values(user_agent) as agents by clientip repo reference
| where digest_count > 1 AND (last_seen - first_seen) < 120
| sort - last_seen
```

### Rapid OCI mutable-tag re-push during Crossplane package install window

`UC_6_3` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
index=* sourcetype IN ("harbor:access","ecr:access","ghcr:access","oci:registry","distribution:registry") uri_path="*/manifests/*" (method=PUT OR http_method=PUT) status IN (200,201)
| rex field=uri_path "(?<repo>.+)/manifests/(?<tag>[^/?#]+)"
| where NOT match(tag, "^sha256:")
| eval push_time=_time
| join type=inner repo tag [
    search index=* sourcetype IN ("harbor:access","ecr:access","ghcr:access","oci:registry","distribution:registry") uri_path="*/manifests/*" (method=GET OR http_method=GET) status=200 user_agent IN ("crossplane*","go-containerregistry*","cosign/*")
    | rex field=uri_path "(?<repo>.+)/manifests/(?<tag>[^/?#]+)"
    | where NOT match(tag, "^sha256:")
    | eval get_time=_time
    | table get_time repo tag clientip user_agent
  ]
| eval delta=abs(push_time - get_time)
| where delta <= 120
| table push_time get_time delta repo tag clientip user_agent
| sort - push_time
```


## Why this matters

Severity classified as **CRIT** based on: 4 use case(s) fired, 4 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
