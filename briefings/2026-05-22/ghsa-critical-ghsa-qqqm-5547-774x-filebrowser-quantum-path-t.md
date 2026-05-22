# [CRIT] [GHSA / CRITICAL] GHSA-qqqm-5547-774x: FileBrowser Quantum: Path traversal in public share PATCH allows file ops outside shared directory

**Source:** GitHub Security Advisories
**Published:** 2026-05-22
**Article:** https://github.com/advisories/GHSA-qqqm-5547-774x

## Threat Profile

FileBrowser Quantum: Path traversal in public share PATCH allows file ops outside shared directory

## Summary

`publicPatchHandler` in `backend/http/public.go` joins user-controlled `fromPath` and `toPath` body fields with the trusted `d.share.Path` BEFORE the downstream sanitizer runs. Because `filepath.Join` collapses `..` segments during the join, the sanitizer in `resourcePatchHandler` never sees the traversal and the move/copy/rename operates on a path outside the shared directory. The sam…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-44542`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-44542`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
