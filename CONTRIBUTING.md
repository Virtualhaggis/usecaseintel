# Contributing — adding a new use case

The catalog is YAML-driven. To add a use case:

## 1. Pick a kill chain phase

`recon`, `weapon`, `delivery`, `exploit`, `install`, `c2`, `actions`.

## 2. Create the YAML

Path: `use_cases/<phase>/UC_<NAME>.yml`

Use an existing file as a template (e.g. `use_cases/exploit/UC_PS_OBFUSCATED.yml`).
Required fields documented in [`use_cases/SCHEMA.md`](use_cases/SCHEMA.md).

```yaml
id: UC_NEW_DETECTION
title: Short human-readable description
kill_chain: exploit
confidence: High
description: |
  Why this matters, what it catches, when it fires.

implementations:
  - splunk
  - defender

mitre_attack:
  - { id: T1059.001, name: 'PowerShell' }

data_models:
  splunk:
    - Endpoint.Processes
  defender:
    - DeviceProcessEvents

splunk_spl: |
  | tstats `summariesonly` count from datamodel=Endpoint.Processes
  ...

defender_kql: |
  DeviceProcessEvents
  | where Timestamp > ago(7d)
  ...
```

## 3. Optional: wire it to article-narrative triggers

If your use case should auto-fire when an article mentions specific keywords,
add or update `rules/<topic>.yml`:

```yaml
name: My new pattern
triggers:
  - keyword phrase one
  - second keyword
fires:
  - UC_NEW_DETECTION
```

## 4. Validate

```
python validate.py
```

Required for PR merge:
- 0 errors
- All MITRE technique IDs current (not deprecated)
- Splunk fields valid against CIM 8.5 spec or ESCU
- Defender tables/columns valid against XDR Advanced Hunting schema

## 5. Test the build

```
python generate.py
```

Open `index.html`, switch to the **ATT&CK Matrix** tab, find your technique
cells. Confirm your use case shows in the drawer when clicked.

## 6. Open a PR

- Title: `feat(use_case): add UC_<NAME> — short description`
- Body: link any source detection (ESCU, Sigma, Microsoft Hunting Queries)
  that informed your detection
- CI runs `validate.py` automatically (see `.github/workflows/validate.yml`)

## SPL/KQL quality bar

- Splunk: use CIM `tstats` with canonical field paths (`Processes.dest`,
  `All_Email.recipient`, `All_Traffic.dest`). Use the `summariesonly`,
  `drop_dm_object_name()`, `security_content_ctime()` macros where appropriate.
- Defender: use Advanced Hunting tables only (no Sentinel-only `SigninLogs`,
  prefer `AADSignInEventsBeta`). Reference Microsoft Learn schema docs when
  in doubt.

## Reference docs

- [Splunk CIM 8.5](https://help.splunk.com/en/data-management/common-information-model/8.5/)
- [Splunk ESCU](https://github.com/splunk/security_content)
- [Defender XDR Advanced Hunting schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables)
- [MITRE ATT&CK Enterprise](https://attack.mitre.org/techniques/enterprise/)
