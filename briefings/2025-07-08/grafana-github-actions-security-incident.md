# [MED] Grafana GitHub Actions Security Incident

**Source:** StepSecurity
**Published:** 2025-07-08
**Article:** https://www.stepsecurity.io/blog/grafana-github-actions-security-incident

## Threat Profile

Back to Blog Threat Intel Grafana GitHub Actions Security Incident This blog post will be updated as more details emerge. On Saturday, April 26, 2025, Grafana Labs disclosed that an unauthorized user leveraged a vulnerability in a GitHub Actions workflow within a public Grafana Labs repository. Varun Sharma View LinkedIn April 28, 2025
Share on X Share on X Share on LinkedIn Share on Facebook Follow our RSS feed 
Table of Contents Loading nav... 
Introduction On Saturday, April 26, 2025, Grafana…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1552.004** — Unsecured Credentials: Private Keys
- **T1213.003** — Data from Information Repositories: Code Repositories
- **T1567** — Exfiltration Over Web Service
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1505.003** — Server Software Component: Web Shell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] GitHub workflow file commits containing toJSON(secrets) + upload-artifact (Grafana-style secret exfil)

`UC_689_0` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
`summariesonly` index=github sourcetype IN ("github:cloud:auditlog","github:audit:json","github:enterprise:audit") action IN ("git.push","workflows.created_workflow_run","workflow_run.created") | rex field=_raw "(?P<workflow_file>\.github/workflows/[^\"\s]+\.ya?ml)" | rex field=_raw "(?P<secret_dump>toJSON?\(\s*secrets\s*\)|\$\{\{\s*toJSON?\(\s*secrets\s*\)\s*\}\})" | rex field=_raw "(?P<upload_artifact>actions/upload-artifact@|upload-artifact)" | rex field=_raw "(?P<crypto>aes-256-cbc|openssl\s+enc|crypto\.publicEncrypt|forge\.pki\.rsa)" | where isnotnull(workflow_file) AND isnotnull(secret_dump) AND (isnotnull(upload_artifact) OR isnotnull(crypto)) | stats min(_time) as firstSeen max(_time) as lastSeen values(workflow_file) as workflows values(repo) as repos values(actor) as actors by branch | where branch!="main" AND branch!="master" AND NOT match(branch,"^(release|hotfix)/")
```

**Defender KQL:**
```kql
// Defender for Cloud Apps must be connected to GitHub Enterprise for these rows to populate
CloudAppEvents
| where Timestamp > ago(7d)
| where Application has "GitHub"
| where ActionType in~ ("Create or update a Git file","Create commit","Push","Create workflow run","git.push")
| extend Raw = tostring(RawEventData)
| extend WorkflowFile = extract(@"(?i)(\.github/workflows/[^\"'\s]+\.ya?ml)", 1, Raw)
| where isnotempty(WorkflowFile)
| extend HasSecretDump  = Raw matches regex @"(?i)toJSON?\s*\(\s*secrets\s*\)"
| extend HasArtifactUpload = Raw matches regex @"(?i)(actions/upload-artifact|upload-artifact@)"
| extend HasCrypto = Raw matches regex @"(?i)(aes-256-cbc|openssl\s+enc|publicEncrypt|forge\.pki)"
| extend BranchRef = tostring(parse_json(Raw).ref)
| where HasSecretDump and (HasArtifactUpload or HasCrypto)
| where BranchRef !endswith "/main" and BranchRef !endswith "/master"
| project Timestamp, AccountDisplayName, AccountType, IPAddress, CountryCode, ObjectName, WorkflowFile, BranchRef, HasSecretDump, HasArtifactUpload, HasCrypto, Raw
```

### [LLM] GitHub bot/App identity creates short-lived branch, commits .github/workflows file, deletes branch

`UC_689_1` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
`summariesonly` index=github sourcetype IN ("github:cloud:auditlog","github:audit:json","github:enterprise:audit") action IN ("git.create","git.create_branch","git.push","git.delete","git.delete_branch","protected_branch.destroy") | eval branch=coalesce(ref, branch, 'data.ref') | eval is_workflow_commit=if(match(_raw, "(?i)\.github/workflows/[^\"]+\.ya?ml"), 1, 0) | stats min(_time) as branch_first_seen max(_time) as branch_last_seen values(action) as actions values(actor_type) as actor_types sum(is_workflow_commit) as workflow_commits values(actor) as actors by repo,branch | where actions="git.create" AND actions="git.delete" AND workflow_commits>=1 | eval lifetime_minutes=round((branch_last_seen-branch_first_seen)/60, 1) | where lifetime_minutes < 60 | where match(branch, "^refs/heads/[a-z0-9]{8,20}$") OR NOT match(branch, "(?i)(feat|fix|chore|release|hotfix|dependabot|renovate)/")
```

**Defender KQL:**
```kql
// Requires Defender for Cloud Apps GitHub connector. ActionType strings reflect MDA's GitHub mappings.
let window = 1h;
let repo_actor = CloudAppEvents
  | where Timestamp > ago(7d)
  | where Application has "GitHub"
  | where ActionType in~ ("Create Git branch","Delete Git branch","Create or update a Git file","Create commit","git.create","git.delete","git.push")
  | extend Raw = tostring(RawEventData)
  | extend Repo = tostring(parse_json(Raw).repository.full_name)
  | extend Branch = coalesce(tostring(parse_json(Raw).ref), tostring(parse_json(Raw)["data"].ref))
  | extend Actor = AccountDisplayName
  | where AccountType in~ ("Bot","Application","ServiceAccount","App") or Actor endswith "[bot]";
repo_actor
| summarize
    BranchCreated  = countif(ActionType in~ ("Create Git branch","git.create")),
    BranchDeleted  = countif(ActionType in~ ("Delete Git branch","git.delete")),
    WorkflowCommit = countif(ActionType in~ ("Create or update a Git file","Create commit","git.push") and Raw matches regex @"(?i)\.github/workflows/[^\"]+\.ya?ml"),
    FirstSeen = min(Timestamp),
    LastSeen  = max(Timestamp),
    SampleEvents = make_set(ActionType, 10)
    by Repo, Branch, Actor
| where BranchCreated >= 1 and BranchDeleted >= 1 and WorkflowCommit >= 1
| extend LifetimeMinutes = datetime_diff('minute', LastSeen, FirstSeen)
| where LifetimeMinutes <= 60
| where Branch matches regex @"^refs/heads/[a-z0-9]{8,20}$" or not(Branch matches regex @"(?i)(feat|fix|chore|release|hotfix|dependabot|renovate)/")
| order by FirstSeen desc
```


## Why this matters

Severity classified as **MED** based on: 2 use case(s) fired, 6 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
