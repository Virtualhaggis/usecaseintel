<!-- curated:true -->
# [HIGH] Toxic Combinations: When Cross-App Permissions Stack Into Risk

**Source:** The Hacker News
**Published:** 2026-04-22
**Article:** https://thehackernews.com/2026/04/toxic-combinations-when-cross-app.html
**Curated:** Analyst-reviewed 2026-04-28

## Threat profile

A vendor research piece (with a real anchor incident — the Moltbook AI-agent platform leak) on the **OAuth toxic-combination** problem:

- Each individual OAuth scope grants **a narrow capability** (read user email, list calendar events, etc.).
- A user who consents to **two apps**, each requesting its own narrow scope, can effectively grant **the union of capabilities** to whichever party can chain them.
- "Token resale" between apps (or compromise of a low-importance app that still requested powerful scopes) creates **toxic combinations** — capabilities that no individual app should have but the user effectively granted.

The Moltbook leak is the worked example: a social platform for AI agents leaked 1.5 million agent API tokens. Many of those tokens were chained third-party credentials (OpenAI keys, GitHub PATs, AWS keys) shared between agents. The exposure propagates through *every* downstream system the original tokens accessed.

For SOC operations, this is a **detect-and-prune problem**: most enterprises have hundreds of consented OAuth apps in their tenant, no inventory of which scopes were granted, and no way to spot the toxic combinations.

We've upgraded severity to **HIGH** because OAuth-app-as-attack-surface is the dominant 2025-2026 SaaS-compromise pattern, and the toxic-combination angle is **systematically under-monitored**.

## Indicators of Compromise

- _Moltbook database leak — affected community is users who registered AI agents on the platform._
- More broadly: **any** OAuth-consented app in your tenant that doesn't have a clear business owner is a potential toxic-combination candidate.

## MITRE ATT&CK (analyst-validated)

- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1528** — Steal Application Access Token
- **T1550.001** — Use Alternate Authentication Material: Application Access Token
- **T1199** — Trusted Relationship
- **T1567.002** — Exfiltration to Cloud Storage

## Recommended SOC actions (priority-ordered)

1. **Inventory consented OAuth apps in your Entra ID / Okta / Google Workspace tenant.** This is the single most important action — most enterprises have never done a full audit.
2. **Hunt high-privilege scope grants.** Apps with `Mail.ReadWrite`, `Files.ReadWrite.All`, `Directory.AccessAsUser.All`, `Sites.FullControl.All`, `User.ReadWrite.All` — these are the toxic-combination ingredients.
3. **Disable user-self-consent for high-impact scopes.** Configure Entra ID consent policies (`Users can consent to apps from verified publishers, for selected permissions`).
4. **Review long-tail OAuth consents** — apps that have been consented to but haven't authenticated in 90+ days are candidates for revocation.
5. **Set up an OAuth-consent-monitoring rule** — alert on any new consent with high-impact scopes.
6. **Tabletop a "compromised OAuth app" scenario** — what's the runbook for revocation, what data was exposed, who notifies what.

## Splunk SPL — OAuth consent grants in tenant (Entra)

```spl
index=azure sourcetype="azure:audit"
    OperationName IN ("Consent to application","Add OAuth2PermissionGrant",
                       "Add delegated permission grant","Add app role assignment")
| eval app = mvindex('targetResources{}.displayName', 0)
| eval permissions = mvindex('targetResources{}.modifiedProperties{}.newValue', 0)
| stats values(initiatedBy.user.userPrincipalName) AS who_consented,
        values(initiatedBy.user.ipAddress) AS source_ip,
        latest(permissions) AS scopes,
        earliest(_time) AS firstTime, latest(_time) AS lastTime,
        count
        by app, OperationName
| sort - lastTime
```

## Splunk SPL — high-privilege OAuth scope assignments

```spl
index=azure sourcetype="azure:audit"
    OperationName IN ("Consent to application","Add app role assignment","Add OAuth2PermissionGrant")
    targetResources{}.modifiedProperties{}.newValue IN (
        "*Mail.ReadWrite*","*Files.ReadWrite.All*","*Directory.AccessAsUser.All*",
        "*Sites.FullControl.All*","*User.ReadWrite.All*","*Mail.Send*",
        "*Calendars.ReadWrite*","*Group.ReadWrite.All*","*RoleManagement.ReadWrite.Directory*")
| eval app = mvindex('targetResources{}.displayName', 0)
| stats values(initiatedBy.user.userPrincipalName) AS consented_by,
        values(initiatedBy.user.ipAddress) AS source_ip,
        latest(targetResources{}.modifiedProperties{}.newValue) AS scopes,
        latest(_time) AS lastTime
        by app
```

## Splunk SPL — OAuth token use anomaly

```spl
index=azure sourcetype=azure:signin
    isInteractive=false servicePrincipalName=*
| stats values(ipAddress) AS source_ips, dc(ipAddress) AS unique_ips,
        dc(country) AS unique_countries, count
        by servicePrincipalName, appId
| where unique_ips > 5 OR unique_countries > 1
| sort - count
```

## Defender KQL — OAuth consents (full audit)

```kql
AuditLogs
| where Timestamp > ago(180d)
| where OperationName in~ ("Consent to application.","Add OAuth2PermissionGrant.",
                            "Add delegated permission grant.",
                            "Add app role assignment to service principal.")
| extend AppName = tostring(TargetResources[0].displayName),
         InitiatorUpn = tostring(InitiatedBy.user.userPrincipalName),
         InitiatorIp = tostring(InitiatedBy.user.ipAddress),
         Permissions = tostring(parse_json(tostring(TargetResources[0].modifiedProperties))[0].newValue)
| project Timestamp, AppName, InitiatorUpn, InitiatorIp, Permissions, OperationName
| order by Timestamp desc
```

## Defender KQL — high-impact OAuth scope grants

```kql
AuditLogs
| where Timestamp > ago(180d)
| where OperationName has_any ("Consent to application.","Add OAuth2PermissionGrant.",
                                 "Add app role assignment")
| extend ModifiedProps = tostring(TargetResources[0].modifiedProperties)
| where ModifiedProps has_any (
    "Mail.ReadWrite","Files.ReadWrite.All","Directory.AccessAsUser.All",
    "Sites.FullControl.All","User.ReadWrite.All","Mail.Send",
    "Calendars.ReadWrite","Group.ReadWrite.All","RoleManagement.ReadWrite.Directory")
| extend AppName = tostring(TargetResources[0].displayName),
         InitiatorUpn = tostring(InitiatedBy.user.userPrincipalName),
         InitiatorIp = tostring(InitiatedBy.user.ipAddress)
| project Timestamp, AppName, InitiatorUpn, InitiatorIp, ModifiedProps, OperationName
| order by Timestamp desc
```

## Defender KQL — service principal sign-in geographic anomaly

```kql
AADServicePrincipalSignInLogs
| where Timestamp > ago(60d)
| summarize signins = count(),
            uniqueIPs = dcount(IPAddress),
            countries = make_set(Country, 30),
            firstSeen = min(Timestamp), lastSeen = max(Timestamp)
            by ServicePrincipalId, ServicePrincipalName, AppId
| where uniqueIPs > 3 or array_length(countries) > 1
| order by signins desc
```

## Why this matters for your SOC

OAuth toxic combinations are the **invisible attack surface** in most cloud-tenant security programs:
- Endpoint EDR doesn't see them.
- Network telemetry doesn't see them.
- Email gateway doesn't see them.
- They live entirely in the identity provider's audit log, which most SOCs under-monitor.

The **practical detection and remediation work** is straightforward but unglamorous: inventory, scope review, consent policy enforcement, monitoring rule. Most of it is one-time work to clean up historical drift, then ongoing alerting on new high-impact consents. Run the consent inventory this week. The result is almost always shocking the first time you do it — undocumented apps, employees consented to high-privilege scopes years ago, service principals nobody owns. Each one is a toxic-combination candidate.
