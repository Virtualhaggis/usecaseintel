"""Batch 3 of Datadog default-rule UCs. Adds ~55 net-new detection
rules across Auth0, Google Workspace, Cisco Duo, CrowdStrike, Falco,
Abnormal Security, Confluence, and more CloudTrail/GitHub/GitLab
variants. Skips duplicates of UCs already seeded by batches 1 & 2.

Idempotent — re-run safe.

Run:
    python _seed_datadog_more_rules2.py
"""
from __future__ import annotations
import sys
from pathlib import Path

ROOT = Path(__file__).parent
UC_DIR = ROOT / "use_cases"


def R(id_suffix, kc, title, mitre, dq, desc, *,
      confidence="High", tier="alerting", fp="low"):
    return {
        "id": "UC_DDOG_" + id_suffix,
        "kill_chain": kc, "title": title,
        "confidence": confidence, "tier": tier, "fp_rate": fp,
        "mitre": mitre, "description": desc, "datadog_query": dq,
    }


ROWS: list[dict] = [
    # ---------- Auth0 ----------
    R("AUTH0_BREACHED_PWD_DETECTION_DISABLED", "install",
      "Auth0 breached-password detection disabled",
      [("T1556", "Modify Authentication Process")],
      "source:auth0 @evt.name:tenant_setting_updated\n"
      "@properties.flags.disable_clickjack_protection_headers:false\n"
      "@properties.attack_protection.breached_password_detection.enabled:false",
      "Breached-password detection turned off — adversary lowering the auth bar. "
      "Datadog default 'Auth0 Breached Password Detection Disabled'."),

    R("AUTH0_BRUTE_FORCE_PROTECTION_DISABLED", "install",
      "Auth0 brute-force protection disabled",
      [("T1556", "Modify Authentication Process"), ("T1110", "Brute Force")],
      "source:auth0 @evt.name:tenant_setting_updated\n"
      "@properties.attack_protection.brute_force_protection.enabled:false",
      "Auth0 brute-force protection disabled. "
      "Datadog default 'Auth0 Brute Force Protection Disabled'."),

    R("AUTH0_SUSPICIOUS_IP_THROTTLING_DISABLED", "install",
      "Auth0 suspicious-IP throttling disabled",
      [("T1556", "Modify Authentication Process")],
      "source:auth0 @evt.name:tenant_setting_updated\n"
      "@properties.attack_protection.suspicious_ip_throttling.enabled:false",
      "Auth0 suspicious-IP throttling turned off. "
      "Datadog default 'Auth0 Suspicious IP Throttling Disabled'."),

    R("AUTH0_BREACHED_PWD_LOGIN", "delivery",
      "Auth0 login with known-breached password",
      [("T1110.004", "Credential Stuffing")],
      "source:auth0 @evt.name:successful_login\n"
      "@properties.flagged.breached_password:true",
      "User authenticated with a credential known from a breach corpus. "
      "Datadog default 'Auth0 Breached Password Login'."),

    R("AUTH0_BRUTE_FORCE", "delivery",
      "Auth0 brute-force attack on user",
      [("T1110", "Brute Force")],
      "source:auth0 @evt.name:limit_wc",
      "Auth0's per-user brute-force lockout fired. "
      "Datadog default 'Brute Force Attack on Auth0 User'."),

    R("AUTH0_CREDENTIAL_STUFFING", "delivery",
      "Auth0 credential-stuffing attack",
      [("T1110.004", "Credential Stuffing")],
      "source:auth0 @evt.name:limit_sul",
      "Auth0's distributed-credential-stuffing detector fired. "
      "Datadog default 'Credential Stuffing Attack on Auth0'."),

    R("AUTH0_IMPOSSIBLE_TRAVEL", "delivery",
      "Auth0 impossible-travel sign-in",
      [("T1078.004", "Cloud Accounts")],
      "source:auth0 @evt.name:successful_login\n"
      "@network.client.geoip.country.iso_code:*",
      "Auth0 successful login from geographically impossible locations. "
      "Datadog default 'Impossible Travel Auth0 Login'."),

    R("AUTH0_ANOMALOUS_PROTECTION_EVENTS", "delivery",
      "Auth0 anomalous attack-protection event spike",
      [("T1110", "Brute Force"), ("T1078", "Valid Accounts")],
      "source:auth0 @evt.name:(limit_wc OR limit_sul OR limit_mu OR pwd_leak)",
      "Spike in Auth0 attack-protection trigger events. "
      "Datadog default 'Auth0 Anomalous Attack Protection Events'."),

    # ---------- Google Workspace ----------
    R("GWS_USER_ADMIN_ASSIGNMENT", "install",
      "Google Workspace admin role assigned to user",
      [("T1098.003", "Additional Cloud Roles")],
      "source:gws.activity @evt.name:GRANT_ADMIN_PRIVILEGE",
      "User granted Workspace admin privileges. "
      "Datadog default 'Google Workspace User Admin Role Assignment'."),

    R("GWS_ADMIN_2SV_DISABLED", "install",
      "Google Workspace admin disabled 2SV for OU",
      [("T1556", "Modify Authentication Process")],
      "source:gws.activity @evt.name:CHANGE_TWO_STEP_VERIFICATION_ENROLLMENT\n"
      "@properties.value:false",
      "Two-step verification turned off for an organisational unit. "
      "Datadog default 'Google Workspace Admin 2SV Disabled'."),

    R("GWS_OAUTH_KEY_ACCOUNT_CHANGES", "install",
      "Google Workspace OAuth key making account changes",
      [("T1550.001", "Application Access Token")],
      "source:gws.activity @evt.name:(CREATE_USER OR DELETE_USER OR SUSPEND_USER OR GRANT_ADMIN_PRIVILEGE)\n"
      "@actor.callerType:KEY",
      "OAuth service-account key creating or modifying users. "
      "Datadog default 'Google Workspace OAuth Key Account Changes'."),

    R("GWS_TOR_CLIENT_ACCESS", "delivery",
      "Google Workspace access from Tor exit node",
      [("T1090.003", "Multi-hop Proxy"), ("T1205.002", "Socket Filters")],
      "source:gws.activity @network.client.ip_category:tor",
      "Workspace activity from Tor — anonymisation flag. "
      "Datadog default 'Google Workspace Tor Client Access'."),

    R("GWS_USER_2SV_DISABLED", "install",
      "Google Workspace user disabled 2SV on own account",
      [("T1556", "Modify Authentication Process")],
      "source:gws.activity @evt.name:2sv_disable",
      "User self-disabled 2SV — adversary post-compromise persistence step. "
      "Datadog default 'Google Workspace User 2SV Disabled'."),

    R("GWS_EMAIL_FORWARDING_EXTERNAL", "actions",
      "Google Workspace email auto-forwarding to external domain",
      [("T1114.003", "Email Forwarding Rule")],
      "source:gws.activity @evt.name:(CHANGE_GMAIL_SETTING OR CREATE_FILTER)\n"
      "@properties.parameters.forwardingAddress:*\n"
      "-@properties.parameters.forwardingAddress:(*@your-domain.com)",
      "Auto-forward to a non-corporate domain — classic mail exfil. "
      "Datadog default 'Google Workspace Email Forwarding External'."),

    R("GWS_SVCACCT_UNFAMILIAR", "install",
      "Google Workspace service account modifying group membership",
      [("T1098", "Account Manipulation"), ("T1078.004", "Cloud Accounts")],
      "source:gws.activity @actor.callerType:KEY\n"
      "@evt.name:(ADD_GROUP_MEMBER OR REMOVE_GROUP_MEMBER OR CHANGE_GROUP_MEMBERSHIP)",
      "Unexpected SA modifying group memberships. "
      "Datadog default 'Google Workspace Service Account Unfamiliar Activity'."),

    # ---------- Cisco Duo ----------
    R("DUO_BRUTE_FORCE", "delivery",
      "Cisco Duo brute-force on protected user",
      [("T1110", "Brute Force")],
      "source:cisco-duo @evt.name:authentication @result:fraud",
      "Repeated failed Duo authentications on the same user. "
      "Datadog default 'Cisco Duo Brute Force Attack'."),

    R("DUO_FRAUD_PUSH", "delivery",
      "Cisco Duo fraud-marked push notifications",
      [("T1621", "Multi-Factor Authentication Request Generation")],
      "source:cisco-duo @evt.name:authentication\n"
      "@result:fraud @reason:user_marked_fraud",
      "User marked Duo push prompts as fraudulent — push-bombing attempt. "
      "Datadog default 'Cisco Duo Fraud Push Notifications'."),

    R("DUO_BYPASS_CODE_CREATION", "install",
      "Cisco Duo emergency bypass code created",
      [("T1556", "Modify Authentication Process")],
      "source:cisco-duo @evt.name:bypass_code_create",
      "Admin generated a Duo bypass code — auth-fallback risk. "
      "Datadog default 'Cisco Duo Bypass Code Creation'."),

    R("DUO_ADMIN_LOCKOUT", "delivery",
      "Cisco Duo admin lockout",
      [("T1110", "Brute Force")],
      "source:cisco-duo @evt.name:admin_login @result:failure",
      "Duo admin locked out after excessive failures. "
      "Datadog default 'Cisco Duo Administrator Lockout'."),

    R("DUO_APP_ENUMERATION", "recon",
      "Cisco Duo application enumeration",
      [("T1592.001", "Hardware")],
      "source:cisco-duo @evt.name:application_view",
      "User browsing the list of Duo-protected applications. "
      "Datadog default 'Cisco Duo Application Enumeration'."),

    # ---------- CrowdStrike + Falco + Abnormal (third-party detection forward) ----------
    R("CROWDSTRIKE_ALERT", "actions",
      "CrowdStrike Falcon alert ingested",
      [("T1566", "Phishing"), ("T1204", "User Execution")],
      "source:crowdstrike @event.name:DetectionSummaryEvent",
      "Forwarded CrowdStrike sensor detection — pivot to the original CS console. "
      "Datadog default 'CrowdStrike Alert Detection'."),

    R("FALCO_RUNTIME_ALERT", "actions",
      "Falco runtime-security alert",
      [("T1611", "Escape to Host"), ("T1059", "Command and Scripting Interpreter")],
      "source:falco @priority:(Critical OR Error OR Warning)",
      "Falco kernel-level runtime alert — high-fidelity container/host detection. "
      "Datadog default 'Falco Runtime Alert'."),

    R("ABNORMAL_MALICIOUS_EMAIL", "delivery",
      "Abnormal Security: malicious email opened",
      [("T1566.001", "Spearphishing Attachment")],
      "source:abnormal-security @evt.name:malicious_email @action:opened",
      "User opened a malicious email Abnormal flagged. "
      "Datadog default 'Abnormal Security Malicious Email Opened'."),

    R("ABNORMAL_BRUTE_FORCE", "delivery",
      "Abnormal Security: brute-force attack detected",
      [("T1110", "Brute Force")],
      "source:abnormal-security @evt.name:brute_force_attack",
      "Abnormal Security flagged brute-force activity. "
      "Datadog default 'Abnormal Security Brute Force Attack'."),

    R("ABNORMAL_LOGIN_NEW_LOCATION", "delivery",
      "Abnormal Security: login from new location",
      [("T1078.004", "Cloud Accounts")],
      "source:abnormal-security @evt.name:login_new_location",
      "Login from a previously-unseen geo for the user. "
      "Datadog default 'Abnormal Security Login New Location'."),

    # ---------- More CloudTrail (deeper coverage) ----------
    R("CT_S3_PUBLIC_ACCESS_REMOVED", "install",
      "AWS S3 public-access-block removed",
      [("T1578.001", "Create Cloud Instance")],
      "source:cloudtrail @evt.outcome:success\n"
      "@evt.name:(DeletePublicAccessBlock OR PutBucketPublicAccessBlock)\n"
      "@requestParameters.PublicAccessBlockConfiguration.BlockPublicAcls:false",
      "S3 public-access-block disabled — bucket exposure path. "
      "Datadog default 'CloudTrail S3 Public Access Block Removed'."),

    R("CT_EBS_DEFAULT_ENCRYPTION_DISABLED", "install",
      "AWS EBS default encryption disabled",
      [("T1562.001", "Disable or Modify Tools")],
      "source:cloudtrail @evt.outcome:success\n"
      "@evt.name:DisableEbsEncryptionByDefault",
      "Default EBS encryption turned off — new volumes plaintext. "
      "Datadog default 'CloudTrail EBS Default Encryption Disabled'."),

    R("CT_CLOUDWATCH_RULE_DELETED", "install",
      "AWS CloudWatch rule deleted",
      [("T1562.001", "Disable or Modify Tools")],
      "source:cloudtrail @evt.outcome:success @evt.name:DeleteRule",
      "CloudWatch rule removed — alerting / automation may be silenced. "
      "Datadog default 'CloudTrail CloudWatch Rule Deleted'."),

    R("CT_GUARDDUTY_PUBLISH_DISABLED", "install",
      "AWS GuardDuty findings publishing disabled",
      [("T1562.008", "Disable or Modify Cloud Logs")],
      "source:cloudtrail @evt.outcome:success\n"
      "@evt.name:UpdatePublishingDestination\n"
      "@requestParameters.publishingDestination.status:disabled",
      "GuardDuty stopped publishing findings to S3. "
      "Datadog default 'CloudTrail GuardDuty Publishing Disabled'."),

    R("CT_ACCESS_DENIED_SPIKE", "delivery",
      "AWS CloudTrail AccessDenied spike",
      [("T1526", "Cloud Service Discovery")],
      "source:cloudtrail @evt.outcome:failure\n"
      "@errorCode:(AccessDenied OR UnauthorizedOperation)",
      "Burst of AccessDenied errors from one principal — privilege "
      "discovery. Datadog default 'CloudTrail Access Denied Spike'."),

    R("CT_S3_EXFILTRATION", "actions",
      "AWS S3 anomalous bulk download (exfil)",
      [("T1537", "Transfer Data to Cloud Account")],
      "source:cloudtrail @evt.name:(GetObject OR ListObjectsV2)\n"
      "@evt.outcome:success",
      "Anomalous S3 read pattern — pivot for staged exfil. "
      "Datadog default 'CloudTrail S3 Bucket Exfiltration'."),

    R("CT_EC2_KEY_CREATION", "install",
      "AWS EC2 key-pair created",
      [("T1199", "Trusted Relationship"), ("T1098", "Account Manipulation")],
      "source:cloudtrail @evt.outcome:success @evt.name:CreateKeyPair",
      "New EC2 key pair issued — backdoor SSH-access primitive. "
      "Datadog default 'CloudTrail EC2 Key Pair Creation'."),

    R("CT_SECRETS_RETRIEVAL", "actions",
      "AWS Secrets Manager retrieval by unfamiliar principal",
      [("T1555", "Credentials from Password Stores")],
      "source:cloudtrail @evt.outcome:success @evt.name:GetSecretValue\n"
      "-@userIdentity.arn:(*ci-* OR *automation* OR *terraform-*)",
      "Secret read by a human / non-automation principal — credential-theft "
      "indicator. Datadog default 'CloudTrail Secrets Manager Retrieval'."),

    R("CT_AMI_PUBLIC_SHARING", "actions",
      "AWS EC2 AMI shared publicly",
      [("T1537", "Transfer Data to Cloud Account")],
      "source:cloudtrail @evt.outcome:success\n"
      "@evt.name:ModifyImageAttribute\n"
      "@requestParameters.launchPermission.add.items.group:all",
      "AMI launchPermission added 'all' — image now public. "
      "Datadog default 'CloudTrail EC2 AMI Public Sharing'."),

    R("CT_ROUTE53_LOGGING_DISABLED", "install",
      "AWS Route53 query logging disabled",
      [("T1562.008", "Disable or Modify Cloud Logs")],
      "source:cloudtrail @evt.outcome:success\n"
      "@evt.name:DeleteQueryLoggingConfig",
      "DNS query logs deleted — name-resolution observability lost. "
      "Datadog default 'CloudTrail Route53 Query Logging Disabled'."),

    R("CT_NACL_MODIFIED", "install",
      "AWS Network ACL modified",
      [("T1098", "Account Manipulation")],
      "source:cloudtrail @evt.outcome:success\n"
      "@evt.name:(CreateNetworkAclEntry OR DeleteNetworkAclEntry OR ReplaceNetworkAclEntry)",
      "VPC NACL entries changed — segmentation drift. "
      "Datadog default 'CloudTrail Network ACL Modified'."),

    R("CT_EBS_SNAPSHOT_PUBLIC", "actions",
      "AWS EBS snapshot made public",
      [("T1537", "Transfer Data to Cloud Account")],
      "source:cloudtrail @evt.outcome:success\n"
      "@evt.name:ModifySnapshotAttribute\n"
      "@requestParameters.createVolumePermission.add.items.group:all",
      "EBS snapshot exposed to all-AWS — bulk data exfil path. "
      "Datadog default 'CloudTrail EBS Snapshot Made Public'."),

    R("CT_ORG_LEAVE", "actions",
      "AWS Organization leave initiated",
      [("T1531", "Account Access Removal")],
      "source:cloudtrail @evt.outcome:success @evt.name:LeaveOrganization",
      "Account left the AWS organization — central control loss. "
      "Datadog default 'CloudTrail AWS Organization Leave'."),

    R("CT_BEDROCK_LOGGING_DISABLED", "install",
      "AWS Bedrock model invocation logging disabled",
      [("T1562.008", "Disable or Modify Cloud Logs")],
      "source:cloudtrail @evt.outcome:success\n"
      "@evt.name:DeleteModelInvocationLoggingConfiguration",
      "Bedrock invocation logs disabled. "
      "Datadog default 'CloudTrail Bedrock Model Invocation Disabled'."),

    R("CT_DETECTIVE_GRAPH_DELETED", "install",
      "AWS Detective behaviour graph deleted",
      [("T1531", "Account Access Removal"), ("T1562.008", "Disable or Modify Cloud Logs")],
      "source:cloudtrail @evt.outcome:success @evt.name:DeleteGraph",
      "Detective graph deleted — investigation trail destroyed. "
      "Datadog default 'CloudTrail Detective Graph Deleted'."),

    # ---------- Datadog audit (more) ----------
    R("DATADOG_SUSPICIOUS_LOGIN", "delivery",
      "Datadog suspicious login",
      [("T1078.004", "Cloud Accounts")],
      "source:audit @evt.name:user.login @outcome.result:SUCCESS\n"
      "@network.client.geoip.country.iso_code:*",
      "Datadog console login flagged as suspicious by geo / device fingerprint. "
      "Datadog default 'Datadog suspicious login'."),

    # ---------- More GitHub variants ----------
    R("GITHUB_PAT_IMPOSSIBLE_TRAVEL", "delivery",
      "GitHub PAT used from impossible-travel locations",
      [("T1078.004", "Cloud Accounts"), ("T1550.001", "Application Access Token")],
      "source:github @actor.type:PAT @network.client.geoip.country.iso_code:*",
      "Same PAT seen from geographically distant locations within an "
      "impossible-travel window. Datadog default 'GitHub PAT Impossible Travel'."),

    R("GITHUB_SECRETS_ENUMERATION", "actions",
      "GitHub secrets-API enumeration",
      [("T1555", "Credentials from Password Stores")],
      "source:github @evt.name:(repo.secret_scanning_alert OR repo.access_secret_scanning_alert)",
      "Burst of access to secret-scanning alerts — adversary harvesting "
      "leaked creds. Datadog default 'GitHub Secrets Enumeration via API'."),

    R("GITHUB_MASS_REPO_DELETION", "actions",
      "GitHub mass repository deletion",
      [("T1485", "Data Destruction"), ("T1531", "Account Access Removal")],
      "source:github @evt.name:repo.destroy",
      "Bulk repo deletion in a tight window — destructive impact. "
      "Datadog default 'GitHub Mass Repository Deletion'."),

    R("GITHUB_SSH_KEY_SUSPICIOUS", "install",
      "GitHub SSH key added from suspicious IP",
      [("T1098.004", "SSH Authorized Keys")],
      "source:github @evt.name:public_key.create",
      "SSH public key added — backdoor access primitive; pivot via IP geo. "
      "Datadog default 'GitHub SSH Key Added Suspicious'."),

    R("GITHUB_SAML_OIDC_DISABLED", "install",
      "GitHub SAML/OIDC SSO disabled",
      [("T1556", "Modify Authentication Process")],
      "source:github @evt.name:(org.disable_saml OR org.disable_oidc OR enterprise.disable_saml)",
      "Org SSO turned off — auth-bar lowering. "
      "Datadog default 'GitHub SAML/OIDC Disabled'."),

    # ---------- More GitLab variants ----------
    R("GITLAB_BRUTE_FORCE", "delivery",
      "GitLab brute-force attack",
      [("T1110", "Brute Force")],
      "source:gitlab @evt.name:user.failed_login",
      "Repeated failed GitLab logins. "
      "Datadog default 'GitLab Brute Force Attack'."),

    R("GITLAB_MFA_DISABLED", "install",
      "GitLab user MFA disabled",
      [("T1556", "Modify Authentication Process")],
      "source:gitlab @evt.name:user.two_factor_auth_disabled",
      "User self-disabled MFA on GitLab. "
      "Datadog default 'GitLab MFA Disabled'."),

    R("GITLAB_PROJECT_VISIBILITY", "actions",
      "GitLab project visibility changed (public)",
      [("T1538", "Cloud Service Dashboard"), ("T1213.003", "Code Repositories")],
      "source:gitlab @evt.name:project.update\n"
      "@change.field:visibility @target.value:public",
      "Project flipped to public — IP-leak risk. "
      "Datadog default 'GitLab Project Visibility Changed'."),

    R("GITLAB_MASS_DOWNLOAD", "actions",
      "GitLab mass repository download",
      [("T1537", "Transfer Data to Cloud Account"), ("T1213.003", "Code Repositories")],
      "source:gitlab @evt.name:repository.git_clone",
      "Anomalous spike in clones from one user / IP — exfil signal. "
      "Datadog default 'GitLab Mass Repository Download'."),

    # ---------- Atlassian + Confluence ----------
    R("ATLASSIAN_ADMIN_GROUP_ADD", "install",
      "Atlassian user added to administrative group",
      [("T1098", "Account Manipulation")],
      "source:atlassian @evt.name:GroupMembershipChanged\n"
      "@target.group:*Admin*",
      "User added to an Atlassian admin group. "
      "Datadog default 'Atlassian user added to administrative group'."),

    R("ATLASSIAN_ADMIN_IMPERSONATION", "actions",
      "Atlassian administrator impersonating user",
      [("T1078", "Valid Accounts"), ("T1098", "Account Manipulation")],
      "source:atlassian @evt.name:UserImpersonated",
      "Admin took over a user session — investigate operational legitimacy. "
      "Datadog default 'Atlassian administrator impersonated user'."),

    R("CONFLUENCE_SPACE_EXPORT", "actions",
      "Confluence space export",
      [("T1537", "Transfer Data to Cloud Account")],
      "source:confluence @evt.name:space.exported",
      "Space-level export — bulk content exfil. "
      "Datadog default 'Confluence Space Export'."),

    R("CONFLUENCE_GLOBAL_SETTING_CHANGED", "install",
      "Confluence global security setting changed",
      [("T1556", "Modify Authentication Process"), ("T1562", "Impair Defenses")],
      "source:confluence @evt.name:global.setting.changed",
      "Global Confluence security setting modified. "
      "Datadog default 'Confluence Global Setting Changed'."),

    R("CONFLUENCE_PUBLIC_LINK", "actions",
      "Confluence page public link created",
      [("T1537", "Transfer Data to Cloud Account"), ("T1538", "Cloud Service Dashboard")],
      "source:confluence @evt.name:page.public_link.created",
      "Public-link sharing of an internal page. "
      "Datadog default 'Confluence Public Link Creation'."),
]


def _yaml_block_scalar(s: str, indent: int = 0) -> str:
    pad = "  " * indent
    body = "\n".join(f"{pad}  {line}" for line in s.split("\n"))
    return f"|-\n{body}"


def _yaml_scalar(s: str) -> str:
    """Render a single-line string as a safe YAML scalar — quote if it
    contains characters that would otherwise be interpreted (colons,
    leading hash/dash/etc)."""
    if any(c in s for c in (":", "#", "{", "}", "[", "]", "&", "*", "!", "|", ">", "'", '"', "%", "@", "`")) or s.startswith(("- ", "? ")):
        return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"") + "\""
    return s


def emit_yaml(row: dict) -> str:
    body = []
    body.append(f"id: {row['id']}")
    body.append(f"title: {_yaml_scalar(row['title'])}")
    body.append(f"kill_chain: {row['kill_chain']}")
    body.append(f"confidence: {row['confidence']}")
    body.append(f"tier: {row['tier']}")
    body.append(f"fp_rate_estimate: {row['fp_rate']}")
    body.append("implementations:")
    body.append("- datadog")
    body.append("mitre_attack:")
    for tid, tname in row["mitre"]:
        body.append(f"- id: {tid}")
        body.append(f"  name: {tname}")
    body.append(f"description: {_yaml_block_scalar(row['description'])}")
    body.append(f"datadog_query: {_yaml_block_scalar(row['datadog_query'])}")
    return "\n".join(body) + "\n"


def main() -> int:
    written = 0
    skipped = 0
    for row in ROWS:
        target = UC_DIR / row["kill_chain"] / f"{row['id']}.yml"
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            skipped += 1
            continue
        target.write_text(emit_yaml(row), encoding="utf-8")
        written += 1
    print(f"\n{written} written, {skipped} already existed (out of {len(ROWS)})")
    sys.path.insert(0, str(ROOT))
    try:
        import yaml as _y
        for row in ROWS:
            target = UC_DIR / row["kill_chain"] / f"{row['id']}.yml"
            doc = _y.safe_load(target.read_text(encoding="utf-8"))
            assert doc.get("id") == row["id"], f"id mismatch in {target}"
        print("YAML load sanity-check: OK")
    except Exception as e:
        print(f"YAML load failed: {e}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
