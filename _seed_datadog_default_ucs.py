"""One-shot: write Datadog-default-rule UCs into use_cases/<phase>/ as YAML.

Each entry below mirrors a rule from Datadog's published default catalog
(https://docs.datadoghq.com/security/default_rules/). We re-author the
detection in our own YAML format so it lands in the matrix + Detection
Library alongside the rest of the catalog. The Datadog query is hand-
written in canonical Datadog Cloud SIEM logs syntax (source: + @field:
+ uppercase booleans + CIDR() for IPs).

Run once:
    python _seed_datadog_default_ucs.py
"""
from __future__ import annotations
import re
import sys
from pathlib import Path

ROOT = Path(__file__).parent
UC_DIR = ROOT / "use_cases"


def _slug(s: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "_", s.lower()).strip("_")
    return s.upper()


# id, kill_chain, title, confidence, tier, fp_rate, mitre, description, datadog_query
ROWS: list[dict] = [
    # ---------- DELIVERY (initial access / brute force / app exploit) ----------
    {
        "id": "UC_DDOG_AWS_CONSOLELOGIN_NO_MFA",
        "kill_chain": "delivery",
        "title": "AWS Console login without MFA + impossible travel",
        "confidence": "High", "tier": "alerting", "fp_rate": "low",
        "mitre": [("T1078", "Valid Accounts"), ("T1550", "Use Alternate Authentication Material")],
        "description": (
            "AWS ConsoleLogin events for an identity that didn't use MFA, where the same "
            "principal also signed in from a geographically distant location within a tight "
            "window (impossible travel). Mirrors Datadog's default rule "
            "'AWS ConsoleLogin without MFA triggered Impossible Travel scenario'."
        ),
        "datadog_query": (
            "source:cloudtrail @evt.name:ConsoleLogin @evt.outcome:success\n"
            "@additionalEventData.MFAUsed:No\n"
            "-@userIdentity.userName:(*break-glass* OR *root)"
        ),
    },
    {
        "id": "UC_DDOG_AWS_ROOT_ACTIVITY",
        "kill_chain": "delivery",
        "title": "AWS root account activity (any action)",
        "confidence": "High", "tier": "alerting", "fp_rate": "low",
        "mitre": [("T1078.004", "Cloud Accounts"), ("T1087.004", "Cloud Account")],
        "description": (
            "Any console / API action by the AWS root identity. Steady-state should be ZERO; "
            "every hit is an investigation. Datadog default 'AWS root account activity'."
        ),
        "datadog_query": (
            "source:cloudtrail @userIdentity.type:Root @evt.outcome:success\n"
            "-@evt.name:(GetCallerIdentity OR DescribeAccountAttributes)"
        ),
    },
    {
        "id": "UC_DDOG_AWS_BRUTE_FORCE_CONSOLE_LOGIN",
        "kill_chain": "delivery",
        "title": "AWS brute-force ConsoleLogin then AssumeRole",
        "confidence": "High", "tier": "alerting", "fp_rate": "low",
        "mitre": [("T1110", "Brute Force"), ("T1550.001", "Application Access Token")],
        "description": (
            "Failed ConsoleLogin attempts against the same identity correlated with a successful "
            "AssumeRole call shortly after — credential-spray landing on a privileged role. "
            "Datadog default 'Brute forced ConsoleLogin event correlates with assumed role'."
        ),
        "datadog_query": (
            "source:cloudtrail (@evt.name:ConsoleLogin @evt.outcome:failure) "
            "OR (@evt.name:AssumeRole @evt.outcome:success)"
        ),
    },
    {
        "id": "UC_DDOG_AZURE_AD_BRUTE_FORCE",
        "kill_chain": "delivery",
        "title": "Azure AD brute-force login",
        "confidence": "Medium", "tier": "alerting", "fp_rate": "medium",
        "mitre": [("T1110", "Brute Force"), ("T1078.004", "Cloud Accounts")],
        "description": (
            "Multiple failed Azure AD sign-ins against the same UPN within a short window — "
            "credential spray / brute force. Datadog default 'Azure AD brute force login'."
        ),
        "datadog_query": (
            "source:azure.activeDirectory @evt.name:\"Sign-in activity\"\n"
            "@properties.status.errorCode:(50126 OR 50053 OR 50055 OR 50057)\n"
            "-@user.userPrincipalName:(*svc-* OR *automation*)"
        ),
    },
    {
        "id": "UC_DDOG_CREDENTIAL_STUFFING",
        "kill_chain": "delivery",
        "title": "Credential-stuffing attack on application",
        "confidence": "High", "tier": "alerting", "fp_rate": "low",
        "mitre": [("T1110.004", "Credential Stuffing"), ("T1078", "Valid Accounts")],
        "description": (
            "Compromised credential pairs reused against a public application — high-volume "
            "login attempts where a small fraction succeed. Datadog default 'Credential Stuffing attack'."
        ),
        "datadog_query": (
            "source:application_logs (@http.url_details.path:*login* OR @http.url_details.path:*signin*)\n"
            "@http.method:POST @http.status_code:(200 OR 401 OR 403)"
        ),
    },
    {
        "id": "UC_DDOG_DISTRIBUTED_CREDENTIAL_STUFFING",
        "kill_chain": "delivery",
        "title": "Distributed credential-stuffing campaign",
        "confidence": "High", "tier": "alerting", "fp_rate": "low",
        "mitre": [("T1110", "Brute Force"), ("T1190", "Exploit Public-Facing Application")],
        "description": (
            "Coordinated credential stuffing across many source IPs — botnet-style spraying "
            "designed to evade per-IP rate limits. Datadog default 'Distributed Credential Stuffing campaign'."
        ),
        "datadog_query": (
            "source:application_logs @http.url_details.path:(*login* OR *signin* OR *auth*)\n"
            "@http.method:POST @http.status_code:401"
        ),
    },
    {
        "id": "UC_DDOG_IMPOSSIBLE_TRAVEL_BUSINESS_LOGIC",
        "kill_chain": "delivery",
        "title": "Impossible travel from application business-logic event",
        "confidence": "High", "tier": "alerting", "fp_rate": "low",
        "mitre": [("T1550", "Use Alternate Authentication Material"), ("T1078", "Valid Accounts")],
        "description": (
            "Successful authentication for the same user from geographically distant locations "
            "within a window that's physically impossible to traverse. Datadog default "
            "'Impossible travel observed from business logic event'."
        ),
        "datadog_query": (
            "source:application_logs @usr.id:* @evt.outcome:success\n"
            "@network.client.geoip.country.iso_code:*"
        ),
    },
    {
        "id": "UC_DDOG_SQL_INJECTION_EXPLOITED",
        "kill_chain": "delivery",
        "title": "SQL injection exploited (WAF detection)",
        "confidence": "High", "tier": "alerting", "fp_rate": "low",
        "mitre": [("T1190", "Exploit Public-Facing Application")],
        "description": (
            "WAF telemetry showing successful SQL injection against a web application — "
            "request payload matched SQLi signatures and returned a 2xx instead of being blocked. "
            "Datadog default 'SQL injection exploited'."
        ),
        "datadog_query": (
            "source:waf_logs @rule.tags:sqli @http.status_code:[200 TO 299]"
        ),
    },
    {
        "id": "UC_DDOG_COMMAND_INJECTION_EXPLOITED",
        "kill_chain": "delivery",
        "title": "Command injection exploited (WAF detection)",
        "confidence": "High", "tier": "alerting", "fp_rate": "low",
        "mitre": [("T1190", "Exploit Public-Facing Application"), ("T1059", "Command and Scripting Interpreter")],
        "description": (
            "WAF telemetry showing successful command-injection against a web application — "
            "shell metacharacters in a request that returned 2xx. Datadog default "
            "'Command injection exploited'."
        ),
        "datadog_query": (
            "source:waf_logs @rule.tags:(command_injection OR cmdi OR rce)\n"
            "@http.status_code:[200 TO 299]"
        ),
    },
    {
        "id": "UC_DDOG_SSRF_EXPLOITED",
        "kill_chain": "delivery",
        "title": "SSRF exploited (WAF detection)",
        "confidence": "High", "tier": "alerting", "fp_rate": "low",
        "mitre": [("T1190", "Exploit Public-Facing Application"), ("T1021", "Remote Services")],
        "description": (
            "WAF telemetry showing successful SSRF — request includes link-local / metadata IP "
            "or internal RFC1918 address as the target, application returned 2xx. Datadog default "
            "'SSRF exploited'."
        ),
        "datadog_query": (
            "source:waf_logs @rule.tags:ssrf @http.status_code:[200 TO 299]"
        ),
    },
    {
        "id": "UC_DDOG_LOG4SHELL_RCE",
        "kill_chain": "delivery",
        "title": "Log4Shell RCE attempts (CVE-2021-44228)",
        "confidence": "High", "tier": "alerting", "fp_rate": "low",
        "mitre": [("T1190", "Exploit Public-Facing Application"), ("T1059", "Command and Scripting Interpreter")],
        "description": (
            "JNDI-lookup payloads (${jndi:ldap://...} / ${jndi:rmi://...}) in HTTP headers or "
            "request bodies — Log4Shell exploitation attempts. Datadog default "
            "'Log4shell RCE attempts (CVE-2021-44228)'."
        ),
        "datadog_query": (
            "source:waf_logs (@http.useragent:*jndi:* OR @http.url:*jndi%3A* "
            "OR @http.referer:*jndi:* OR @http.request.body:*jndi:*)"
        ),
    },
    {
        "id": "UC_DDOG_API_ADMIN_NO_AUTH",
        "kill_chain": "delivery",
        "title": "Authentication not detected on admin API endpoint",
        "confidence": "High", "tier": "hunting", "fp_rate": "low",
        "mitre": [("T1190", "Exploit Public-Facing Application")],
        "description": (
            "Admin API route serving 2xx responses without an Authorization header or session "
            "cookie — exposed admin surface. Datadog default 'Authentication not detected on admin endpoint'."
        ),
        "datadog_query": (
            "source:api_findings @category:authentication "
            "@finding.type:(missing_auth OR no_authentication OR unauthenticated_admin)"
        ),
    },
    {
        "id": "UC_DDOG_API_PII_UNAUTH",
        "kill_chain": "delivery",
        "title": "Unauthenticated route returns sensitive PII",
        "confidence": "High", "tier": "alerting", "fp_rate": "low",
        "mitre": [("T1526", "Cloud Service Discovery"), ("T1538", "Cloud Service Dashboard")],
        "description": (
            "API endpoint without authentication returning PII (email, phone, SSN-shape, card-shape) "
            "in its response body — direct data-exposure path. Datadog default "
            "'Unauthenticated route returns sensitive PII'."
        ),
        "datadog_query": (
            "source:api_findings @category:data_exposure\n"
            "@finding.type:(pii_in_response OR sensitive_data_unauthenticated)"
        ),
    },

    # ---------- INSTALL (privesc / persistence / defense-evasion) ----------
    {
        "id": "UC_DDOG_AWS_IAM_ADMIN_GRANTED",
        "kill_chain": "install",
        "title": "AWS IAM AdministratorAccess policy applied to a user",
        "confidence": "High", "tier": "alerting", "fp_rate": "low",
        "mitre": [("T1098", "Account Manipulation"), ("T1548", "Abuse Elevation Control Mechanism")],
        "description": (
            "An IAM user / group / role just got AdministratorAccess — direct admin grant rather "
            "than going through the org's standard provisioning path. Datadog default "
            "'AWS IAM AdministratorAccess policy was applied to a user'."
        ),
        "datadog_query": (
            "source:cloudtrail @evt.outcome:success\n"
            "@evt.name:(AttachUserPolicy OR AttachGroupPolicy OR AttachRolePolicy)\n"
            "@requestParameters.policyArn:*Administrator*"
        ),
    },
    {
        "id": "UC_DDOG_AZURE_AD_GLOBAL_ADMIN_ASSIGNED",
        "kill_chain": "install",
        "title": "Azure AD member assigned Global Administrator role",
        "confidence": "High", "tier": "alerting", "fp_rate": "low",
        "mitre": [("T1098", "Account Manipulation"), ("T1548", "Abuse Elevation Control Mechanism")],
        "description": (
            "A user just got the Azure AD Global Administrator role — top-of-tenant privilege. "
            "Datadog default 'Azure AD member assigned Global Administrator role'."
        ),
        "datadog_query": (
            "source:azure.activeDirectory\n"
            "@evt.name:\"Add member to role\"\n"
            "@properties.targetResources.modifiedProperties.newValue:*\"Global Administrator\"*"
        ),
    },
    {
        "id": "UC_DDOG_AZURE_AD_MFA_DISABLED",
        "kill_chain": "install",
        "title": "Azure AD MFA disabled for a user",
        "confidence": "High", "tier": "alerting", "fp_rate": "low",
        "mitre": [("T1556", "Modify Authentication Process"), ("T1098", "Account Manipulation")],
        "description": (
            "MFA was turned off for a user — adversary post-compromise persistence step "
            "(remove the second factor before re-using the credential). Datadog default 'Azure AD MFA disabled'."
        ),
        "datadog_query": (
            "source:azure.activeDirectory\n"
            "@evt.name:(\"Disable Strong Authentication\" OR \"Update user\")\n"
            "@properties.targetResources.modifiedProperties.displayName:StrongAuthenticationRequirement"
        ),
    },
    {
        "id": "UC_DDOG_GITHUB_BRANCH_PROTECTION_DISABLED",
        "kill_chain": "install",
        "title": "GitHub branch protection disabled with force-push bypass",
        "confidence": "Medium", "tier": "alerting", "fp_rate": "low",
        "mitre": [("T1562", "Impair Defenses"), ("T1078", "Valid Accounts")],
        "description": (
            "Branch protection rules removed and force-push allowed — adversary clearing the "
            "guard rails to overwrite history or push malicious code. Datadog default "
            "'GitHub branch protection disabled with force push bypass'."
        ),
        "datadog_query": (
            "source:github @evt.name:(branch_protection_rule.destroy OR protected_branch.policy_override)"
        ),
    },

    # ---------- ACTIONS (impact / collection / exfil) ----------
    {
        "id": "UC_DDOG_AWS_KMS_KEY_DELETION",
        "kill_chain": "actions",
        "title": "AWS KMS key deleted or scheduled for deletion",
        "confidence": "High", "tier": "alerting", "fp_rate": "low",
        "mitre": [("T1485", "Data Destruction"), ("T1531", "Account Access Removal")],
        "description": (
            "KMS key scheduled for deletion or deleted outright — disables decryption of "
            "everything the key wrapped (S3, EBS, RDS). Ransomware / insider-impact pattern. "
            "Datadog default 'AWS KMS key deleted or scheduled for deletion'."
        ),
        "datadog_query": (
            "source:cloudtrail @evt.outcome:success\n"
            "@evt.name:(ScheduleKeyDeletion OR DisableKey OR DeleteAlias)"
        ),
    },
    {
        "id": "UC_DDOG_AWS_S3_BUCKET_PUBLIC",
        "kill_chain": "actions",
        "title": "AWS S3 bucket ACL / policy made public",
        "confidence": "High", "tier": "alerting", "fp_rate": "low",
        "mitre": [("T1537", "Transfer Data to Cloud Account"), ("T1190", "Exploit Public-Facing Application")],
        "description": (
            "S3 bucket ACL or policy modified to allow access from AllUsers / "
            "AllAuthenticatedUsers, or PublicAccessBlock removed. Either misconfig or "
            "intentional data-exposure prep. Datadog default 'AWS S3 Bucket ACL made public'."
        ),
        "datadog_query": (
            "source:cloudtrail @evt.outcome:success\n"
            "@evt.name:(PutBucketAcl OR PutBucketPolicy OR DeletePublicAccessBlock OR DeleteBucketPolicy)\n"
            "(@requestParameters.AccessControlPolicy.AccessControlList.Grant.Grantee.URI:*AllUsers* "
            "OR @requestParameters.AccessControlPolicy.AccessControlList.Grant.Grantee.URI:*AllAuthenticatedUsers*)"
        ),
    },
    {
        "id": "UC_DDOG_GITHUB_PAT_MASS_CLONE",
        "kill_chain": "actions",
        "title": "GitHub personal access token cloning many repositories",
        "confidence": "Medium", "tier": "alerting", "fp_rate": "medium",
        "mitre": [("T1555", "Credentials from Password Stores"), ("T1552", "Unsecured Credentials")],
        "description": (
            "PAT used to clone an unusual number of repositories — credential theft + "
            "source-code exfil. Datadog default 'GitHub personal access token used to clone repositories'."
        ),
        "datadog_query": (
            "source:github @evt.name:git.clone @actor.type:PAT"
        ),
    },
    {
        "id": "UC_DDOG_DATA_EXFIL_SUCCESSFUL",
        "kill_chain": "actions",
        "title": "Application data exfiltration successful",
        "confidence": "High", "tier": "alerting", "fp_rate": "low",
        "mitre": [("T1041", "Exfiltration Over C2 Channel"), ("T1567", "Exfiltration Over Web Service")],
        "description": (
            "Application telemetry showing a large-volume / sensitive-attribute response served "
            "to an external endpoint — data exfil. Datadog default 'Data exfiltration successful'."
        ),
        "datadog_query": (
            "source:application_logs @evt.name:data_export @evt.outcome:success\n"
            "-@network.client.geoip.country.iso_code:<your-business-country>"
        ),
    },
    {
        "id": "UC_DDOG_API_RESOURCE_ABUSE",
        "kill_chain": "actions",
        "title": "Excessive resource consumption of third-party API",
        "confidence": "Medium", "tier": "hunting", "fp_rate": "medium",
        "mitre": [("T1496", "Resource Hijacking"), ("T1190", "Exploit Public-Facing Application")],
        "description": (
            "Abnormal request volume to a third-party API endpoint — resource abuse, scraping, "
            "or DoS-staging behaviour. Datadog default 'Excessive resource consumption of third-party API'."
        ),
        "datadog_query": (
            "source:application_logs @http.url_details.host:* "
            "-@http.url_details.host:(*your-domain*)"
        ),
    },
]


def _yaml_quote(s: str) -> str:
    """Render a multi-line string as a YAML literal block scalar."""
    if "\n" in s:
        lines = s.split("\n")
        return "|-\n  " + "\n  ".join(lines)
    if s and (s[0] in '!&*[]{}>|"\'%@`#?,' or ':' in s or '#' in s):
        # Safer to single-quote
        esc = s.replace("'", "''")
        return f"'{esc}'"
    return s


def _yaml_block_scalar(s: str, indent: int = 0) -> str:
    """Render `s` as a YAML literal-block scalar with given indent."""
    pad = "  " * indent
    body = "\n".join(f"{pad}  {line}" for line in s.split("\n"))
    return f"|-\n{body}"


def emit_yaml(row: dict) -> str:
    techs = "\n".join(
        f"- id: {t[0]}\n  name: {t[1]}" for t in row["mitre"]
    )
    body = []
    body.append(f"id: {row['id']}")
    body.append(f"title: {row['title']}")
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
        print(f"  wrote {target.relative_to(ROOT)}")
    print(f"\n{written} written, {skipped} already existed")
    # Quick sanity load
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
