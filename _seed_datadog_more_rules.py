"""Batch 2 of Datadog default-rule UCs. Idempotent — re-run safe; skips
files that already exist. Sourced from
https://docs.datadoghq.com/security/default_rules/ — detection-style
rules only (no CSPM / posture-baseline rules).

Run:
    python _seed_datadog_more_rules.py
"""
from __future__ import annotations
import sys
from pathlib import Path

ROOT = Path(__file__).parent
UC_DIR = ROOT / "use_cases"

# Compact builder: (id_suffix, kill_chain, title, mitre_pairs, datadog_query, description)
# id is auto-prefixed with UC_DDOG_. Confidence/tier/fp_rate use sensible defaults.

def R(id_suffix, kc, title, mitre, dq, desc, *,
      confidence="High", tier="alerting", fp="low"):
    return {
        "id": "UC_DDOG_" + id_suffix,
        "kill_chain": kc, "title": title,
        "confidence": confidence, "tier": tier, "fp_rate": fp,
        "mitre": mitre, "description": desc, "datadog_query": dq,
    }


ROWS: list[dict] = [
    # ---------- AWS CloudTrail (defense evasion / config tampering) ----------
    R("AWS_CLOUDTRAIL_CONFIG_MODIFIED", "install",
      "AWS CloudTrail logging configuration modified",
      [("T1562.008", "Disable or Modify Cloud Logs"), ("T1098", "Account Manipulation")],
      "source:cloudtrail @evt.outcome:success\n"
      "@evt.name:(StopLogging OR DeleteTrail OR UpdateTrail OR PutEventSelectors)",
      "CloudTrail logging stopped, trail deleted, or selectors changed — "
      "blinding the audit pipeline. Datadog default 'AWS CloudTrail configuration modified'."),

    R("AWS_VPC_FLOW_LOG_DELETED", "install",
      "AWS VPC Flow Log deleted",
      [("T1562.008", "Disable or Modify Cloud Logs")],
      "source:cloudtrail @evt.outcome:success @evt.name:DeleteFlowLogs",
      "VPC Flow Logs deleted — adversary erasing network-traffic visibility. "
      "Datadog default 'AWS VPC Flow Log deleted'."),

    R("AWS_GUARDDUTY_DISABLED", "install",
      "AWS GuardDuty detector disabled or deleted",
      [("T1562.001", "Disable or Modify Tools")],
      "source:cloudtrail @evt.outcome:success\n"
      "@evt.name:(DeleteDetector OR DisableOrganizationAdminAccount OR UpdateDetector)\n"
      "@requestParameters.enable:false",
      "GuardDuty turned off — defenders' main AWS-native threat detection silenced. "
      "Datadog default 'AWS GuardDuty detector disabled'."),

    R("AWS_CONFIG_MODIFIED", "install",
      "AWS Config service modified or stopped",
      [("T1562.008", "Disable or Modify Cloud Logs")],
      "source:cloudtrail @evt.outcome:success\n"
      "@evt.name:(StopConfigurationRecorder OR DeleteConfigurationRecorder "
      "OR DeleteDeliveryChannel OR PutConfigurationRecorder)",
      "AWS Config recorder stopped or deleted — compliance trail blinded. "
      "Datadog default 'AWS Config modified'."),

    R("AWS_SECURITYHUB_DISABLED", "install",
      "AWS SecurityHub disabled",
      [("T1562.001", "Disable or Modify Tools")],
      "source:cloudtrail @evt.outcome:success @evt.name:DisableSecurityHub",
      "SecurityHub turned off — aggregated AWS findings silenced. "
      "Datadog default 'AWS SecurityHub disabled'."),

    R("AWS_S3_BUCKET_POLICY_MODIFIED", "install",
      "AWS S3 bucket policy modified",
      [("T1098", "Account Manipulation")],
      "source:cloudtrail @evt.outcome:success\n"
      "@evt.name:(PutBucketPolicy OR DeleteBucketPolicy)",
      "S3 bucket access policy changed — pivot to find adversary granting "
      "themselves read or write. Datadog default 'AWS S3 bucket policy modified'."),

    R("AWS_LAMBDA_MODIFIED", "install",
      "AWS Lambda function code or configuration modified",
      [("T1648", "Serverless Execution"), ("T1098", "Account Manipulation")],
      "source:cloudtrail @evt.outcome:success\n"
      "@evt.name:(UpdateFunctionCode OR UpdateFunctionConfiguration "
      "OR PutFunctionConcurrency OR AddPermission)",
      "Lambda function code/config changed — adversary persistence via "
      "serverless backdoor. Datadog default 'AWS Lambda function modified'."),

    R("AWS_EC2_SECGROUP_MODIFIED", "install",
      "AWS EC2 security group rules modified",
      [("T1098", "Account Manipulation")],
      "source:cloudtrail @evt.outcome:success\n"
      "@evt.name:(AuthorizeSecurityGroupIngress OR AuthorizeSecurityGroupEgress "
      "OR ModifySecurityGroupRules OR RevokeSecurityGroupIngress)",
      "EC2 security-group rules changed — adversary opening a path or "
      "covering tracks. Datadog default 'AWS EC2 security group modified'."),

    R("AWS_IAM_POLICY_MODIFIED", "install",
      "AWS IAM policy created / updated / version changed",
      [("T1098.003", "Additional Cloud Roles")],
      "source:cloudtrail @evt.outcome:success\n"
      "@evt.name:(CreatePolicy OR CreatePolicyVersion OR SetDefaultPolicyVersion "
      "OR PutUserPolicy OR PutRolePolicy OR PutGroupPolicy)",
      "IAM policy added or version changed — privilege drift. "
      "Datadog default 'AWS IAM policy modified'."),

    R("AWS_ACCESS_KEY_CREATED_ANOMALY", "actions",
      "AWS access key created (programmatic credential)",
      [("T1136.003", "Cloud Account"), ("T1098", "Account Manipulation")],
      "source:cloudtrail @evt.outcome:success @evt.name:CreateAccessKey\n"
      "-@userIdentity.userName:(*ci-* OR *terraform-* OR *automation*)",
      "New IAM access key created — long-lived credential issued, watch for "
      "abuse. Datadog default 'AWS access key creation by unusual principal'."),

    R("AWS_RDS_CLUSTER_DELETED", "actions",
      "AWS RDS DB cluster deleted",
      [("T1485", "Data Destruction")],
      "source:cloudtrail @evt.outcome:success\n"
      "@evt.name:(DeleteDBCluster OR DeleteDBInstance)\n"
      "-@requestParameters.skipFinalSnapshot:false",
      "RDS DB cluster or instance deleted — destructive impact. "
      "Datadog default 'AWS RDS cluster deleted'."),

    R("AWS_ECS_CLUSTER_DELETED", "actions",
      "AWS ECS cluster deleted",
      [("T1485", "Data Destruction")],
      "source:cloudtrail @evt.outcome:success @evt.name:DeleteCluster",
      "ECS cluster removed — workload impact. "
      "Datadog default 'AWS ECS cluster deleted'."),

    R("AWS_IAM_IMPOSSIBLE_TRAVEL", "delivery",
      "Impossible travel observed for IAM user",
      [("T1078.004", "Cloud Accounts")],
      "source:cloudtrail @userIdentity.type:IAMUser @evt.outcome:success\n"
      "@network.client.geoip.country.iso_code:*",
      "IAM user activity from geographically distant locations within an "
      "impossible-travel window. Datadog default 'Impossible travel observed on IAM user'."),

    # ---------- Azure (defense evasion / privilege drift) ----------
    R("AZURE_DIAGNOSTIC_SETTING_DELETED", "install",
      "Azure diagnostic setting deleted",
      [("T1562.008", "Disable or Modify Cloud Logs")],
      "source:azure.activity_logs\n"
      "@operationName.value:Microsoft.Insights/diagnosticSettings/delete\n"
      "@properties.activityStatusValue:Succeeded",
      "Azure diagnostic-setting deletion blinds activity-log forwarding to "
      "SIEM. Datadog default 'Azure diagnostic setting deleted'."),

    R("AZURE_KEYVAULT_KEYS_ACCESSED", "actions",
      "Azure Key Vault keys / secrets read",
      [("T1555.005", "Password Managers"), ("T1552.001", "Credentials In Files")],
      "source:azure.activity_logs\n"
      "@operationName.value:(Microsoft.KeyVault/vaults/keys/read OR "
      "Microsoft.KeyVault/vaults/secrets/read)\n"
      "@properties.activityStatusValue:Succeeded",
      "Key Vault secret/key reads — pivot for credential-theft tradecraft. "
      "Datadog default 'Azure Key Vault access keys viewed'."),

    R("AZURE_STORAGE_SOFT_DELETE_DISABLED", "actions",
      "Azure storage soft-delete disabled",
      [("T1485", "Data Destruction"), ("T1490", "Inhibit System Recovery")],
      "source:azure.activity_logs\n"
      "@operationName.value:Microsoft.Storage/storageAccounts/blobServices/write\n"
      "@properties.responseBody:*\"deleteRetentionPolicy\":{\"enabled\":false*",
      "Soft-delete turned off — adversary preparing to destroy blobs without "
      "recovery. Datadog default 'Azure storage account soft delete disabled'."),

    R("AZURE_SP_OWNER_ADDED", "install",
      "Azure new owner added to service principal",
      [("T1098", "Account Manipulation")],
      "source:azure.activeDirectory\n"
      "@evt.name:\"Add owner to service principal\"",
      "Service-principal ownership change — adversary getting persistent "
      "control of an app identity. Datadog default 'Azure new owner added to service principal'."),

    R("AZURE_SQL_FW_RULE_CREATED", "install",
      "Azure SQL Server firewall rule created",
      [("T1098", "Account Manipulation")],
      "source:azure.activity_logs\n"
      "@operationName.value:Microsoft.Sql/servers/firewallRules/write\n"
      "@properties.activityStatusValue:Succeeded",
      "Azure SQL firewall rule added — opening DB to a new IP range. "
      "Datadog default 'Azure SQL Server Firewall rule created'."),

    R("AZURE_USER_ADDED_ADMIN_GROUP", "install",
      "Azure user added to administrative group",
      [("T1098", "Account Manipulation")],
      "source:azure.activeDirectory\n"
      "@evt.name:\"Add member to group\"\n"
      "@properties.targetResources.modifiedProperties.newValue:*Admin*",
      "User joined an Azure admin group — privilege escalation path. "
      "Datadog default 'Azure user added to administrative group'."),

    # ---------- GCP audit ----------
    R("GCP_SVC_ACCT_KEY_CREATED", "actions",
      "GCP service-account key created",
      [("T1136.003", "Cloud Account"), ("T1552", "Unsecured Credentials")],
      "source:gcp.audit\n"
      "@protoPayload.methodName:google.iam.admin.v1.CreateServiceAccountKey",
      "New SA key issued — long-lived credential exfil risk. "
      "Datadog default 'GCP Service Account key created'."),

    R("GCP_IAM_ROLE_CREATED", "install",
      "GCP custom IAM role created",
      [("T1098", "Account Manipulation")],
      "source:gcp.audit\n"
      "@protoPayload.methodName:google.iam.admin.v1.CreateRole",
      "Custom GCP IAM role defined — pivot for hidden-privilege grants. "
      "Datadog default 'GCP IAM role created'."),

    R("GCP_EXTERNAL_OWNER_ADDED", "install",
      "GCP project external principal added as owner",
      [("T1098", "Account Manipulation")],
      "source:gcp.audit @protoPayload.methodName:(SetIamPolicy OR setIamPolicy)\n"
      "@protoPayload.serviceData.policyDelta.bindingDeltas.role:roles/owner\n"
      "@protoPayload.serviceData.policyDelta.bindingDeltas.member:user:*",
      "External email granted project ownership — direct full-takeover risk. "
      "Datadog default 'GCP project external principal added as owner'."),

    R("GCP_FIREWALL_RULE_MODIFIED", "install",
      "GCP Compute Engine firewall rule modified",
      [("T1098", "Account Manipulation")],
      "source:gcp.audit\n"
      "@protoPayload.methodName:(beta.compute.firewalls.insert OR v1.compute.firewalls.patch OR v1.compute.firewalls.delete)",
      "VPC firewall rule changed — adversary opening or covering a path. "
      "Datadog default 'GCP Compute Engine firewall rule modified'."),

    R("GCP_LOGGING_BUCKET_DELETED", "install",
      "GCP Cloud Logging bucket deleted",
      [("T1562.008", "Disable or Modify Cloud Logs")],
      "source:gcp.audit\n"
      "@protoPayload.methodName:google.logging.v2.ConfigServiceV2.DeleteBucket",
      "Cloud Logging bucket removed — audit trail destroyed. "
      "Datadog default 'GCP Logging Bucket deleted'."),

    R("GCP_LOGGING_SINK_MODIFIED", "install",
      "GCP Cloud Logging sink modified",
      [("T1562.008", "Disable or Modify Cloud Logs")],
      "source:gcp.audit\n"
      "@protoPayload.methodName:google.logging.v2.ConfigServiceV2.UpdateSink",
      "Cloud Logging sink redirected — adversary cutting off log forwarding. "
      "Datadog default 'GCP logging sink modified'."),

    R("GCP_STORAGE_PERMS_MODIFIED", "install",
      "GCP Cloud Storage bucket permissions modified",
      [("T1098", "Account Manipulation")],
      "source:gcp.audit @protoPayload.methodName:storage.setIamPermissions",
      "GCS bucket IAM changed — possible public exposure. "
      "Datadog default 'GCP Cloud Storage bucket permissions modified'."),

    # ---------- Kubernetes ----------
    R("K8S_RBAC_BINDING_CREATED", "install",
      "Kubernetes RBAC role binding created",
      [("T1098", "Account Manipulation")],
      "source:kubernetes.audit @verb:create\n"
      "@objectRef.resource:(rolebindings OR clusterrolebindings)",
      "RBAC binding added — privilege drift inside the cluster. "
      "Datadog default 'Kubernetes RBAC role binding created'."),

    R("K8S_SECRET_ACCESSED", "actions",
      "Kubernetes Secret accessed",
      [("T1552.007", "Container API"), ("T1555", "Credentials from Password Stores")],
      "source:kubernetes.audit @verb:get @objectRef.resource:secrets\n"
      "-@user.username:(system:serviceaccount:* OR system:apiserver)",
      "Secret read by a non-system principal — credential-theft signal. "
      "Datadog default 'Kubernetes secret accessed'."),

    R("K8S_PRIVILEGED_POD_CREATED", "install",
      "Kubernetes pod created with privileged flag",
      [("T1611", "Escape to Host"), ("T1548", "Abuse Elevation Control Mechanism")],
      "source:kubernetes.audit @verb:create @objectRef.resource:pods\n"
      "@requestObject.spec.containers.securityContext.privileged:true",
      "Privileged pod — direct host-takeover primitive. "
      "Datadog default 'Kubernetes pod executed with privileged flag'."),

    R("K8S_CLUSTER_ROLE_DELETED", "install",
      "Kubernetes ClusterRole / binding deleted",
      [("T1531", "Account Access Removal"), ("T1098", "Account Manipulation")],
      "source:kubernetes.audit @verb:delete\n"
      "@objectRef.resource:(clusterroles OR clusterrolebindings)",
      "ClusterRole / binding removed — defenders losing access or adversary "
      "covering tracks. Datadog default 'Kubernetes ClusterRole binding deleted'."),

    R("K8S_WEBHOOK_MODIFIED", "install",
      "Kubernetes admission webhook configuration modified",
      [("T1554", "Compromise Host Software Binary"), ("T1098", "Account Manipulation")],
      "source:kubernetes.audit @verb:(create OR update OR patch)\n"
      "@objectRef.resource:(mutatingwebhookconfigurations OR validatingwebhookconfigurations)",
      "Admission webhook changed — adversary inserting cluster-wide "
      "interception. Datadog default 'Kubernetes webhook configuration modified'."),

    # ---------- Okta ----------
    R("OKTA_USER_LOCKED", "delivery",
      "Okta user account locked",
      [("T1110.003", "Password Spraying")],
      "source:okta @evt.name:user.account.lock",
      "Okta user lockout — credential-spray indicator (and a paste-target "
      "for IP / target lists). Datadog default 'Okta user account locked'."),

    R("OKTA_MFA_BYPASS", "delivery",
      "Okta MFA bypass attempt",
      [("T1556", "Modify Authentication Process")],
      "source:okta @outcome.reason:*MFA*\n"
      "@evt.name:(user.authentication.auth_via_mfa OR user.session.start)\n"
      "@outcome.result:FAILURE",
      "MFA challenge failed in a way that suggests a bypass attempt. "
      "Datadog default 'Okta MFA bypass attempt'."),

    R("OKTA_ADMIN_ROLE_ASSIGNED", "install",
      "Okta administrative role assigned to user",
      [("T1098", "Account Manipulation")],
      "source:okta @evt.name:user.account.privilege.grant",
      "User gets an Okta admin role — privilege drift. "
      "Datadog default 'Okta administrative role assigned'."),

    R("OKTA_AUTH_POLICY_MODIFIED", "install",
      "Okta authentication / sign-on policy modified",
      [("T1556", "Modify Authentication Process")],
      "source:okta @evt.name:(policy.lifecycle.update OR policy.rule.update OR policy.lifecycle.delete)",
      "Auth policy / rule changed — adversary lowering the auth bar. "
      "Datadog default 'Okta authentication policy modified'."),

    R("OKTA_APP_ACCESS_GRANTED", "install",
      "Okta application access granted to user",
      [("T1098", "Account Manipulation")],
      "source:okta @evt.name:application.user_membership.add",
      "User added to an Okta-mediated app — pivot for entitlement audits. "
      "Datadog default 'Okta application access granted'."),

    # ---------- GitHub ----------
    R("GITHUB_PAT_CREATED", "actions",
      "GitHub personal access token created",
      [("T1136", "Create Account"), ("T1552", "Unsecured Credentials")],
      "source:github @evt.name:personal_access_token.access_granted",
      "New PAT issued — long-lived credential watch-list. "
      "Datadog default 'GitHub personal access token created'."),

    R("GITHUB_REPO_TRANSFER", "actions",
      "GitHub repository transfer initiated",
      [("T1098", "Account Manipulation"), ("T1537", "Transfer Data to Cloud Account")],
      "source:github @evt.name:(repo.transfer OR repo.transfer_outgoing OR repo.transfer_start)",
      "Repo transferred to another owner — IP-leak path. "
      "Datadog default 'GitHub repository transfer initiated'."),

    R("GITHUB_ORG_REMOVED_ENTERPRISE", "install",
      "GitHub organization removed from enterprise",
      [("T1098", "Account Manipulation")],
      "source:github @evt.name:enterprise.remove_organization",
      "Org dropped out of enterprise scope — admin oversight loss. "
      "Datadog default 'GitHub organization removed from enterprise'."),

    R("GITHUB_SECRET_SCANNING_DISABLED", "install",
      "GitHub secret scanning disabled",
      [("T1562.001", "Disable or Modify Tools")],
      "source:github @evt.name:(repository_secret_scanning.disable OR org.secret_scanning_disable)",
      "Secret-scanning turned off — credentials in code go un-flagged. "
      "Datadog default 'GitHub secret scanning disabled'."),

    R("GITHUB_REPO_PUBLIC", "actions",
      "GitHub repository visibility changed to public",
      [("T1538", "Cloud Service Dashboard"), ("T1213.003", "Code Repositories")],
      "source:github @evt.name:repo.access\n"
      "@target.visibility:public",
      "Private repo flipped to public — unintentional or intentional source-"
      "code exposure. Datadog default 'GitHub repository visibility changed to public'."),

    R("GITHUB_MFA_DISABLED", "install",
      "GitHub organization 2FA requirement removed",
      [("T1556", "Modify Authentication Process")],
      "source:github @evt.name:(org.disable_two_factor_requirement OR org.update_two_factor_requirement)",
      "Org-wide 2FA requirement removed — auth bar lowered. "
      "Datadog default 'GitHub MFA requirement disabled'."),

    # ---------- GitLab ----------
    R("GITLAB_PASSWORD_RESET_SUSPICIOUS", "delivery",
      "GitLab password reset from suspicious IP",
      [("T1078", "Valid Accounts"), ("T1556", "Modify Authentication Process")],
      "source:gitlab @evt.name:user.password_reset",
      "Password reset event — investigate alongside originating IP / geo. "
      "Datadog default 'GitLab password reset from suspicious IP'."),

    R("GITLAB_ADMIN_ADDED", "install",
      "GitLab administrator role granted",
      [("T1098", "Account Manipulation")],
      "source:gitlab @evt.name:(user.access_level_changed OR admin.added)\n"
      "@target.access_level:admin",
      "User gained admin on GitLab tenant. "
      "Datadog default 'GitLab administrator added'."),

    R("GITLAB_GROUP_PUBLIC", "actions",
      "GitLab group visibility changed to public",
      [("T1538", "Cloud Service Dashboard")],
      "source:gitlab @evt.name:group.update @target.visibility:public",
      "Private GitLab group flipped to public — exposure. "
      "Datadog default 'GitLab group visibility changed to public'."),

    R("GITLAB_PAT_GENERATED", "actions",
      "GitLab personal access token generated",
      [("T1136", "Create Account")],
      "source:gitlab @evt.name:user.token.create",
      "New GitLab PAT issued — credential watch-list. "
      "Datadog default 'GitLab personal access token generated'."),

    R("GITLAB_SSO_DISABLED", "install",
      "GitLab SSO disabled",
      [("T1556", "Modify Authentication Process")],
      "source:gitlab @evt.name:application_setting.update\n"
      "@change:sso_enabled @target.value:false",
      "SSO turned off — auth fallback to local creds. "
      "Datadog default 'GitLab SSO disabled'."),

    # ---------- Snowflake ----------
    R("SNOWFLAKE_ROLE_CREATED", "install",
      "Snowflake role created",
      [("T1098", "Account Manipulation")],
      "source:snowflake @evt.name:CREATE_ROLE",
      "New Snowflake role defined — privilege drift in the warehouse. "
      "Datadog default 'Snowflake role created'."),

    R("SNOWFLAKE_USER_ROLE_ADDED", "install",
      "Snowflake user added to role",
      [("T1098", "Account Manipulation")],
      "source:snowflake @evt.name:GRANT_ROLE",
      "User got new role — entitlement audit. "
      "Datadog default 'Snowflake user added to role'."),

    R("SNOWFLAKE_SHARE_MODIFIED", "actions",
      "Snowflake share created or modified",
      [("T1537", "Transfer Data to Cloud Account")],
      "source:snowflake @evt.name:(CREATE_SHARE OR ALTER_SHARE OR ADD_ACCOUNTS_TO_SHARE)",
      "Cross-account data share opened — direct data-exfil primitive. "
      "Datadog default 'Snowflake share created or modified'."),

    # ---------- Microsoft 365 ----------
    R("M365_ADMIN_ROLE_ASSIGNED", "install",
      "M365 admin role assigned to user",
      [("T1098", "Account Manipulation")],
      "source:m365 @evt.name:\"Add member to role\"\n"
      "@properties.targetResources.modifiedProperties.newValue:*Administrator*",
      "User became an M365 admin — privilege drift. "
      "Datadog default 'M365 admin role assigned'."),

    R("M365_MFA_DISABLED", "install",
      "M365 MFA disabled for a user",
      [("T1556", "Modify Authentication Process")],
      "source:m365 @evt.name:(\"Disable Strong Authentication\" OR \"Update user\")\n"
      "@properties.targetResources.modifiedProperties.displayName:StrongAuthenticationRequirement",
      "MFA removed — adversary auth-bar lowering. "
      "Datadog default 'M365 MFA disabled'."),

    R("M365_MAILBOX_DELEGATION", "install",
      "M365 mailbox delegation granted",
      [("T1098.002", "Additional Email Delegate Permissions")],
      "source:m365 @evt.name:(\"Add-MailboxPermission\" OR \"Add-RecipientPermission\")",
      "Inbox delegation — adversary inbox-rule pre-staging. "
      "Datadog default 'M365 mailbox delegation granted'."),

    R("M365_FORWARDING_RULE", "actions",
      "M365 mail-forwarding rule created",
      [("T1114.003", "Email Forwarding Rule")],
      "source:m365 @evt.name:(\"New-InboxRule\" OR \"Set-InboxRule\")\n"
      "@properties.parameters.forwardTo:*",
      "Auto-forward rule — classic adversary exfil persistence. "
      "Datadog default 'M365 forwarding rule created'."),

    # ---------- MongoDB ----------
    R("MONGODB_USER_PRIVESCAL", "install",
      "MongoDB user role escalated",
      [("T1098", "Account Manipulation")],
      "source:mongodb @evt.name:(grantRolesToUser OR updateUser)",
      "DB user got a higher role — privilege drift. "
      "Datadog default 'MongoDB user privilege escalated'."),

    R("MONGODB_AUTH_DISABLED", "install",
      "MongoDB authentication disabled",
      [("T1556", "Modify Authentication Process")],
      "source:mongodb @evt.name:setParameter\n"
      "@params.authenticationMechanisms:*disabled*",
      "MongoDB auth turned off — anyone can connect. "
      "Datadog default 'MongoDB authentication disabled'."),

    R("MONGODB_DB_DELETED", "actions",
      "MongoDB database dropped",
      [("T1485", "Data Destruction")],
      "source:mongodb @evt.name:dropDatabase",
      "DB dropped — destructive event. "
      "Datadog default 'MongoDB database deleted'."),

    R("MONGODB_USER_CREATED", "install",
      "MongoDB user created",
      [("T1136", "Create Account")],
      "source:mongodb @evt.name:createUser",
      "New DB user — pivot for legitimacy review. "
      "Datadog default 'MongoDB user created'."),

    # ---------- Postgres ----------
    R("POSTGRES_SUPERUSER_CREATED", "install",
      "PostgreSQL superuser role created",
      [("T1098", "Account Manipulation")],
      "source:postgres @evt.name:CREATE_ROLE @params.superuser:true",
      "Superuser role created — DBA-level privilege drift. "
      "Datadog default 'PostgreSQL role created with superuser'."),

    R("POSTGRES_DB_DELETED", "actions",
      "PostgreSQL database dropped",
      [("T1485", "Data Destruction")],
      "source:postgres @evt.name:DROP_DATABASE",
      "DB dropped — destructive event. "
      "Datadog default 'PostgreSQL database deleted'."),

    R("POSTGRES_AUTH_MODIFIED", "install",
      "PostgreSQL authentication method modified",
      [("T1556", "Modify Authentication Process")],
      "source:postgres @evt.name:(pg_hba_reload OR ALTER_SYSTEM)\n"
      "@params.parameter:(authentication OR password_encryption OR ssl)",
      "pg_hba reload or auth setting change — bar lowering. "
      "Datadog default 'PostgreSQL authentication method modified'."),

    # ---------- Datadog itself (audit) ----------
    R("DATADOG_AUDIT_DISABLED", "install",
      "Datadog audit trail disabled",
      [("T1562.008", "Disable or Modify Cloud Logs")],
      "source:audit @evt.name:audit_logs.update\n"
      "@properties.audit_logs_enabled:false",
      "Datadog's own audit logging turned off — meta-blinding. "
      "Datadog default 'Datadog audit trail disabled'."),

    R("DATADOG_DASHBOARD_PUBLIC", "actions",
      "Datadog dashboard made publicly accessible",
      [("T1538", "Cloud Service Dashboard")],
      "source:audit @evt.name:dashboard.publish_externally",
      "Dashboard exposed publicly — possible PII or token leakage. "
      "Datadog default 'Datadog dashboard made publicly accessible'."),

    R("DATADOG_LOGIN_METHOD_CHANGED", "install",
      "Datadog organization login method changed",
      [("T1556", "Modify Authentication Process")],
      "source:audit @evt.name:(saml.update OR saml.disable OR org.login.update)",
      "Org SSO/SAML setting changed — auth-flow tampering. "
      "Datadog default 'Datadog organization login method changed'."),

    R("DATADOG_SECURITY_RULE_MODIFIED", "install",
      "Datadog security notification rule modified or deleted",
      [("T1562", "Impair Defenses")],
      "source:audit @evt.name:(security_monitoring_rule.delete OR security_monitoring_rule.update)",
      "SIEM rule edited or deleted in Datadog — defender losing detection. "
      "Datadog default 'Datadog security notification rule modified or deleted'."),

    # ---------- 1Password ----------
    R("1PASSWORD_TOR_ACTIVITY", "delivery",
      "1Password activity from Tor exit node",
      [("T1090.003", "Multi-hop Proxy")],
      "source:1password @network.client.ip_category:tor",
      "1Password access from Tor — credential-vault foreign-source flag. "
      "Datadog default '1Password activity observed from Tor client IP'."),

    R("1PASSWORD_VAULT_EXPORT", "actions",
      "1Password vault export attempted",
      [("T1537", "Transfer Data to Cloud Account"), ("T1555", "Credentials from Password Stores")],
      "source:1password @evt.name:export.vault",
      "Vault export — bulk credential exfil. "
      "Datadog default '1Password vault export attempt by user'."),

    R("1PASSWORD_FAILED_SIGNIN_BURST", "delivery",
      "1Password failed sign-in burst",
      [("T1110", "Brute Force")],
      "source:1password @evt.name:auth.signin @outcome.result:FAILURE",
      "Failed 1Password logins — credential spray indicator. "
      "Datadog default 'Anomalous amount of failed sign-in attempts by 1Password user'."),

    R("1PASSWORD_ITEM_EXFIL_ATTEMPT", "actions",
      "1Password item exfiltration attempt",
      [("T1555", "Credentials from Password Stores")],
      "source:1password @evt.name:item.exfiltrate",
      "Suspicious item-level access — credential-theft pattern. "
      "Datadog default 'Attempt to exfiltrate a 1Password item by user'."),

    R("1PASSWORD_IMPOSSIBLE_TRAVEL", "delivery",
      "1Password impossible-travel sign-in",
      [("T1078", "Valid Accounts"), ("T1550", "Use Alternate Authentication Material")],
      "source:1password @evt.name:auth.signin @outcome.result:SUCCESS",
      "Geographically impossible 1Password sign-in. "
      "Datadog default 'Impossible travel event observed from 1Password user'."),

    # ---------- Misc / runtime / network ----------
    R("CONTAINER_ESCAPE_ATTEMPT", "install",
      "Container escape attempt detected",
      [("T1611", "Escape to Host")],
      "source:runtime-security @evt.category:container_escape",
      "Process tried to break out of container isolation — direct host-"
      "compromise primitive. Datadog default 'Container escape attempt detected'."),

    R("APP_USER_TOR", "delivery",
      "Application user activity from Tor",
      [("T1090.003", "Multi-hop Proxy")],
      "source:application-threats @evt.name:user.tor_activity",
      "App-side activity from Tor exit — anonymisation flag. "
      "Datadog default 'User activity from Tor'."),

    R("APP_LFI_EXPLOITED", "delivery",
      "Local File Inclusion (LFI) exploited",
      [("T1190", "Exploit Public-Facing Application")],
      "source:waf_logs @rule.tags:lfi @http.status_code:[200 TO 299]",
      "LFI WAF rule fired with 2xx response — successful file read. "
      "Datadog default 'Local file inclusion exploited'."),

    R("APP_SPRING4SHELL_RCE", "delivery",
      "Spring4Shell RCE attempts (CVE-2022-22963)",
      [("T1190", "Exploit Public-Facing Application"), ("T1059", "Command and Scripting Interpreter")],
      "source:waf_logs @rule.tags:(spring4shell OR cve_2022_22963 OR cve_2022_22965)",
      "Spring4Shell exploitation attempts. "
      "Datadog default 'Spring4shell RCE attempts - CVE-2022-22963'."),

    R("APP_JWT_BYPASS_ATTEMPT", "delivery",
      "JWT authentication bypass attempt",
      [("T1190", "Exploit Public-Facing Application"), ("T1556", "Modify Authentication Process")],
      "source:waf_logs @rule.tags:(jwt OR jwt_bypass OR none_alg)",
      "JWT manipulation / none-alg / kid-abuse signatures. "
      "Datadog default 'JWT authentication bypass attempt'."),
]


def _yaml_block_scalar(s: str, indent: int = 0) -> str:
    pad = "  " * indent
    body = "\n".join(f"{pad}  {line}" for line in s.split("\n"))
    return f"|-\n{body}"


def emit_yaml(row: dict) -> str:
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
    print(f"\n{written} written, {skipped} already existed (out of {len(ROWS)})")
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
