# AWS CloudWatch Logs Insights — query syntax + CloudTrail field reference

Concise reference for the `cloudwatch_query` field on every UC.

## Query language at a glance

```
fields <field>, <field>, ...
| filter <predicate>
| stats <agg> by <field>
| sort <field> [desc|asc]
| limit <n>
```

Pipeline operators: `fields`, `filter`, `stats`, `sort`, `limit`, `parse`, `display`, `dedup`. Each line that follows the opening stage starts with `|`. Comments use `#` (operators substitute the actual log-group name via a leading comment).

## Syntax essentials

- **String comparison**: `eventName = "ConsoleLogin"`, case-sensitive. No `=~`.
- **Set membership**: `eventName in ["StopLogging", "DeleteTrail"]` — square brackets, comma-separated quoted strings.
- **Regex match**: `userIdentity.userName like /admin/i` — slashes + optional trailing `i` for case-insensitive. CWLI regex is a subset of PCRE.
- **Null / presence**: prefer `not isPresent(errorCode)` over `errorCode = null`. CloudTrail returns `errorCode` only on failures, so absence means success.
- **Boolean operators**: lowercase `and`, `or`, `not` (unlike Datadog which requires uppercase).
- **Wildcards inside regex** work normally; `eventName = "Get*"` does NOT — use `eventName like /^Get/` instead.
- **Nested paths** use dots: `userIdentity.sessionContext.attributes.mfaAuthenticated`. CWLI auto-flattens JSON.
- **Aggregations**: `stats count(*) as events, sum(if(eventName="ConsoleLogin",1,0)) as logins by sourceIPAddress`.
- **Functions in fields/filters**: `if(x,y,z)`, `coalesce(a,b)`, `concat(a,b)`, `strlen(s)`, `tomillis(@timestamp)`, `bin(5m)` for time bucketing.
- **Sort** can take multiple keys: `sort eventTime desc, sourceIPAddress`.

## Standard log groups we target

| Telemetry | Log group | Notes |
|---|---|---|
| CloudTrail management events | `/aws/cloudtrail` | The primary detection surface. Field paths below |
| CloudTrail data events | `/aws/cloudtrail/dataevents` | S3 object-level, Lambda invoke — typically a separate trail |
| VPC Flow Logs | `/aws/vpc/flowlogs` | Network 5-tuple + bytes; no IPs vs hostnames |
| GuardDuty findings | `/aws/guardduty/findings` | Already-tagged threat findings; pivot rather than primary detection |
| Lambda execution | `/aws/lambda/<function-name>` | App-tier signals |

Always lead the query with a `# log group: /aws/cloudtrail` (or the appropriate group) comment so operators know which trail to point this at.

## CloudTrail field reference (the fields you can actually query)

### Top-level
- `eventTime` — ISO timestamp (use `@timestamp` in CWLI queries)
- `eventName` — the API action, e.g. `ConsoleLogin`, `AssumeRole`, `PutBucketPolicy`
- `eventSource` — `iam.amazonaws.com`, `s3.amazonaws.com`, `ec2.amazonaws.com`, etc.
- `eventType` — `AwsApiCall`, `AwsConsoleSignIn`, `AwsServiceEvent`
- `awsRegion` — `us-east-1`, `eu-west-2`, etc.
- `sourceIPAddress` — caller IP or `AWS Internal` for service-to-service
- `userAgent` — `console.amazonaws.com`, `aws-cli/...`, `Boto3/...`
- `errorCode` — present only on failures (`AccessDenied`, `UnauthorizedOperation`)
- `errorMessage` — human-readable failure text (`"Failed authentication"` for failed ConsoleLogin)
- `recipientAccountId` — the AWS account that received the call
- `readOnly` — boolean; `false` for state-changing operations
- `managementEvent` — boolean; distinguishes mgmt vs data events

### userIdentity.* (the caller)
- `userIdentity.type` — `Root`, `IAMUser`, `AssumedRole`, `Federated`, `SAMLUser`, `WebIdentityUser`, `AWSService`, `AWSAccount`
- `userIdentity.userName` — IAM user / federated principal name (absent for AssumedRole — use `sessionContext.sessionIssuer.userName`)
- `userIdentity.arn` — full ARN of the caller
- `userIdentity.principalId` — unique principal ID
- `userIdentity.accountId` — the calling account
- `userIdentity.invokedBy` — present when the call came via another AWS service
- `userIdentity.sessionContext.sessionIssuer.type` — for AssumedRole, the entity that originally assumed the role
- `userIdentity.sessionContext.sessionIssuer.userName` — useful for AssumedRole correlation
- `userIdentity.sessionContext.attributes.mfaAuthenticated` — `"true"` / `"false"` string

### requestParameters.* (what they asked for)
Shape varies per `eventName`. Common ones we use:
- `requestParameters.userName` (CreateUser, AttachUserPolicy)
- `requestParameters.policyArn` (AttachUserPolicy / AttachRolePolicy)
- `requestParameters.bucketName` (S3 ops)
- `requestParameters.name` (Trail/DeliveryChannel/Recorder ops)
- `requestParameters.detectorId` (GuardDuty)
- `requestParameters.enable` (UpdateDetector — `"true"` / `"false"`)
- `requestParameters.keyId` (KMS)
- `requestParameters.aliasName` (KMS aliases)
- `requestParameters.pendingWindowInDays` (ScheduleKeyDeletion)
- `requestParameters.functionName` (Lambda)
- `requestParameters.cluster` (ECS DeleteCluster)
- `requestParameters.dBClusterIdentifier`, `requestParameters.dBInstanceIdentifier` (RDS)
- `requestParameters.skipFinalSnapshot` (RDS — `"true"` is destructive)
- `requestParameters.groupId`, `requestParameters.ipPermissions` (EC2 security groups)
- `requestParameters.FlowLogId` (VPC flow log deletion)

### responseElements.* (what AWS returned)
- `responseElements.ConsoleLogin` — `"Success"` / `"Failure"`
- `responseElements.accessKey.userName` (CreateAccessKey)
- Other paths vary per eventName

### additionalEventData.*
- `additionalEventData.MFAUsed` — `"Yes"` / `"No"` (ConsoleLogin only)
- `additionalEventData.LoginTo` — destination URL on console sign-in

## House style for the `cloudwatch_query` field we emit

- **Always lead with a log-group comment**: `# log group: /aws/cloudtrail` so operators know which trail to point this at.
- **Project useful fields in `fields`** — pick the analyst-relevant ones (`@timestamp, eventName, userIdentity.arn, sourceIPAddress, requestParameters.<the-one-that-matters>`). Don't dump `@message`.
- **Filter for success unless detecting failures**: `not isPresent(errorCode)` is the idiomatic "the action actually happened" check.
- **Prefer `in [...]` over OR-chains** when matching event-name sets.
- **Use `like /regex/i`** for partial matches; avoid wildcards (`*`) which CWLI doesn't expand in string comparisons.
- **End with `sort @timestamp desc`** unless aggregating — gives analysts the most recent hits first.
- **Don't invent fields**. If you need geo-IP or threat-intel enrichment, leave a comment noting the gap rather than inventing `network.client.geoip.*` paths (those are Datadog, not CWLI).
- **Empty string is fine**. If the detection telemetry doesn't naturally live in CloudWatch Logs (Windows endpoint, M365 mailflow, etc.), leave `cloudwatch_query: ""` and don't shoehorn something irrelevant.

## Minimal example

```
# log group: /aws/cloudtrail
fields @timestamp, eventName, sourceIPAddress, userIdentity.userName, additionalEventData.MFAUsed
| filter eventName = "ConsoleLogin"
      and responseElements.ConsoleLogin = "Success"
      and additionalEventData.MFAUsed = "No"
      and userIdentity.userName not like /break-glass/
| sort @timestamp desc
```
