# [HIGH] High profile AWS breaches & how to avoid them

**Source:** Snyk
**Published:** 2023-06-07
**Article:** https://snyk.io/blog/aws-security-breaches/

## Threat Profile

Snyk Blog In this article
Written by Jamie Smith 
June 7, 2023
0 mins read A few days before Christmas 2021, employees and clients of appointment scheduling service Flexbooker realized threat actors had taken ten million lines of customer ID information – including photos, driver’s licenses, and hashed passwords . 
Attackers made off with millions of pieces of personally identifiable information (PII) because Flexbooker had misconfigured its AWS account, specifically an AWS S3 bucket that left i…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1530** — Data from Cloud Storage
- **T1552.005** — Unsecured Credentials: Cloud Instance Metadata API
- **T1619** — Cloud Storage Object Discovery
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1537** — Transfer Data to Cloud Account

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### S3 bucket exposed to public via ACL/policy change or Public Access Block removal

`UC_1604_0` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Change.All_Changes where All_Changes.vendor_product="AWS CloudTrail" All_Changes.command IN ("PutBucketAcl","PutBucketPolicy","DeleteBucketPublicAccessBlock","DeletePublicAccessBlock") by All_Changes.user All_Changes.command All_Changes.object All_Changes.src All_Changes.status | `drop_dm_object_name(All_Changes)` | where status="success" | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | sort - lastTime
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where Application == "Amazon Web Services"
| where ActionType in ("PutBucketAcl","PutBucketPolicy","DeleteBucketPublicAccessBlock","DeletePublicAccessBlock")
| project Timestamp, ActionType, Actor=AccountDisplayName, IPAddress, Bucket=ObjectName, RawEventData
| order by Timestamp desc
```

### EC2 instance-role credentials performing S3 recon (Capital One IMDS-SSRF pattern)

`UC_1604_1` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
sourcetype=aws:cloudtrail userIdentity.type=AssumedRole userIdentity.arn="*assumed-role*i-*" (eventName=ListBuckets OR eventName=ListObjects OR eventName=ListObjectsV2 OR eventName=GetBucketAcl OR eventName=DescribeInstances) | stats count as calls values(eventName) as ops min(_time) as firstTime max(_time) as lastTime by userIdentity.arn sourceIPAddress | sort - calls
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where Application == "Amazon Web Services"
| where ActionType in ("ListBuckets","ListObjects","ListObjectsV2","GetBucketAcl","DescribeInstances")
| where RawEventData has "assumed-role" and RawEventData has "/i-"
| summarize Calls=count(), Ops=make_set(ActionType) by IPAddress, Arn=tostring(RawEventData.userIdentity.arn)
| order by Calls desc
```

### RDS DB snapshot shared, copied, restored or exported (Imperva stolen-key pattern)

`UC_1604_2` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Change.All_Changes where All_Changes.vendor_product="AWS CloudTrail" All_Changes.command IN ("ModifyDBSnapshotAttribute","ModifyDBClusterSnapshotAttribute","RestoreDBInstanceFromDBSnapshot","RestoreDBClusterFromSnapshot","CopyDBSnapshot","StartExportTask") by All_Changes.user All_Changes.command All_Changes.object All_Changes.src All_Changes.status | `drop_dm_object_name(All_Changes)` | where status="success" | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | sort - lastTime
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where Application == "Amazon Web Services"
| where ActionType in ("ModifyDBSnapshotAttribute","ModifyDBClusterSnapshotAttribute","RestoreDBInstanceFromDBSnapshot","RestoreDBClusterFromSnapshot","CopyDBSnapshot","StartExportTask")
| project Timestamp, ActionType, Actor=AccountDisplayName, IPAddress, Snapshot=ObjectName, RawEventData
| order by Timestamp desc
```


## Why this matters

Severity classified as **HIGH** based on: 3 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
