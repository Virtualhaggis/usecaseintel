# [HIGH] 6 big AWS IAM vulnerabilities – and how to avoid them

**Source:** Snyk
**Published:** 2021-11-05
**Article:** https://snyk.io/blog/6-big-aws-iam-vulnerabilities-and-how-to-avoid-them/

## Threat Profile

Snyk Blog In this article
Written by Becki Lee 
November 5, 2021
0 mins read Editor's note This blog originally appeared on fugue.co. Fugue joined Snyk in 2022 and is a key component of Snyk IaC .
What’s a cloud vulnerability? In the simplest terms, it’s an exploitable weakness in a cloud environment. Vulnerabilities are commonly caused by cloud resource misconfigurations and can lead to breaches and security failures — especially when the vulnerability is related to Identity and Access Manageme…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1580** — Cloud Infrastructure Discovery
- **T1526** — Cloud Service Discovery
- **T1530** — Data from Cloud Storage Object
- **T1098** — Account Manipulation
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1098.003** — Account Manipulation: Additional Cloud Roles

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### S3 bucket enumeration fan-out by a single principal (Capital One recon pattern)

`UC_2565_0` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
sourcetype=aws:cloudtrail eventSource="s3.amazonaws.com" (eventName="ListBuckets" OR eventName="ListObjects" OR eventName="ListObjectsV2")
| stats count AS listCalls dc('requestParameters.bucketName') AS bucketsTouched min(_time) AS firstSeen max(_time) AS lastSeen values(eventName) AS apis BY userIdentity.arn sourceIPAddress
| where bucketsTouched>=10 OR listCalls>=50
| sort - bucketsTouched
```

### S3 mass object download / 's3 sync' exfiltration from a single bucket

`UC_2565_1` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
sourcetype=aws:cloudtrail eventSource="s3.amazonaws.com" eventName="GetObject"
| bin _time span=5m
| stats count AS objectReads dc('requestParameters.key') AS distinctObjects BY _time userIdentity.arn 'requestParameters.bucketName' sourceIPAddress
| where objectReads>=500
| sort - objectReads
```

### IAM role trust policy allows all principals (Principal '*' + sts:AssumeRole)

`UC_2565_2` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
sourcetype=aws:cloudtrail eventSource="iam.amazonaws.com" (eventName="CreateRole" OR eventName="UpdateAssumeRolePolicy")
| eval doc=coalesce('requestParameters.policyDocument','requestParameters.assumeRolePolicyDocument')
| where like(doc,"%sts:AssumeRole%") AND (match(doc,"\"Principal\"\s*:\s*\"\*\"") OR match(doc,"\"AWS\"\s*:\s*\"\*\""))
| table _time userIdentity.arn sourceIPAddress requestParameters.roleName doc
| sort - _time
```

### IAM policy grants full administrative '*:*' privileges or attaches AdministratorAccess

`UC_2565_3` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
sourcetype=aws:cloudtrail eventSource="iam.amazonaws.com"
| eval doc=coalesce('requestParameters.policyDocument',"")
| where ((eventName IN ("AttachRolePolicy","AttachUserPolicy","AttachGroupPolicy")) AND like('requestParameters.policyArn',"%AdministratorAccess%")) OR ((eventName IN ("PutRolePolicy","PutUserPolicy","PutGroupPolicy","CreatePolicy")) AND match(doc,"\"Action\"\s*:\s*\"\*\"") AND match(doc,"\"Resource\"\s*:\s*\"\*\""))
| table _time eventName userIdentity.arn sourceIPAddress requestParameters.roleName requestParameters.userName requestParameters.policyArn
| sort - _time
```

### Successful AWS console login without MFA

`UC_2565_4` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
sourcetype=aws:cloudtrail eventName="ConsoleLogin" "responseElements.ConsoleLogin"="Success" "additionalEventData.MFAUsed"="No" userIdentity.type!="AssumedRole"
| table _time userIdentity.type userIdentity.arn userIdentity.userName sourceIPAddress additionalEventData.MFAUsed
| sort - _time
```


## Why this matters

Severity classified as **HIGH** based on: 5 use case(s) fired, 6 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
