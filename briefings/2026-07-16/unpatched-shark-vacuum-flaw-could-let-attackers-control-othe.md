# [HIGH] Unpatched Shark Vacuum Flaw Could Let Attackers Control Other Vacuums Region-Wide

**Source:** The Hacker News
**Published:** 2026-07-16
**Article:** https://thehackernews.com/2026/07/unpatched-shark-vacuum-flaw-could-let.html

## Threat Profile

Unpatched Shark Vacuum Flaw Could Let Attackers Control Other Vacuums Region-Wide 
 Swati Khandelwal  Jul 16, 2026 IoT Security / Vulnerability 
Pull the certificate off the flash of a Shark RV2320EDUS robot vacuum, and you can run root commands on other people's Shark vacuums across the same AWS region: watch the camera, drive the robot, read the map of the house, and take the Wi-Fi password in plaintext.
A researcher publishing under the handle tokay0 put the method online on Monday, having …

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1526** — Cloud Service Discovery
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1059** — Command and Scripting Interpreter
- **T1098** — Account Manipulation

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### AWS IoT wildcard subscribe to $aws/things/# (Shark vacuum serial harvesting)

`UC_5_0` · phase: **recon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
sourcetype="aws:iot" eventType=Subscribe
| search topics="*$aws/things/#*" OR topics="*$aws/things/+*" OR topicName="*$aws/things/#*" OR topicName="*$aws/things/+*"
| stats count min(_time) as firstTime max(_time) as lastTime values(topics) as topics by clientId, principalId, sourceIp
| convert ctime(firstTime) ctime(lastTime)
| sort - count
```

### Single AWS IoT principal publishing shadow updates across many devices (Exec_Command fan-out)

`UC_5_1` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
sourcetype="aws:iot" eventType=Publish topicName="*$aws/things/*/shadow/update"
| rex field=topicName "\$aws/things/(?<targetThing>[^/]+)/shadow/update"
| stats dc(targetThing) as distinctThings count as updates values(sourceIp) as sourceIp by principalId, clientId
| where distinctThings > 5
| sort - distinctThings
```

### Creation of overly-permissive AWS IoT policy granting $aws/things/* without ThingName scoping

`UC_5_2` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
sourcetype="aws:cloudtrail" eventSource="iot.amazonaws.com" (eventName=CreatePolicy OR eventName=CreatePolicyVersion OR eventName=SetDefaultPolicyVersion)
| search requestParameters.policyDocument="*$aws/things/*" NOT requestParameters.policyDocument="*iot:Connection.Thing.ThingName*"
| table _time eventName userIdentity.arn sourceIPAddress requestParameters.policyName requestParameters.policyDocument
| sort - _time
```


## Why this matters

Severity classified as **HIGH** based on: 3 use case(s) fired, 4 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
