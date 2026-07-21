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

- **T1580** — Cloud Infrastructure Discovery
- **T1078.001** — Valid Accounts: Default Accounts
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1098** — Account Manipulation
- **T1552.001** — Unsecured Credentials: Credentials In Files

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### AWS IoT client subscribing to reserved wildcard topic $aws/things/# (Shark vacuum serial harvest)

`UC_76_0` · phase: **recon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
index=aws sourcetype="aws:iot" eventType=Subscribe (topicName="$aws/things/#" OR topicName="$aws/things/+" OR topicName="$aws/things/*")
| stats count AS subscribes values(topicName) AS topics min(_time) AS firstSeen by clientId principalId sourceIp
| sort - subscribes
```

### Single AWS IoT principal writing shadows to multiple distinct device thing names (cross-device Exec_Command RCE)

`UC_76_1` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
index=aws sourcetype="aws:iot" (eventType=UpdateThingShadow OR eventType=Publish) topicName="$aws/things/*/shadow/update"
| rex field=topicName "\$aws/things/(?<thingName>[^/]+)/shadow/update"
| stats dc(thingName) AS distinctThings count values(sourceIp) AS srcIps by clientId principalId
| where distinctThings > 1
| sort - distinctThings
```

### AWS IoT policy created/updated granting reserved $aws/things/* topic without ThingName pinning

`UC_76_2` · phase: **weapon** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
index=aws sourcetype="aws:cloudtrail" eventSource="iot.amazonaws.com" (eventName=CreatePolicy OR eventName=CreatePolicyVersion) requestParameters.policyDocument="*topicfilter/$aws/things/*" NOT requestParameters.policyDocument="*iot:Connection.Thing.ThingName*"
| table _time eventName userIdentity.arn sourceIPAddress requestParameters.policyName
| sort - _time
```


## Why this matters

Severity classified as **HIGH** based on: 3 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
