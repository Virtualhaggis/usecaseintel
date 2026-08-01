# [HIGH] Code execution back door found in Ruby’s rest-client library

**Source:** Snyk
**Published:** 2019-08-21
**Article:** https://snyk.io/blog/code-execution-back-door-found-in-rubys-rest-client-library/

## Threat Profile

Snyk Blog In this article
Written by Hayley Denbraver 
August 21, 2019
0 mins read On August 19th, 2019 [rest-client](https://snyk.io/vuln/rubygems:rest-client) , a simple HTTP and REST client for Ruby, reported a new security threat . A maintainer's RubyGem account was compromised and a malicious third party installed a code execution back door. The exploit affects versions greater than 1.6.10 and less than 1.7.0.rc1.
What happened? GitHub user [juskoljo](https://github.com/juskoljo) raised an …

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1102.001** — Web Service: Dead Drop Resolver
- **T1195.001** — Supply Chain Compromise: Compromise Software Dependencies and Development Tools
- **T1041** — Exfiltration Over C2 Channel
- **T1071.001** — Application Layer Protocol: Web Protocols

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Ruby/Rails process fetching remote code from pastebin.com raw (rest-client 1.6.13 backdoor)

`UC_3493_0` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where (Web.url="*pastebin.com/raw/5iNdELNX*" OR (Web.url="*pastebin.com/raw/*" AND Web.http_user_agent="*ruby*")) by Web.src, Web.dest, Web.url, Web.http_user_agent, Web.http_method | `drop_dm_object_name(Web)` | sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName has_any ("ruby","rails","puma","unicorn","passenger")
| where RemoteUrl has "pastebin.com" and (RemoteUrl has "/raw/" or RemoteUrl has "5iNdELNX")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessAccountName
| order by Timestamp desc
```

### Exfiltration callback to mironanoru.zzz.com.ua (rest-client backdoor C2)

`UC_3493_1` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where (DNS.query="mironanoru.zzz.com.ua" OR DNS.query="*.mironanoru.zzz.com.ua") by DNS.src, DNS.query, DNS.answer | `drop_dm_object_name(DNS)` | sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "mironanoru.zzz.com.ua"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessAccountName
| order by Timestamp desc
```


## Why this matters

Severity classified as **HIGH** based on: 2 use case(s) fired, 4 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
