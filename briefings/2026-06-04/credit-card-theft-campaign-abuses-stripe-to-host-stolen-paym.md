# [HIGH] Credit card theft campaign abuses Stripe to host stolen payment info

**Source:** BleepingComputer
**Published:** 2026-06-04
**Article:** https://www.bleepingcomputer.com/news/security/credit-card-theft-campaign-abuses-stripe-to-host-stolen-payment-info/

## Threat Profile

Credit card theft campaign abuses Stripe to host stolen payment info 
By Bill Toulas 
June 4, 2026
04:47 PM
0 
A new Magecart campaign is using Stripe's API infrastructure to host the credit card-stealing payload and the data exfiltrated from checkout pages.
The entire malicious activity relies on Google Tag Manager and Stripe domains - googletagmanager.com and api.stripe.com - that are trusted implicitly by online stores.
The new malware family was discovered by researchers at ecommerce securit…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1102.001** — Web Service: Dead Drop Resolver
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1189** — Drive-by Compromise
- **T1567** — Exfiltration Over Web Service

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Magecart skimmer payload fetched from Stripe customer record cus_TfFjAAZQNOYENR

`UC_18_1` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.user) as user values(Web.http_user_agent) as user_agent values(Web.http_referrer) as referrer from datamodel=Web where Web.url="*cus_TfFjAAZQNOYENR*" OR Web.url="*api.stripe.com/v1/customers/cus_TfFjAAZQNOYENR*" by Web.src, Web.dest, Web.url
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| sort - lastTime
```

**Defender KQL:**
```kql
union isfuzzy=true
( DeviceNetworkEvents
  | where Timestamp > ago(7d)
  | where RemoteUrl has "cus_TfFjAAZQNOYENR"
  | project Timestamp, DeviceId, DeviceName, RemoteIP, RemotePort, RemoteUrl,
            InitiatingProcessFileName, InitiatingProcessAccountName, InitiatingProcessCommandLine
),
( DeviceEvents
  | where Timestamp > ago(7d)
  | where RemoteUrl has "cus_TfFjAAZQNOYENR" or AdditionalFields has "cus_TfFjAAZQNOYENR"
  | project Timestamp, DeviceId, DeviceName, ActionType, RemoteUrl, AdditionalFields,
            InitiatingProcessFileName, InitiatingProcessAccountName
)
| order by Timestamp desc
```

### [LLM] Magecart skimmer payload fetched from Firestore project braintree-payment-app

`UC_18_2` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.user) as user values(Web.http_user_agent) as user_agent values(Web.http_referrer) as referrer from datamodel=Web where (Web.url="*braintree-payment-app*" OR Web.url="*projects/braintree-payment-app/databases*" OR Web.url="*tracking/captcha*") AND Web.url="*firestore.googleapis.com*" by Web.src, Web.dest, Web.url
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| sort - lastTime
```

**Defender KQL:**
```kql
union isfuzzy=true
( DeviceNetworkEvents
  | where Timestamp > ago(7d)
  | where RemoteUrl has "braintree-payment-app"
     or RemoteUrl has "projects/braintree-payment-app"
     or (RemoteUrl has "firestore.googleapis.com" and RemoteUrl has "tracking/captcha")
  | project Timestamp, DeviceId, DeviceName, RemoteIP, RemoteUrl,
            InitiatingProcessFileName, InitiatingProcessAccountName, InitiatingProcessCommandLine
),
( DeviceEvents
  | where Timestamp > ago(7d)
  | where RemoteUrl has "braintree-payment-app" or AdditionalFields has "braintree-payment-app" or AdditionalFields has "_d_data_customer_"
  | project Timestamp, DeviceId, DeviceName, ActionType, RemoteUrl, AdditionalFields,
            InitiatingProcessFileName, InitiatingProcessAccountName
)
| order by Timestamp desc
```

### PowerShell encoded / obfuscated command

`UC_PS_OBFUSCATED` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("powershell.exe","pwsh.exe")
      AND (Processes.process="*-enc *" OR Processes.process="*EncodedCommand*"
        OR Processes.process="*FromBase64String*" OR Processes.process="*-nop*"
        OR Processes.process="*-w hidden*" OR Processes.process="*Invoke-Expression*"
        OR Processes.process="*IEX(*" OR Processes.process="*DownloadString*"
        OR Processes.process="*Net.WebClient*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine matches regex @"(?i)(-enc|encodedcommand|frombase64string|-nop|-w\s+hidden|invoke-expression|iex\s*\(|downloadstring|net\.webclient)"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```


## Why this matters

Severity classified as **HIGH** based on: 3 use case(s) fired, 6 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
