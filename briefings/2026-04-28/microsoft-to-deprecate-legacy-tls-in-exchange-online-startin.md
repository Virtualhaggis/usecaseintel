<!-- curated:true -->
# [MED] Microsoft to Deprecate Legacy TLS for POP/IMAP in Exchange Online Starting July 2026

**Source:** BleepingComputer
**Published:** 2026-04-28
**Article:** https://www.bleepingcomputer.com/news/microsoft/microsoft-to-deprecate-legacy-tls-in-exchange-online-starting-july/
**Curated:** Analyst-reviewed 2026-04-28

## Threat profile

Microsoft will start **blocking legacy TLS connections for POP3 and IMAP** in Exchange Online from **July 2026**. This is a deprecation, not a vulnerability, but operationally relevant for SOCs because:

- Many enterprises still have legacy POP/IMAP clients (kiosk apps, scanners-to-email, automation scripts, third-party contact-form integrations) using **TLS 1.0 or 1.1**.
- POP3/IMAP is also the **canonical authentication channel for password-spray and credential-stuffing attacks** against Microsoft tenants — modern auth doesn't apply, MFA can't enforce.
- The deprecation should reduce risk, but **the transition window** is when bad actors will scan for hosts that have switched but kept fallback enabled, and when defenders will see auth failures from real legacy clients.

We've upgraded severity to **MED** because:
- Inventory + remediation is non-trivial in many enterprises.
- It surfaces a long-standing **password-spray attack surface** that ought to have been deprecated long ago.

## Indicators of Compromise

- _No IOCs — this is a deprecation announcement, not an active threat._
- Hunt focus: own legacy POP3/IMAP clients on TLS 1.0 / 1.1; password-spray attempts via these protocols.

## MITRE ATT&CK (analyst-validated)

- **T1110.003** — Brute Force: Password Spraying (the dominant POP/IMAP attack)
- **T1110.004** — Brute Force: Credential Stuffing
- **T1078** — Valid Accounts (post-spray)
- **T1556** — Modify Authentication Process (where attackers force fallback to legacy auth)

## Recommended SOC actions (priority-ordered)

1. **Inventory POP3 / IMAP authentication today.** Pull the last 30 days of legacy-protocol auth from your tenant (Defender / Entra ID logs). The list of users + apps + IPs *is* your migration backlog.
2. **Disable legacy auth proactively** (well before July). Microsoft has been pushing this for years; tenants that use Conditional Access can already block "legacy auth" wholesale.
3. **Identify legacy clients**: scan-to-email MFP, IoT cameras emailing alerts, legacy mail clients (Outlook 2010 and earlier), home-grown automation. Each needs a migration path or a service-account replacement.
4. **Hunt password-spray attempts on POP3 / IMAP** — see queries below.
5. **Coordinate with operations / facility / IT teams** on the timeline. Many of the legacy clients are owned by non-IT (facilities, marketing, etc.).
6. **Document a fallback plan** for July transition — what happens if the multi-function-printer's email-alert breaks at 2am? Who fixes it?

## Splunk SPL — POP3 / IMAP authentication, last 30 days

```spl
index=azure sourcetype=azure:signin
    (clientAppUsed IN ("POP3","IMAP4","IMAP","SMTP","POP","ExchangeActiveSync",
                        "Exchange ActiveSync","Other clients") OR isLegacyAuth=true)
| stats count, dc(ipAddress) AS unique_ips, values(ipAddress) AS source_ips,
        earliest(_time) AS firstSeen, latest(_time) AS lastSeen
        by userPrincipalName, clientAppUsed, status.errorCode
| sort - count
```

## Splunk SPL — password spray on POP3 / IMAP

```spl
index=azure sourcetype=azure:signin
    clientAppUsed IN ("POP3","IMAP4","IMAP","Exchange ActiveSync")
    status.errorCode!=0
| stats dc(userPrincipalName) AS distinct_users, count AS attempts,
        values(userPrincipalName) AS targeted_users
        by ipAddress, _time
| where distinct_users >= 5
| sort - distinct_users
```

## Splunk SPL — TLS-version anomaly (Exchange / proxy logs)

```spl
index=email sourcetype IN ("ms_o365_management","exchange:tls","proxy")
    protocol IN ("POP3","IMAP")
    tls_version IN ("TLSv1.0","TLSv1.1","TLS_1_0","TLS_1_1","SSLv3")
| stats count, dc(client_ip) AS unique_clients, values(client_ip) AS clients
        by tls_version, protocol, user
| sort - count
```

## Defender KQL — legacy POP3 / IMAP auth in Entra

```kql
AADSignInEventsBeta
| where Timestamp > ago(30d)
| where ClientAppUsed in~ ("POP3","IMAP","IMAP4","SMTP","Other clients",
                            "Exchange ActiveSync","Authenticated SMTP")
   or IsLegacyAuth == true
| summarize signins = count(),
            uniqueIPs = dcount(IPAddress),
            uniqueUsers = dcount(AccountUpn),
            firstSeen = min(Timestamp), lastSeen = max(Timestamp),
            users = make_set(AccountUpn, 50)
            by ClientAppUsed, AppDisplayName
| order by signins desc
```

## Defender KQL — POP3 / IMAP password spray

```kql
AADSignInEventsBeta
| where Timestamp > ago(30d)
| where ClientAppUsed in~ ("POP3","IMAP","IMAP4","Exchange ActiveSync")
| where ResultType != 0
| summarize attempts = count(),
            distinctUsers = dcount(AccountUpn),
            users = make_set(AccountUpn, 30),
            firstSeen = min(Timestamp), lastSeen = max(Timestamp)
            by IPAddress, bin(Timestamp, 1h)
| where distinctUsers >= 5
| order by distinctUsers desc
```

## Why this matters for your SOC

POP3 / IMAP / legacy auth is **the most prolific Microsoft-tenant compromise vector of the last 10 years** — credential stuffing and password spray hit these protocols because they bypass MFA and Conditional Access. Microsoft's deprecation timeline is the **forcing function** to clean it up, but the actual operational work is yours:

1. Run the legacy-auth inventory query this week.
2. Build a migration plan for each non-trivial client.
3. Pre-disable legacy auth in test rings, then production, well before July.
4. Hunt for password-spray on legacy protocols continuously — it's still the dominant initial-access for cloud-mailbox compromise in 2026.

The deprecation will help, but only if your remediation is faster than the attacker's ability to find your final remaining legacy-auth user.
