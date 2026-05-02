# KQL scalar functions — null/empty, IP, paths, regex, JSON

Distilled from BluRaven *Advanced Hands-On KQL* — Section 5 (Creating
and Manipulating Fields). Scalar functions return a single value per
row and are usable inside `where` / `extend` / `project`.

<!-- ============================================================== -->

## scalar-empty-and-null

> **String columns in KQL do not store NULL.** They store empty
> strings. Reach for `isempty` / `isnotempty` for string-typed columns
> and `isnull` / `isnotnull` for non-string columns.

| Function | Use for | Notes |
|----------|---------|-------|
| `isempty(col)` | string columns | true when value is empty *or* null |
| `isnotempty(col)` | string columns | inverse of `isempty` |
| `isnull(col)` | non-string columns (`int`, `long`, `datetime`, `dynamic`) | true when value is null |
| `isnotnull(col)` | non-string columns | inverse of `isnull` |

> Course practice: when you don't know the underlying type, default to
> `isempty` / `isnotempty` — they handle string and dynamic, and
> degrade gracefully on numeric.

```kql
// Cobalt Strike — a rundll32.exe launch with no command line is a
// classic beacon spawn. Empty-cmdline rundll32 is the signal.
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "rundll32.exe"
| where isempty(ProcessCommandLine)
```

```kql
// Sentinel security events — only keep events that actually carry a
// Workstation field (different events populate different fields)
SecurityEvent
| where TimeGenerated > ago(1d)
| where isnotempty(Workstation)
```

<!-- ============================================================== -->

## scalar-not-function-vs-bang

`not(expr)` is a scalar function that flips a boolean expression.
Reach for it when an operator has no negation form. For operators
that *do* (`!=`, `!has`, `!contains`, `!in`, `!startswith`), prefer
the operator form — the engine pushes the negation into the index
seek.

```kql
// these are equivalent — but the second form is engine-friendlier
SecurityEvent | where not(TargetUserName == "suspicious_user")
SecurityEvent | where TargetUserName != "suspicious_user"

// `not()` is the right tool when the inner is a function
DeviceNetworkEvents | where not(ipv4_is_private(RemoteIP))
```

<!-- ============================================================== -->

## scalar-ipv4-functions

Strings work as IP storage in M365D / Sentinel, but `has` / `contains`
on IPs is fragile (`has "192.168.1.1"` will match `192.168.1.10`).
Always reach for the `ipv4_*` family for correctness.

| Function | Returns | Notes |
|----------|---------|-------|
| `ipv4_is_in_range(ip, "10.0.0.0/8")` | bool | Single CIDR membership. |
| `ipv4_is_in_any_range(ip, dynamic([...]))` | bool | List of CIDRs. |
| `ipv4_is_private(ip)` | bool | RFC 1918 (`10/8`, `172.16/12`, `192.168/16`). **Does NOT cover loopback `127/8` or APIPA `169.254/16`** — handle those separately. |
| `ipv4_compare(a, b)` | int | `-1` / `0` / `1` like a comparator — useful for ranges. |
| `parse_ipv4(ip)` | long | Numeric form for arithmetic comparisons. |

```kql
// Block-list a single subnet
let suspicious_subnet = "207.10.24.0/24";
DeviceNetworkEvents
| where Timestamp > ago(1h)
| where ipv4_is_in_range(RemoteIP, suspicious_subnet)

// Multi-subnet block-list
let suspicious_subnets = dynamic(["207.10.24.0/24", "200.15.34.0/24"]);
DeviceNetworkEvents
| where ipv4_is_in_any_range(RemoteIP, suspicious_subnets)

// LAN-to-LAN connections only (lateral movement scope)
DeviceNetworkEvents
| where ipv4_is_private(LocalIP) and ipv4_is_private(RemoteIP)

// Egress to public — invert with not(), no `!ipv4_is_private`
DeviceNetworkEvents
| where not(ipv4_is_private(RemoteIP))
| where not(RemoteIP startswith "127.")        // also exclude loopback
| where not(RemoteIP startswith "169.254.")    // and APIPA
```

> There is no `ipv4_is_not_in_range` — wrap with `not(...)` to invert.

<!-- ============================================================== -->

## scalar-paths-and-regex

Backslash is an escape character in **both** KQL strings and regex.
That's why path-matching has the most footguns of any KQL subject.

### Path-matching guidance

```kql
// Verbatim string — preferred for path predicates
| where InitiatingProcessFolderPath startswith @"C:\Users\TEMP"

// Or escape — same effect, harder to read
| where InitiatingProcessFolderPath startswith "C:\\Users\\TEMP"
```

### Regex backslash escaping

```kql
// matches regex with verbatim string — TWO backslashes per literal one
| where InitiatingProcessFolderPath matches regex @"C:\\Users\\TEMP.*"

// matches regex with normal string — FOUR backslashes per literal one
| where InitiatingProcessFolderPath matches regex "C:\\\\Users\\\\TEMP.*"
```

### Case-insensitive regex

`matches regex` is **case-sensitive by default** (RE2). Prepend
`(?i)` to the pattern for case-insensitive matching — necessary
because security log columns often have inconsistent capitalisation
(e.g. user-supplied paths preserve user case).

```kql
| where InitiatingProcessFolderPath matches regex @"(?i)C:\\Users\\TEMP.*"
```

> Reviewer rule of thumb: every `matches regex` predicate against a
> filesystem path or command line should start with `(?i)` unless you
> have a specific reason for case-sensitivity.

<!-- ============================================================== -->

## scalar-json-extraction

Several Defender / Sentinel columns are dynamic JSON — most notably
`AdditionalFields`. Two access notations:

| Notation | When |
|----------|------|
| Dot — `col.Key` | Key is a clean identifier (no spaces, dots, hyphens). |
| Bracket — `col["Pass-through authentication"]` | Always safe; **required** when the key contains spaces, dots, or other delimiters. |

> Course preference: **default to bracket notation**. The dot form
> silently fails if the key has unexpected punctuation — the engine
> may return zero rows without an error.

```kql
IdentityLogonEvents
| where Timestamp > ago(7d)
| where AdditionalFields["Pass-through authentication"] == "false"

IdentityLogonEvents
| where AdditionalFields["ARG.PROPERTY"] == "false"
```

### When `AdditionalFields` is stored as a string

In some tables (e.g. `DeviceEvents`), `AdditionalFields` is typed
`string` rather than `dynamic`. Direct property access errors out
with:

> *Path expression source must be of type 'dynamic'. Received a source of type string instead.*

Convert with `parse_json()` first (the older `todynamic()` is
deprecated but equivalent):

```kql
DeviceEvents
| where Timestamp > ago(1h)
| where ActionType == "NamedPipeEvent"
| where parse_json(AdditionalFields)["DesiredAccess"] == 1180063
```

### Common shapes worth memorising

```kql
// Sentinel SecurityEvent (Windows EventLogs) — eventdata is XML
//                  column is a flat string. Use parse_xml() instead.

// M365D AADSignInEventsBeta — MfaDetail is a JSON string
| extend Methods = tostring(parse_json(MfaDetail).AuthMethod)

// M365D DeviceEvents NamedPipeEvent — DesiredAccess in AdditionalFields
| extend DesiredAccess = toint(parse_json(AdditionalFields).DesiredAccess)

// AAD app-consent — ConsentContext is JSON in AdditionalFields
| extend Scope = tostring(parse_json(AdditionalFields).ConsentContext.Scope)
```

> When extracting nested values, always `tostring()` / `toint()` /
> `tobool()` the result before comparing — `parse_json` returns a
> `dynamic` and naive comparison can silently mismatch types.
