# kql_syntax_checker

Self-contained Win-x64 binary that validates KQL queries using Microsoft's
official `Microsoft.Azure.Kusto.Language` parser — the same engine the
Defender XDR Advanced Hunting portal uses. Invoked by `kql_syntax_validator.py`
in the parent project; you usually don't need to run it directly.

## Interface

Reads JSON array from stdin, writes JSON array to stdout.

```jsonc
// stdin
[
  {"id": "uc1", "kql": "DeviceProcessEvents | where ProcessId == 1"},
  {"id": "uc2", "kql": "DeviceProcessEvents | wher BadCol"}
]

// stdout
[
  {"id": "uc1", "ok": true, "diagnostics": []},
  {"id": "uc2", "ok": false, "diagnostics": [
    {"severity": "Error", "message": "...", "start": 24, "length": 4, "line": 1, "column": 25}
  ]}
]
```

Exit codes: `0` ran cleanly (results in stdout); `1` launch / IO failure.

## Rebuilding

Requires .NET 8 SDK (download at https://dotnet.microsoft.com/download/dotnet/8.0).

```powershell
cd tools/kql_syntax_checker
dotnet publish -c Release
# resulting exe lands in: bin/Release/net8.0/win-x64/publish/kql_syntax_checker.exe
copy bin\Release\net8.0\win-x64\publish\kql_syntax_checker.exe bin\kql_syntax_checker.exe
```

The committed `bin/kql_syntax_checker.exe` is the self-contained build —
runs on any Windows x64 machine without a .NET SDK or runtime installed.
Approx 30 MB.

## When to rebuild

- New Defender / Sentinel KQL operator added in the wild (rare; Microsoft
  ships parser updates as new NuGet versions).
- Bump `Microsoft.Azure.Kusto.Language` version in the `.csproj` and rebuild.

## Smoke test

```powershell
'[{"id":"good","kql":"DeviceProcessEvents | where ProcessId == 1"},{"id":"bad","kql":"DeviceProcessEvents | wher BadCol"}]' `
  | .\bin\kql_syntax_checker.exe
```
