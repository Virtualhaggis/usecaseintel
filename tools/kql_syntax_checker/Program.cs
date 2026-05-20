// kql_syntax_checker — batch KQL syntax + semantic validator
//
// Reads a JSON array of {id, kql} entries from stdin, parses each KQL
// with Microsoft's official Kusto.Language library (the same engine the
// Defender XDR Advanced Hunting UI uses), and writes a JSON array of
// {id, ok, diagnostics[]} to stdout.
//
// Invoked by the Python pipeline as:
//   echo '[{"id":"a","kql":"DeviceProcessEvents | where ..."}]' \
//     | kql_syntax_checker.exe
//
// Exit codes:
//   0 = ran cleanly (validation results in stdout)
//   1 = launch / IO failure
//
// Rebuild:
//   dotnet publish -c Release

using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using Kusto.Language;
using Kusto.Language.Editor;

namespace KqlSyntaxChecker;

public record InputEntry(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("kql")] string Kql);

public record OutputDiagnostic(
    [property: JsonPropertyName("severity")] string Severity,
    [property: JsonPropertyName("message")] string Message,
    [property: JsonPropertyName("start")] int Start,
    [property: JsonPropertyName("length")] int Length,
    [property: JsonPropertyName("line")] int Line,
    [property: JsonPropertyName("column")] int Column);

public record OutputEntry(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("ok")] bool Ok,
    [property: JsonPropertyName("diagnostics")] List<OutputDiagnostic> Diagnostics);

public static class Program
{
    public static int Main(string[] args)
    {
        try
        {
            string inputJson = Console.In.ReadToEnd();
            // Strip BOM if the caller piped via PowerShell or similar — string
            // pipes on Windows often prepend U+FEFF / 0xEF 0xBB 0xBF.
            if (!string.IsNullOrEmpty(inputJson) && inputJson[0] == '﻿')
            {
                inputJson = inputJson.Substring(1);
            }
            if (string.IsNullOrWhiteSpace(inputJson))
            {
                Console.Out.Write("[]");
                return 0;
            }

            var entries = JsonSerializer.Deserialize<List<InputEntry>>(inputJson)
                          ?? new List<InputEntry>();
            var results = new List<OutputEntry>(entries.Count);

            foreach (var entry in entries)
            {
                results.Add(Validate(entry));
            }

            var opts = new JsonSerializerOptions { WriteIndented = false };
            Console.Out.Write(JsonSerializer.Serialize(results, opts));
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"kql_syntax_checker: {ex.GetType().Name}: {ex.Message}");
            return 1;
        }
    }

    private static OutputEntry Validate(InputEntry entry)
    {
        var diagnostics = new List<OutputDiagnostic>();
        if (string.IsNullOrWhiteSpace(entry.Kql))
        {
            // Empty KQL is "valid" — nothing to validate; let the caller
            // decide whether an empty query is acceptable.
            return new OutputEntry(entry.Id, true, diagnostics);
        }

        // We deliberately use Parse() not ParseAndAnalyze(). Semantic
        // analysis (column / table resolution) would flag every Defender
        // table as "unknown" because the parser's built-in schema is for
        // Azure Data Explorer, not Defender XDR. Column-level checks are
        // already covered by `kql_schema_validator.py` which knows the
        // Defender + Sentinel schemas. This binary's job is to catch
        // pure grammar errors — missing pipes, bad operator spellings,
        // mis-matched parens, malformed `summarize ... by`, etc.
        KustoCode code;
        try
        {
            code = KustoCode.Parse(entry.Kql);
        }
        catch (Exception ex)
        {
            diagnostics.Add(new OutputDiagnostic(
                Severity: "Error",
                Message: $"parser threw: {ex.GetType().Name}: {ex.Message}",
                Start: 0, Length: 0, Line: 0, Column: 0));
            return new OutputEntry(entry.Id, false, diagnostics);
        }

        bool hasError = false;
        foreach (var diag in code.GetDiagnostics())
        {
            var (line, col) = LineColumnFromOffset(entry.Kql, diag.Start);
            string severity = diag.Severity?.ToString() ?? "Error";
            if (severity == "Error") hasError = true;
            diagnostics.Add(new OutputDiagnostic(
                Severity: severity,
                Message: diag.Message ?? "(no message)",
                Start: diag.Start,
                Length: diag.Length,
                Line: line,
                Column: col));
        }

        return new OutputEntry(entry.Id, !hasError, diagnostics);
    }

    private static (int line, int column) LineColumnFromOffset(string text, int offset)
    {
        if (offset < 0 || offset > text.Length) return (0, 0);
        int line = 1, col = 1;
        for (int i = 0; i < offset; i++)
        {
            if (text[i] == '\n') { line++; col = 1; }
            else col++;
        }
        return (line, col);
    }
}
