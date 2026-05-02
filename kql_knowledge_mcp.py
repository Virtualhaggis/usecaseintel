"""KQL knowledge MCP server.

Exposes the `knowledge/*.md` files as searchable MCP tools so other
clients (Cursor, Claude Desktop, claude.ai web with custom connectors)
can query the BluRaven KQL knowledge base distilled into this repo.

Tools:
    list_kql_topics()           — list every knowledge file + every section id within
    search_kql(query, k=5)      — keyword search across all knowledge content
    get_kql_section(section_id) — fetch one section by its anchor id (e.g. `pattern-process-tree`)
    get_kql_file(filename)      — fetch a whole knowledge file by name (e.g. `kql_patterns.md`)

Run with:
    python kql_knowledge_mcp.py

Wire into Claude Desktop (`%AppData%\Claude\claude_desktop_config.json`):
    {
      "mcpServers": {
        "kql-knowledge": {
          "command": "python",
          "args": ["C:/path/to/kql_knowledge_mcp.py"]
        }
      }
    }

Wire into Cursor (`~/.cursor/mcp.json` — same shape).
"""
from __future__ import annotations

import asyncio
import re
from pathlib import Path
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool


KNOWLEDGE_DIR = Path(__file__).parent / "knowledge"

# ---- knowledge index --------------------------------------------------------

# Section anchor: `## <id>` where id starts lowercase and may contain
# letters, digits, and hyphens. Allows mixed case for IDs like
# `table-DeviceProcessEvents`.
_SECTION_HEADER_RE = re.compile(r"^##\s+(?P<id>[a-z][A-Za-z0-9-]+)\s*$", re.MULTILINE)


def _load_files() -> dict[str, str]:
    """Return {filename: full_text} for every kql_*.md in knowledge/.

    Excludes README.md and other meta files — only files prefixed
    `kql_` carry indexed content.
    """
    if not KNOWLEDGE_DIR.exists():
        return {}
    out: dict[str, str] = {}
    for p in sorted(KNOWLEDGE_DIR.glob("kql_*.md")):
        try:
            out[p.name] = p.read_text(encoding="utf-8")
        except Exception:
            continue
    return out


def _build_index(files: dict[str, str]) -> dict[str, tuple[str, str]]:
    """Return {section_id: (filename, body)}.

    A section runs from `## <id>` to the next `## <id>` or the next
    HTML divider comment (`<!-- ===... -->`) or EOF — whichever comes
    first. The body includes the `## <id>` header line.
    """
    index: dict[str, tuple[str, str]] = {}
    for fname, text in files.items():
        # find every header position
        starts = [(m.start(), m.group("id")) for m in _SECTION_HEADER_RE.finditer(text)]
        for i, (pos, sid) in enumerate(starts):
            end = starts[i + 1][0] if i + 1 < len(starts) else len(text)
            body = text[pos:end].rstrip()
            # Drop trailing divider comment if present
            body = re.sub(r"\n<!--\s*=+\s*-->\s*$", "", body).rstrip()
            if sid not in index:
                index[sid] = (fname, body)
    return index


_FILES = _load_files()
_INDEX = _build_index(_FILES)


# ---- search -----------------------------------------------------------------

_TOKEN_RE = re.compile(r"[A-Za-z0-9_]{3,}")


def _score(query: str, body: str) -> int:
    """Cheap keyword-overlap scorer — sum of per-token hit counts.

    Token matches are case-insensitive. Phrase matches (the full query
    appearing as a contiguous substring) are weighted heavily so that
    quoted or specific phrases beat scattered token matches.
    """
    body_l = body.lower()
    q_l = query.lower().strip()
    if not q_l:
        return 0
    score = 0
    if q_l in body_l:
        score += 50  # phrase match
    for tok in _TOKEN_RE.findall(q_l):
        score += body_l.count(tok)
    return score


def _search(query: str, k: int) -> list[tuple[str, str, str, int]]:
    """Return top-k matching sections as (section_id, filename, body, score)."""
    scored: list[tuple[str, str, str, int]] = []
    for sid, (fname, body) in _INDEX.items():
        s = _score(query, body)
        if s > 0:
            scored.append((sid, fname, body, s))
    scored.sort(key=lambda r: r[3], reverse=True)
    return scored[:k]


# ---- MCP server -------------------------------------------------------------

server: Server = Server("kql-knowledge")


@server.list_tools()
async def _list_tools() -> list[Tool]:
    return [
        Tool(
            name="list_kql_topics",
            description=(
                "List every section in the KQL knowledge base. Returns one "
                "line per section in the format `<section_id>  [<filename>]  <first heading line>`. "
                "Use this to discover what's available before searching."
            ),
            inputSchema={"type": "object", "properties": {}, "required": []},
        ),
        Tool(
            name="search_kql",
            description=(
                "Keyword-search the KQL knowledge base. Returns the top-k "
                "matching sections with their full body text. Pass natural "
                "language like 'phishing link to process spawn' or specific "
                "operator names like 'mv-expand'. Case-insensitive. Phrase "
                "matches rank above scattered tokens."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search query — keywords or phrase.",
                    },
                    "k": {
                        "type": "integer",
                        "description": "Max number of sections to return. Default 5.",
                        "default": 5,
                        "minimum": 1,
                        "maximum": 20,
                    },
                },
                "required": ["query"],
            },
        ),
        Tool(
            name="get_kql_section",
            description=(
                "Fetch a single knowledge section by its anchor id (e.g. "
                "'pattern-process-tree', 'anti-bare-process-execution', "
                "'externaldata-tii-feeds'). Use list_kql_topics first if "
                "you don't know the id."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "section_id": {
                        "type": "string",
                        "description": "The anchor id of the section to fetch.",
                    }
                },
                "required": ["section_id"],
            },
        ),
        Tool(
            name="get_kql_file",
            description=(
                "Fetch an entire knowledge file by name (e.g. 'kql_patterns.md'). "
                "Useful when you want the full context of one topic area."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "filename": {
                        "type": "string",
                        "description": "Filename including extension, e.g. 'kql_patterns.md'.",
                    }
                },
                "required": ["filename"],
            },
        ),
    ]


@server.call_tool()
async def _call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    if name == "list_kql_topics":
        if not _INDEX:
            return [TextContent(type="text", text="(knowledge/ is empty or missing)")]
        lines = []
        for fname in sorted(_FILES):
            lines.append(f"\n# {fname}")
            for sid, (sfname, body) in sorted(_INDEX.items()):
                if sfname != fname:
                    continue
                # first non-blank line after the ## header
                first_para = ""
                for ln in body.splitlines()[1:]:
                    if ln.strip() and not ln.lstrip().startswith("**"):
                        first_para = ln.strip()
                        break
                    if ln.strip().startswith("**"):
                        first_para = ln.strip()
                        break
                lines.append(f"  {sid}  {first_para[:120]}")
        return [TextContent(type="text", text="\n".join(lines))]

    if name == "search_kql":
        query = (arguments or {}).get("query", "")
        k = int((arguments or {}).get("k", 5))
        hits = _search(query, k)
        if not hits:
            return [TextContent(type="text", text=f"No sections matched '{query}'.")]
        chunks = []
        for sid, fname, body, score in hits:
            chunks.append(f"--- {sid}  [{fname}]  score={score} ---\n{body}")
        return [TextContent(type="text", text="\n\n".join(chunks))]

    if name == "get_kql_section":
        sid = (arguments or {}).get("section_id", "").strip()
        entry = _INDEX.get(sid)
        if not entry:
            close = [s for s in _INDEX if sid and sid in s][:5]
            hint = f" Did you mean one of: {', '.join(close)}?" if close else ""
            return [TextContent(type="text", text=f"Unknown section_id '{sid}'.{hint}")]
        fname, body = entry
        return [TextContent(type="text", text=f"[{fname}]\n\n{body}")]

    if name == "get_kql_file":
        fname = (arguments or {}).get("filename", "").strip()
        text = _FILES.get(fname)
        if text is None:
            available = ", ".join(sorted(_FILES))
            return [TextContent(type="text", text=f"Unknown filename '{fname}'. Available: {available}")]
        return [TextContent(type="text", text=text)]

    return [TextContent(type="text", text=f"Unknown tool: {name}")]


async def _amain() -> None:
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


def main() -> None:
    asyncio.run(_amain())


if __name__ == "__main__":
    main()
