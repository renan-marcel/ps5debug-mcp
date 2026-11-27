# ps5debug-mcp

A **zero-dependency** Model Context Protocol (MCP) server for [`ps5debug-NG`](https://github.com/Pharaoh2k/ps5debug-NG), built on top of the pure-Python protocol layer from [`PS5Debug-studio`](https://github.com/Pharaoh2k/PS5Debug-studio).

It lets AI coding/reversing agents (Claude Code, Antigravity / Gemini, Cursor, VS Code, Windsurf) inspect processes, resolve ASLR module bases, read/write live PS5 memory, scan AOB patterns, disassemble with Zydis, set hardware watchpoints / software breakpoints, walk call stacks, and tail `/dev/klog` — completely standalone with no external disassembler required (and optionally pairs with **Binary Ninja MCP** if you want static ELF decompilation alongside it).

## Features

- **Zero external Python dependencies:** Uses only Python 3.10+ standard library (`stdio` JSON-RPC 2.0).
- **ASLR ↔ Binary Ninja address translation:** `ps5_resolve_address` converts between Binary Ninja / ELF virtual addresses and live PS5 addresses using `PROC_MAPS`.
- **Memory & Analysis:** `ps5_read_memory` (hex, utf8, ascii, typed scalars `u8..f64`), `ps5_write_memory`, `ps5_aob_scan`, `ps5_disasm_region` (server-side Zydis), `ps5_find_xrefs_to`.
- **Live Debugging (Ports 744 + 755):** `ps5_debug_attach`, software breakpoints (`0xCC`, 30 slots), hardware watchpoints (`DR0–DR3`), thread list/suspend/resume, GP registers, single-stepping, and server-side RBP stack walk (`ps5_debug_read_stack`).
- **Kernel Log Streaming (Port 3232):** `ps5_klog_start` + `ps5_klog_tail` with ring-buffer filtering.

## Requirements

- Python **3.10+** on the host PC.
- A jailbroken PS5 running the **`ps5debug-NG`** payload (ports `744`, `755`, `3232`).
- Firewall allowing inbound TCP on port `755` if using breakpoints/watchpoints (`ps5_debug_attach`).

## Installation

Install directly from GitHub Releases (no clone needed):

```bash
pip install https://github.com/renan-marcel/ps5debug-mcp/releases/latest/download/ps5debug_mcp-0.1.0-py3-none-any.whl
```

Or install directly via Git:

```bash
pip install git+https://github.com/renan-marcel/ps5debug-mcp.git
```

Or clone for local development:

```bash
git clone https://github.com/renan-marcel/ps5debug-mcp.git
cd ps5debug-mcp
pip install -e .
```

Or run without installing:

```bash
PYTHONPATH=src python -m ps5debug_mcp
```

## Client Configuration

### Claude Code (`~/.claude.json` or `.mcp.json`)

```json
{
  "mcpServers": {
    "ps5debug": {
      "command": "python",
      "args": ["-m", "ps5debug_mcp"],
      "env": {
        "PS5_DEBUG_HOST": "192.168.1.xxx"
      }
    }
  }
}
```

### Antigravity / Gemini CLI (`~/.gemini/antigravity/mcp_config.json`)

```json
{
  "mcpServers": {
    "ps5debug": {
      "command": "python",
      "args": ["-m", "ps5debug_mcp"],
      "env": {
        "PS5_DEBUG_HOST": "192.168.1.xxx"
      }
    }
  }
}
```

### Cursor / VS Code / Windsurf

Point the MCP `stdio` entry to `ps5debug-mcp` (if installed via `pip install -e .`) or `python -m ps5debug_mcp` with `PYTHONPATH` pointing to `src/`, and optionally set `PS5_DEBUG_HOST`.

## Documentation

- [Tools Reference](docs/TOOLS.md) — Every MCP tool, argument, and return payload.
- [Binary Ninja + PS5 Workflow](docs/BINARY_NINJA_WORKFLOW.md) — Optional guide for combining `binary-ninja` MCP and `ps5debug-mcp`.

## GitFlow & Automated Releases

- **`main` (protected):** Production/release branch. Direct pushes are blocked; changes enter via Pull Request after all CI checks (`Python 3.10–3.13`) pass.
- **`develop`:** Integration branch for `feature/*` and `fix/*` branches.
- **Auto Tag & Release:** Every merge/PR into `main` automatically computes the next semantic version tag from Conventional Commits (`feat!:` → major, `feat:` → minor, `fix:`/`chore:`/`ci:` → patch), pushes the `vX.Y.Z` tag, builds `.whl` and `.tar.gz`, and publishes a GitHub Release.

## License & Attribution

Licensed under the **Apache License 2.0** ([LICENSE](LICENSE)).  
Protocol client (`ps5debug_client.py`) and interrupt listener (`debugger_core.py`) are derived from `PS5Debug-studio` (Apache-2.0) for `ps5debug-NG`.
