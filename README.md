# LCRE - Binary Forensics CLI Tool

LCRE is a CLI tool for static binary analysis and forensics automation. It provides fast triage via native Go parsing and deep analysis via Ghidra headless integration.

## Features

- **Fast Triage**: Native Go parsing for PE, ELF, and Mach-O binaries
- **Heuristic Analysis**: Detect packers, suspicious imports, and malware indicators
- **IOC Extraction**: Extract URLs, IPs, domains, paths, and registry keys
- **Binary Diff**: Compare two binaries to identify changes
- **Ghidra Integration**: Deep analysis with decompilation and call graph extraction
- **Multiple Output Formats**: JSON and Markdown
- **AI-Ready**: Machine-readable capabilities for AI assistant integration

## Installation

### From Source

```bash
go install github.com/maxime/lcre/cmd/lcre@latest
```

### Build from Repository

```bash
git clone https://github.com/maxime/lcre
cd lcre
make build
```

### Docker

```bash
docker build -t lcre .
docker run --rm -v $(pwd):/work lcre triage /work/sample.exe
```

## Usage

### Triage (Fast Analysis)

```bash
# Basic triage
lcre triage sample.exe

# With strings and heuristics
lcre triage sample.exe --strings --heuristics

# Output as Markdown
lcre triage sample.exe -o md
```

### IOC Extraction

```bash
lcre iocs malware.exe
```

### Binary Diff

```bash
lcre diff version1.exe version2.exe
```

### Full Report

```bash
lcre report sample.exe -o json > report.json
```

### Interactive Query (Cached Analysis)

The query system provides instant access to analysis results. First query triggers analysis and caches results; subsequent queries are instant.

```bash
# Get a quick summary
lcre query summary /bin/ls

# Query with deep analysis (uses Ghidra)
lcre query summary /bin/ls --deep

# List sections with entropy info
lcre query sections /bin/ls

# Search strings
lcre query strings /bin/ls --pattern "error"
lcre query strings /bin/ls --limit 50 --offset 100

# Get string at specific offset
lcre query strings /bin/ls --at 0x1234

# List imports (filter by library or function)
lcre query imports /bin/ls
lcre query imports /bin/ls --library libc
lcre query imports /bin/ls --function printf

# List exports
lcre query exports /bin/ls --pattern main

# Query IOCs
lcre query iocs /bin/ls
lcre query iocs /bin/ls --type url

# Query heuristic matches
lcre query heuristics /bin/ls
lcre query heuristics /bin/ls --category packer

# List functions (requires --deep)
lcre query functions /bin/ls --deep
lcre query functions /bin/ls --name main --deep

# Get function details with callers/callees
lcre query function /bin/ls main --deep
lcre query function /bin/ls 0x401000 --deep

# Query cross-references
lcre query xrefs-to /bin/ls 0x401000 --deep
lcre query xrefs-from /bin/ls 0x401000 --deep

# Find call path between functions
lcre query call-path /bin/ls main printf --deep

# Hex dump bytes
lcre query bytes /bin/ls --offset 0x1000 --length 256

# Search for byte patterns
lcre query search-bytes /bin/ls --pattern "48 89 e5"

# Get decompiled function (requires --deep)
lcre query decompile /bin/ls main --deep
```

### Cache Management

```bash
# List all cached analyses
lcre cache list

# Show cache info for a binary
lcre cache info /bin/ls

# Clear cache for specific binary
lcre cache clear /bin/ls

# Clear cache by SHA256 hash
lcre cache clear abc123def456...

# Clear all caches
lcre cache clear
```

### Ghidra Deep Analysis

```bash
# Requires Ghidra installation
export GHIDRA_HOME=/path/to/ghidra

lcre ghidra analyze sample.exe --timeout 10m
lcre ghidra analyze sample.exe --decompile
```

### AI Assistant Integration

LCRE includes a `capabilities` command that outputs comprehensive JSON describing all commands, flags, and investigation workflows. This is designed for AI assistants like Claude Code to quickly understand what LCRE can do.

```bash
# Get full capabilities JSON
lcre capabilities

# Pipe to jq for specific info
lcre capabilities | jq '.workflows'
lcre capabilities | jq '.commands[] | select(.name == "query") | .subcommands'
```

See the [Claude Code Quick-Start Guide](docs/CLAUDE_CODE_GUIDE.md) for AI-assisted binary analysis workflows.

## Output Schema

### Analysis Result

```json
{
  "metadata": {
    "path": "/path/to/binary",
    "name": "binary.exe",
    "size": 123456,
    "md5": "...",
    "sha1": "...",
    "sha256": "...",
    "format": "PE",
    "arch": "x86_64",
    "bits": 64
  },
  "sections": [
    {
      "name": ".text",
      "virtual_addr": 4096,
      "virtual_size": 8192,
      "raw_size": 8192,
      "entropy": 6.5,
      "permissions": "r-x"
    }
  ],
  "imports": [
    {
      "library": "kernel32.dll",
      "function": "CreateFileA"
    }
  ],
  "exports": [],
  "strings": [],
  "heuristics": {
    "matches": [],
    "total_score": 0,
    "risk_level": "info"
  },
  "backend": "native",
  "duration_seconds": 0.5
}
```

## Heuristic Rules

| ID | Name | Category | Description |
|----|------|----------|-------------|
| PACKER001 | Packer Sections | packer | UPX, ASPack, MPRESS, VMProtect section names |
| PACKER002 | High Entropy | packer | Sections with entropy > 7.0 |
| IMPORT001 | Process Injection | injection | CreateRemoteThread, WriteProcessMemory, etc. |
| IMPORT002 | Anti-Debug | anti-debug | IsDebuggerPresent, CheckRemoteDebuggerPresent |
| IMPORT003 | Persistence | persistence | RegSetValueEx, CreateService |
| IMPORT004 | Crypto APIs | crypto | CryptEncrypt, CryptGenKey |
| STRING001 | Network IOCs | network | URLs, IPs, domains in strings |
| STRING002 | Suspicious Paths | evasion | /proc, Run keys, temp paths |
| SECTION001 | Tiny Text | anomaly | Small .text with large high-entropy sections |

## Exit Codes

- `0`: Success
- `1`: Error
- `2`: Partial success (some analysis failed)

## Environment Variables

- `GHIDRA_HOME`: Path to Ghidra installation
- `LCRE_SCRIPTS_PATH`: Path to LCRE Ghidra scripts

## License

MIT
