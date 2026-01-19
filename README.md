# LCRE - Binary Forensics CLI Tool

LCRE is a CLI tool for static binary analysis and forensics automation. It provides fast triage via native Go parsing and deep analysis via Ghidra headless integration.
The goal of this CLI is not to implement new capabilities itself, but to stand on the shoulders of giants and unify the capabilities under a single CLI that LLMs can easily use.

## Features

- **Fast Analysis**: Native Go parsing for PE, ELF, and Mach-O binaries
- **YARA Integration**: Signature-based malware detection with custom rule support
- **Import Hash (ImpHash)**: Calculate import hashes for fuzzy malware matching
- **IOC Extraction**: Extract URLs, IPs, domains, paths, and registry keys
- **Binary Diff**: Compare two binaries to identify changes
- **Ghidra Integration**: Deep analysis with decompilation and call graph extraction
- **Multiple Output Formats**: JSON and Markdown
- **AI-Ready**: Machine-readable capabilities for AI assistant integration

## Installation

### From Source

```bash
go install github.com/refractionPOINT/lcre/cmd/lcre@latest
```

### Build from Repository

```bash
git clone https://github.com/refractionPOINT/lcre
cd lcre
make build
```

### Docker

```bash
docker build -t lcre .
docker run --rm -v $(pwd):/work lcre analyze /work/sample.exe
```

## Quick Reference

```
lcre analyze <binary>            # Fast one-shot analysis
lcre query <subcommand> <binary> # Cached interactive queries
lcre diff <binary_a> <binary_b>  # Compare two binaries
lcre cache <subcommand>          # Manage analysis cache
lcre capabilities                # Machine-readable command schema
```

## Usage

### Analyze (Fast Analysis)

```bash
# Basic analysis (strings and YARA enabled by default, markdown output)
lcre analyze sample.exe

# Disable strings extraction
lcre analyze sample.exe --strings=false

# Disable YARA scanning
lcre analyze sample.exe --yara=false

# Include IOC extraction
lcre analyze sample.exe --iocs

# Output as JSON
lcre analyze sample.exe -o json
```

### Binary Diff

```bash
lcre diff version1.exe version2.exe
```

### Interactive Query (Cached Analysis)

The query system provides instant access to analysis results. First query triggers analysis and caches results; subsequent queries are instant.

```bash
# Get a quick summary
lcre query summary /bin/ls

# Summary with full metadata details
lcre query summary /bin/ls --full

# List sections with entropy info
lcre query sections /bin/ls

# Search strings
lcre query strings /bin/ls --pattern "error"
lcre query strings /bin/ls --limit 50 --offset 100

# List imports (filter by library or function)
lcre query imports /bin/ls
lcre query imports /bin/ls --library libc

# List exports
lcre query exports /bin/ls

# Query IOCs
lcre query iocs /bin/ls
lcre query iocs /bin/ls --type url

# Get import hash (PE binaries only)
lcre query imphash sample.exe

# YARA signature scanning
lcre query yara sample.exe --rules /path/to/rules.yar

# Hex dump bytes
lcre query bytes /bin/ls 0x1000 256

# Search for byte patterns
lcre query search-bytes /bin/ls "48 89 e5"
```

### Ghidra Commands (Auto-triggered)

Commands that require Ghidra will automatically trigger deep analysis on first use. Ghidra must be installed and `GHIDRA_HOME` set.

```bash
# List functions (auto-triggers Ghidra analysis)
lcre query functions /bin/ls
lcre query functions /bin/ls --name main

# Get function details with callers/callees
lcre query function /bin/ls main

# Query cross-references
lcre query xrefs-to /bin/ls 0x401000
lcre query xrefs-from /bin/ls 0x401000

# Find function callers and callees
lcre query callers /bin/ls main
lcre query callees /bin/ls main

# Find call path between functions
lcre query call-path /bin/ls main printf

# Decompile a function
lcre query decompile /bin/ls main
```

### Cache Management

```bash
# List all cached analyses
lcre cache list

# Show cache info for a binary
lcre cache info /bin/ls

# Clear cache for specific binary
lcre cache clear /bin/ls

# Clear all caches
lcre cache clear
```

### AI Assistant Integration

LCRE includes a `capabilities` command that outputs comprehensive JSON describing all commands, flags, and investigation workflows.

```bash
# Get capabilities (markdown by default)
lcre capabilities

# Get as JSON for programmatic use
lcre capabilities -o json
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
    "bits": 64,
    "imphash": "abc123..."
  },
  "sections": [...],
  "imports": [...],
  "exports": [],
  "strings": [],
  "backend": "native",
  "duration_seconds": 0.5
}
```

## YARA Rules

LCRE integrates with the YARA command-line tool for signature-based malware detection.

```bash
# Scan with custom rules
lcre query yara sample.exe --rules /path/to/rules.yar

# Disable YARA scanning during analysis
lcre analyze sample.exe --yara=false
```

Community YARA rules:
- [YARA Rules Repository](https://github.com/Yara-Rules/rules)
- [Florian Roth's Signature Base](https://github.com/Neo23x0/signature-base)

## Environment Variables

- `GHIDRA_HOME`: Path to Ghidra installation (required for function/decompile commands)
- `LCRE_SCRIPTS_PATH`: Path to LCRE Ghidra scripts

## Optional Dependencies

- **YARA**: For signature-based malware detection (`apt install yara` or `brew install yara`)
- **Ghidra**: For function extraction and decompilation

## License

Apache License 2.0
