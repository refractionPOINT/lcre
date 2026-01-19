# LCRE - Binary Forensics CLI Tool

LCRE is a CLI tool for static binary analysis and forensics automation. It provides fast triage via native Go parsing and deep analysis via Ghidra headless integration.

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
lcre analyze <binary>           # Fast one-shot analysis
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
lcre query exports /bin/ls
lcre query exports /bin/ls --name main

# Query IOCs
lcre query iocs /bin/ls
lcre query iocs /bin/ls --type url

# Get import hash (PE binaries only)
lcre query imphash sample.exe

# YARA signature scanning
lcre query yara sample.exe --rules /path/to/rules.yar

# List functions (requires --deep)
lcre query functions /bin/ls --deep
lcre query functions /bin/ls --name main --deep

# Get function details with callers/callees
lcre query function /bin/ls main --deep
lcre query function /bin/ls 0x401000 --deep

# Query cross-references
lcre query xrefs-to /bin/ls 0x401000 --deep
lcre query xrefs-from /bin/ls 0x401000 --deep

# Find function callers and callees
lcre query callers /bin/ls main --deep
lcre query callees /bin/ls main --deep

# Find call path between functions
lcre query call-path /bin/ls main printf --deep

# Hex dump bytes (offset and length as positional args)
lcre query bytes /bin/ls 0x1000 256

# Search for byte patterns (pattern as positional arg)
lcre query search-bytes /bin/ls "48 89 e5"

# Get decompiled function (requires --deep)
lcre query decompile /bin/ls main --deep
```

### Deep Analysis with Ghidra

For deep analysis including function extraction, decompilation, and call graphs, use the `--deep` flag with any query command:

```bash
# Requires Ghidra installation
export GHIDRA_HOME=/path/to/ghidra

# First query with --deep triggers Ghidra analysis
lcre query summary /bin/ls --deep

# Subsequent queries use cached Ghidra results
lcre query functions /bin/ls --deep
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

### Example: AI-Powered Malware Analysis

We conducted an experiment where Claude Code was given an unknown malware sample and asked to determine if it was malicious using only LCRE commands. The AI performed:

- Initial analysis and hash extraction
- Section entropy analysis (detected packing)
- IOC extraction (found Bitcoin addresses)
- String searches (found ransomware artifacts)
- Import analysis (identified crypto and persistence APIs)
- Deep analysis with Ghidra (decompiled key functions)

The AI correctly identified the sample as ransomware with HIGH confidence, documenting specific CLI evidence for every finding.

**[Read the Full Analysis Report](docs/EXAMPLE_AI_MALWARE_ANALYSIS.md)** - A detailed walkthrough of the commands used and evidence discovered.

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
  "pe_info": {
    "checksum": 0,
    "image_base": 4194304,
    "section_alignment": 4096,
    "entry_point_section": ".text"
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
  "backend": "native",
  "duration_seconds": 0.5
}
```

## YARA Rules

LCRE integrates with the YARA command-line tool for signature-based malware detection. You must provide your own YARA rules files.

### Using YARA Rules

```bash
# Scan with a custom YARA rules file
lcre query yara sample.exe --rules /path/to/rules.yar

# Scan with a directory of YARA rules
lcre query yara sample.exe --rules /path/to/rules/

# Disable YARA scanning during analysis
lcre analyze sample.exe --yara=false
```

### Example Rules

You can find community YARA rules from sources like:
- [YARA Rules Repository](https://github.com/Yara-Rules/rules)
- [ReversingLabs YARA Rules](https://github.com/reversinglabs/reversinglabs-yara-rules)
- [Florian Roth's Signature Base](https://github.com/Neo23x0/signature-base)

## Exit Codes

- `0`: Success
- `1`: Error
- `2`: Partial success (some analysis failed)

## Dependencies

LCRE uses the following external Go packages:

| Package | Version | Purpose |
|---------|---------|---------|
| [github.com/spf13/cobra](https://github.com/spf13/cobra) | v1.8.0 | CLI framework for command structure, flags, and help text |
| [modernc.org/sqlite](https://gitlab.com/cznic/sqlite) | v1.44.1 | Pure Go SQLite driver for caching analysis results |

All other functionality uses Go standard library packages including `debug/pe`, `debug/elf`, and `debug/macho` for binary parsing.

## Environment Variables

- `GHIDRA_HOME`: Path to Ghidra installation
- `LCRE_SCRIPTS_PATH`: Path to LCRE Ghidra scripts

## Optional Dependencies

- **YARA**: For signature-based malware detection (`apt install yara` or `brew install yara`). YARA scanning is enabled by default in analysis.

## License

Apache License 2.0
