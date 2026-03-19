# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

LCRE (LimaCharlie Reverse Engineering) is a CLI tool for static binary analysis and forensics automation. It provides fast triage via native Go parsing for PE/ELF/Mach-O binaries, deep analysis via Ghidra headless integration, and enrichment from external analysis tools (capa, diec, floss, etc.). The tool is designed for AI assistant integration with machine-readable output formats.

## Build and Test Commands

```bash
make build          # Build binary to bin/lcre
make test           # Run all tests with coverage
make test-race      # Run tests with race detector (requires CGO_ENABLED=1)
make test-short     # Run quick tests only
make lint           # Run golangci-lint
make fmt            # Format code
make vet            # Run go vet
make dev            # Format, vet, test, and build
```

Run a single test:
```bash
go test -v -run TestFunctionName ./internal/package/...
```

## Architecture

### Two-Tier Analysis System

1. **Native Backend** (`internal/backend/native/`): Fast Go-native parsing for PE, ELF, and Mach-O binaries. Handles headers, imports, exports, sections, strings, and entropy calculation. Default backend.

2. **Ghidra Backend** (`internal/backend/ghidra/`): Deep analysis via headless Ghidra. Provides function extraction, decompilation, call graphs, and cross-references. Auto-triggered when Ghidra-specific commands are run.

### Backend Interface

All backends implement `backend.Backend` interface in `internal/backend/backend.go`. Backends self-register via init() to `backend.DefaultRegistry`.

### Caching Layer

`internal/cache/` provides SQLite-backed caching keyed by binary SHA256. Cache stores:
- Analysis results in SQLite (`analysis.db`)
- Quick-load metadata (`metadata.json`)
- Decompiled functions as `.c` files in `decompiled/` subdirectory

Cache location: `~/.cache/lcre/<sha256>/`

### CLI Structure

- `internal/cli/root.go`: Root command setup with global flags (`-o`, `-v`, `-t`)
- `internal/cli/analyze.go`: One-shot analysis command
- `internal/cli/query.go`: Parent for all cached query subcommands
- `internal/cli/query_*.go`: Individual query subcommands (summary, strings, imports, functions, decompile, etc.)

### Enrichment System

`internal/enrichment/` provides parsers for external tool output (e.g., from REMnux MCP).
The `lcre enrich` command imports tool results into the cache. Dedicated parsers exist for
capa, diec, and floss; all other tools have their raw output stored as-is.

- `internal/enrichment/enrichment.go`: Parser registry and `ParseToolOutput()` entry point
- `internal/enrichment/capa.go`: capa JSON -> capabilities with ATT&CK/MBC mappings
- `internal/enrichment/diec.go`: diec JSON -> packer/compiler detections
- `internal/enrichment/floss.go`: FLOSS JSON -> obfuscated/decoded strings
- `internal/cli/enrich.go`: `lcre enrich` command
- `internal/cli/query_capabilities.go`: `lcre query capabilities`
- `internal/cli/query_packer.go`: `lcre query packer`
- `internal/cli/query_enrichments.go`: `lcre query enrichments` / `lcre query enrichment`

### Data Models

`internal/model/` defines all data structures:
- `AnalysisResult`: Top-level output containing metadata, sections, imports, exports, strings, functions
- `BinaryMetadata`: File info, hashes, format, architecture
- `Capability`: Behavioral capability with ATT&CK/MBC mappings (from capa)
- `PackerDetection`: Packer/compiler/linker detection (from diec)
- `Enrichment`: Raw tool output storage
- Query commands filter and return subsets of cached AnalysisResult

### Output Formatters

`internal/output/` handles JSON and Markdown formatting. All commands default to Markdown (`-o md`), use `-o json` for JSON.

## Global Flags

- `-o, --output`: Output format (`json`, `md`) - default: `md`
- `-t, --timeout`: Analysis timeout - default: `2m0s`
- `-v, --verbose`: Verbose output

## Investigation Workflows

### Quick Triage
Fast initial assessment of a suspicious binary:
```bash
lcre query summary <binary>      # Overview with YARA matches and counts
lcre query yara <binary>         # Check YARA signature matches
lcre query iocs <binary>         # Extract IOCs (URLs, IPs, domains, paths)
```

### Malware Analysis
Deep analysis for confirmed or suspected malware:
```bash
lcre query summary <binary>                        # Initial risk assessment
lcre query functions <binary>                      # List all functions (triggers Ghidra)
lcre query decompile <binary> <suspicious_func>    # Examine suspicious functions
lcre query call-path <binary> main <target_func>   # Trace how malicious functions are reached
```

### IOC Extraction
Comprehensive IOC extraction for threat intelligence:
```bash
lcre query iocs <binary>                           # Extract IOCs from cached analysis
lcre query strings --pattern http <binary>         # Find URL-related strings
lcre query strings --pattern "C:\\" <binary>       # Find Windows file paths
lcre query imports --library ws2_32 <binary>       # Check for networking imports
lcre query imports --library wininet <binary>      # Check for HTTP/internet imports
```

### Packed Binary Analysis
Handle packed or obfuscated binaries:
```bash
lcre query yara <binary>         # Check for packer signatures (UPX, VMProtect, etc.)
lcre query sections <binary>     # Check section entropy (high entropy suggests packing)
lcre query bytes <binary> 0x0 256  # Examine PE header for packer artifacts
lcre query imports <binary>      # Check imports (packed binaries often have few imports)
```

### Function Tracing
Trace execution flow through functions:
```bash
lcre query functions --name <pattern> <binary>   # Find functions matching pattern
lcre query function <binary> <func_name>         # Get function details with callers/callees
lcre query callers <binary> <func_name>          # Find all functions that call this function
lcre query callees <binary> <func_name>          # Find all functions called by this function
lcre query decompile <binary> <func_name>        # Examine decompiled code
```

### Binary Comparison
Compare two binary versions to identify changes:
```bash
lcre diff <binary_a> <binary_b>    # Get structural differences
lcre query summary <binary_a>      # Get summary of first binary
lcre query summary <binary_b>      # Get summary of second binary
lcre query yara <binary_b>         # Check new binary for malware signatures
```

### REMnux Enrichment
When a REMnux MCP server is available, use it to enrich LCRE analysis with external tools.
Run tools on the REMnux server, save output, then import into LCRE's cache:
```bash
# 1. Analyze with LCRE first
lcre analyze <binary>

# 2. Upload binary to REMnux and run tools (via MCP)
#    Save tool output as JSON files (use -j or --json flags where available)

# 3. Import results into LCRE cache
lcre enrich <binary> --tool capa --input capa_output.json      # Capabilities + ATT&CK
lcre enrich <binary> --tool diec --input diec_output.json      # Packer/compiler detection
lcre enrich <binary> --tool floss --input floss_output.json    # Obfuscated strings
lcre enrich <binary> --tool <any_tool> --input output.json     # Any tool (raw storage)

# 4. Query enriched data
lcre query capabilities <binary>                   # Behavioral capabilities
lcre query capabilities <binary> --namespace anti  # Filter by namespace
lcre query packer <binary>                         # Packer/compiler detections
lcre query enrichments <binary>                    # List all enrichments
lcre query enrichment <binary> <tool>              # View raw tool output
```

Tools with dedicated parsers (capa, diec, floss) extract structured data into queryable
tables. All other tools have their output stored as-is and retrievable via `query enrichment`.
Both JSON and plain text tool output are accepted.

## Environment Variables

- `GHIDRA_HOME`: Path to Ghidra installation (required for function/decompile commands)
- `LCRE_SCRIPTS_PATH`: Path to LCRE Ghidra scripts

## Optional Dependencies

- **YARA**: For signature-based scanning (`internal/yara/`)
- **Ghidra**: For deep analysis (function extraction, decompilation)

## Archive Extraction Convention

**Always use `7z` (p7zip) instead of `unzip`** for extracting zip archives. The classic `unzip` utility only supports PKZIP encryption up to v4.6 and fails on archives using AES-256 encryption (PK compat v5.1), which is common in password-protected malware sample archives. The `7z` command handles all zip encryption methods.

```bash
# Correct - use 7z
7z x -y -o"/output/dir" archive.zip
7z x -y -p"infected" -o"/output/dir" encrypted_archive.zip

# Wrong - do not use unzip
unzip archive.zip -d /output/dir
```

Required packages: `p7zip-full` (Debian/Ubuntu) or `p7zip` (other distros).
