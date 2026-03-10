# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

LCRE (LimaCharlie Reverse Engineering) is a CLI tool for static binary analysis and forensics automation. It provides fast triage via native Go parsing for PE/ELF/Mach-O binaries and deep analysis via Ghidra headless integration. The tool is designed for AI assistant integration with machine-readable output formats.

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

# Using LimaCharlie

## Required Skill

**ALWAYS load the `lc-essentials:limacharlie-call` skill** before any LimaCharlie API operation. Never call LimaCharlie MCP tools directly.

## Critical Rules

**ALWAYS require the user to specify the organization or organizations they intend to operate on**, NEVER assume.

### 1. Never Call MCP Tools Directly

- **WRONG**: `mcp__plugin_lc-essentials_limacharlie__lc_call_tool(...)`
- **CORRECT**: Use Task tool with `subagent_type="lc-essentials:limacharlie-api-executor"`

### 2. Never Write LCQL Queries Manually

LCQL uses unique pipe-based syntax validated against org-specific schemas.

- **ALWAYS**: `generate_lcql_query()` first, then `run_lcql_query()` with the generated query
- Manual queries WILL fail or produce incorrect results

### 3. Never Generate D&R Rules Manually

Use AI generation tools:
1. `generate_dr_rule_detection()` - Generate detection YAML
2. `generate_dr_rule_respond()` - Generate response YAML
3. `validate_dr_rule_components()` - Validate before deploy

### 4. Never Calculate Timestamps Manually

LLMs consistently produce incorrect timestamp values.

**ALWAYS use bash:**
```bash
date +%s                           # Current time (seconds)
date -d '1 hour ago' +%s           # 1 hour ago
date -d '7 days ago' +%s           # 7 days ago
date -d '2025-01-15 00:00:00 UTC' +%s  # Specific date
```

### 5. OID is UUID, NOT Organization Name

- **WRONG**: `oid: "my-org-name"`
- **CORRECT**: `oid: "c1ffedc0-ffee-4a1e-b1a5-abc123def456"`
- Use `get_org_oid_by_name` to convert a single org name to OID (cached, efficient)
- Use `list_user_orgs` to list all accessible orgs with their OIDs

### 6. Timestamp Milliseconds vs Seconds

- Detection/event data: **milliseconds** (13 digits)
- API parameters (`get_historic_events`, `get_historic_detections`): **seconds** (10 digits)
- **ALWAYS** divide by 1000 when using detection timestamps for API queries

### 7. Never Fabricate Data

- Only report what APIs return
- Never estimate, infer, or extrapolate data
- Show "N/A" or "Data unavailable" for missing fields
- Never calculate costs (no pricing data in API)

### 8. Spawn Agents in Parallel

When processing multiple organizations or items:
- Use a SINGLE message with multiple Task calls
- Do NOT spawn agents sequentially
- Each agent handles ONE item, parent aggregates results

## Standard Operating Procedures (SOPs)

Organizations can define SOPs (Standard Operating Procedures) in LimaCharlie that guide how tasks are performed. SOPs can be large documents, so they are loaded lazily (similar to Claude Code Skills).

### On Conversation Start

Before running LimaCharlie operations:

**List all SOPs** using `list_sops` for each organization in scope, extracting only the name of the SOP and the `description` field.
**During operations** if an SOP description sounds like it applies to the current operation, call `get_sop` to get the actual procedure.
**Take into account** the contents of the fetched SOP, if a match is found, announce: "Following SOP: [sop-name] - [description]"

### Example Workflow

1. User signals intent to work on org 123
2. LLM lists SOPs on org 123: "malware-response" => description: "Standard procedure for malware incidents"
3. User asks to investigate a malware alert on org 123
4. LLM announces: "Following SOP: malware-response - Standard procedure for malware incidents"
5. LLM recognizes the "malware-response" SOP relates to this and calls `get_sop(name="malware-response")` to load the full procedure
6. LLM follows the documented steps from the loaded SOP content

## Sensor Selector Reference

Sensor selectors use [bexpr](https://github.com/hashicorp/go-bexpr) syntax to filter sensors. Use `*` to match all sensors.

### Available Fields

| Field | Type | Description |
|-------|------|-------------|
| `sid` | string | Sensor ID (UUID) |
| `oid` | string | Organization ID (UUID) |
| `iid` | string | Installation Key ID (UUID) |
| `plat` | string | Platform name (see values below) |
| `ext_plat` | string | Extended platform (for multi-platform adapters like Carbon Black) |
| `arch` | string | Architecture (see values below) |
| `hostname` | string | Sensor hostname |
| `ext_ip` | string | External IP address |
| `int_ip` | string | Internal IP address |
| `mac_addr` | string | MAC address |
| `did` | string | Device ID |
| `enroll` | int | Enrollment timestamp |
| `alive` | int | Last seen timestamp |
| `is_del` | bool | Sensor is deleted |
| `isolated` | bool | Sensor is network isolated |
| `should_isolate` | bool | Sensor should be isolated |
| `kernel` | bool | Kernel mode enabled |
| `sealed` | bool | Sensor is sealed |
| `should_seal` | bool | Sensor should be sealed |
| `tags` | string[] | Sensor tags (use `in` operator) |

### Platform Values (`plat`, `ext_plat`)

**EDR Platforms:** `windows`, `linux`, `macos`, `ios`, `android`, `chrome`, `vpn`

**Adapter/USP Platforms:** `text`, `json`, `gcp`, `aws`, `carbon_black`, `1password`, `office365`, `sophos`, `crowdstrike`, `msdefender`, `sentinel_one`, `okta`, `duo`, `github`, `slack`, `azure_ad`, `azure_monitor`, `entraid`, `zeek`, `cef`, `wel`, `xml`, `guard_duty`, `k8s_pods`, `wiz`, `proofpoint`, `box`, `cylance`, `fortigate`, `netscaler`, `paloalto_fw`, `iis`, `trend_micro`, `trend_worryfree`, `bitwarden`, `mimecast`, `hubspot`, `zendesk`, `pandadoc`, `falconcloud`, `sublime`, `itglue`, `canary_token`, `lc_event`, `email`, `mac_unified_logging`, `azure_event_hub_namespace`, `azure_key_vault`, `azure_kubernetes_service`, `azure_network_security_group`, `azure_sql_audit`

### Architecture Values (`arch`)

`x86`, `x64`, `arm`, `arm64`, `alpine64`, `chromium`, `wireguard`, `arml`, `usp_adapter`

### Example Selectors

```
plat == windows                           # All Windows sensors
plat == windows and arch == x64           # 64-bit Windows only
plat == linux and hostname contains "web" # Linux with "web" in hostname
"prod" in tags                            # Sensors tagged "prod"
plat == windows and not isolated          # Non-isolated Windows
ext_plat == windows                       # Carbon Black/Crowdstrike reporting Windows endpoints
```

### Extensions
Not all extensions have a configuration, to determine if an extension is subscribed to, use `list-extension-subscriptions`.
