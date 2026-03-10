# lcre v1.0.0

Binary Forensics CLI for static analysis, malware investigation, and reverse engineering automation

## Global Flags

- `-o, --output` (string): Output format (json, md) (default: md)
- `-t, --timeout` (duration): Analysis timeout (default: 2m0s)
- `-v, --verbose` (bool): Verbose output (default: false)

## Commands

### analyze

**Usage:** `lcre analyze <binary>`

Analyze a binary file

**Flags:**
- `--iocs`: Extract IOCs from strings
- `--max-strings`: Maximum strings to extract
- `--min-string-len`: Minimum string length to extract
- `--strings`: Extract strings from binary
- `--yara`: Run YARA scan

**Examples:**
- `lcre analyze /path/to/suspicious.exe` - Fast initial analysis of a binary
- `lcre analyze --strings=false /path/to/binary` - Analysis without string extraction
- `lcre analyze --iocs /path/to/binary` - Include IOC extraction

### cache

**Usage:** `lcre cache`

Manage analysis cache

#### cache clear

**Usage:** `lcre cache clear [binary_or_hash]`

Clear cached analyses

**Examples:**
- `lcre cache clear` - Clear all cached analyses
- `lcre cache clear /path/to/binary` - Clear cache for specific binary

#### cache info

**Usage:** `lcre cache info <binary>`

Show cache info for a binary

**Examples:**
- `lcre cache info /path/to/binary` - Show cache details for binary

#### cache list

**Usage:** `lcre cache list`

List cached analyses

**Examples:**
- `lcre cache list` - List all cached analyses

### capabilities

**Usage:** `lcre capabilities`

Output machine-readable capabilities for AI assistants

**Flags:**
- `--help`: help for capabilities

### diff

**Usage:** `lcre diff <binary_a> <binary_b>`

Compare two binaries

**Examples:**
- `lcre diff old_version.exe new_version.exe` - Compare two binary versions

### enrich

**Usage:** `lcre enrich <binary>`

Import external tool output into the analysis cache

**Flags:**
- `--input`: Path to tool output JSON file
- `--tool`: Tool name (e.g., capa, diec, floss)

**Examples:**
- `lcre enrich sample.exe --tool capa --input capa.json` - Import capa capabilities
- `lcre enrich sample.exe --tool diec --input diec.json` - Import packer/compiler detections
- `lcre enrich sample.exe --tool floss --input floss.json` - Import obfuscated strings
- `lcre enrich sample.exe --tool peframe --input peframe.json` - Import any tool output

### query

**Usage:** `lcre query <binary> <subcommand>`

Query binary analysis data

#### query bytes

**Usage:** `lcre query bytes <binary> <offset> <length>`

Hex dump bytes

**Examples:**
- `lcre query bytes /path/to/binary 0x0 64` - Hex dump 64 bytes from offset 0

#### query call-path

**Usage:** `lcre query call-path <binary> <from> <to>`

Find call path between functions

**Examples:**
- `lcre query call-path /path/to/binary main evil_func` - Find call path between functions

#### query callees

**Usage:** `lcre query callees <binary> <function>`

Find function callees

**Examples:**
- `lcre query callees /path/to/binary func_name` - Find what this function calls

#### query callers

**Usage:** `lcre query callers <binary> <function>`

Find function callers

**Examples:**
- `lcre query callers /path/to/binary func_name` - Find who calls this function

#### query capabilities

**Usage:** `lcre query capabilities <binary>`

Show detected capabilities (from capa enrichment)

**Examples:**
- `lcre query capabilities /path/to/binary` - List all detected capabilities
- `lcre query capabilities /path/to/binary --namespace anti-analysis` - Filter by namespace

#### query decompile

**Usage:** `lcre query decompile <binary> <function>`

Decompile a function

**Examples:**
- `lcre query decompile /path/to/binary main` - Decompile function

#### query enrichment

**Usage:** `lcre query enrichment <binary> <tool>`

Show raw output from an external tool enrichment

**Examples:**
- `lcre query enrichment /path/to/binary capa` - View raw capa output

#### query enrichments

**Usage:** `lcre query enrichments <binary>`

List external tool enrichments

**Examples:**
- `lcre query enrichments /path/to/binary` - List all imported enrichments

#### query exports

**Usage:** `lcre query exports <binary>`

List exports

**Examples:**
- `lcre query exports /path/to/binary` - List all exports

#### query function

**Usage:** `lcre query function <binary> <name_or_address>`

Get function details

**Examples:**
- `lcre query function /path/to/binary main` - Get function details
- `lcre query function /path/to/binary 0x401000` - Get function by address

#### query functions

**Usage:** `lcre query functions <binary>`

List functions

**Examples:**
- `lcre query functions /path/to/binary` - List functions (requires deep analysis)

#### query imphash

**Usage:** `lcre query imphash <binary>`

Get the import hash (imphash) of a PE binary

#### query imports

**Usage:** `lcre query imports <binary>`

List imports

**Examples:**
- `lcre query imports /path/to/binary` - List all imports
- `lcre query imports --library kernel32 /path/to/binary` - Filter by library

#### query iocs

**Usage:** `lcre query iocs <binary>`

List IOCs

**Examples:**
- `lcre query iocs /path/to/binary` - Get extracted IOCs from cache

#### query packer

**Usage:** `lcre query packer <binary>`

Show packer/compiler detections (from diec enrichment)

**Examples:**
- `lcre query packer /path/to/binary` - Show packer/compiler detections
- `lcre query packer /path/to/binary --type packer` - Filter by detection type

#### query search-bytes

**Usage:** `lcre query search-bytes <binary> <pattern>`

Search byte pattern

**Examples:**
- `lcre query search-bytes /path/to/binary 4D5A9000` - Search for byte pattern

#### query sections

**Usage:** `lcre query sections <binary>`

List binary sections

**Examples:**
- `lcre query sections /path/to/binary` - List binary sections with entropy

#### query strings

**Usage:** `lcre query strings <binary>`

Search strings

**Examples:**
- `lcre query strings /path/to/binary` - List extracted strings
- `lcre query strings --pattern http /path/to/binary` - Search for pattern

#### query summary

**Usage:** `lcre query summary <binary>`

Get analysis summary

**Examples:**
- `lcre query summary /path/to/binary` - Get analysis summary with YARA matches and counts
- `lcre query summary --full /path/to/binary` - Get summary with full metadata details

#### query xrefs-from

**Usage:** `lcre query xrefs-from <binary> <address>`

Find references from address

**Examples:**
- `lcre query xrefs-from /path/to/binary 0x401000` - Find references from address

#### query xrefs-to

**Usage:** `lcre query xrefs-to <binary> <address>`

Find references to address

**Examples:**
- `lcre query xrefs-to /path/to/binary 0x401000` - Find references to address

#### query yara

**Usage:** `lcre query yara <binary>`

Scan binary with YARA rules

## Workflows

### quick_triage

Fast initial assessment of a suspicious binary

**When to use:** First step when investigating any unknown binary. Provides summary and key indicators without deep analysis.

**Steps:**
1. `lcre query summary <binary>` - Get overview with YARA matches and counts
2. `lcre query yara <binary>` - Check YARA signature matches
3. `lcre query iocs <binary>` - Extract IOCs (URLs, IPs, domains, file paths)

### malware_analysis

Deep analysis workflow for confirmed or suspected malware

**When to use:** When quick triage indicates high risk or suspicious behavior requiring deeper investigation.

**Steps:**
1. `lcre query summary <binary>` - Initial risk assessment
2. `lcre query summary <binary>` - Trigger deep analysis with Ghidra
3. `lcre query functions <binary>` - List all functions for review
4. `lcre query decompile <binary> <suspicious_func>` - Examine suspicious functions
5. `lcre query call-path <binary> main <target_func>` - Trace how malicious functions are reached

### binary_comparison

Compare two binary versions to identify changes

**When to use:** When comparing a known-good binary against a potentially modified version, or tracking malware evolution.

**Steps:**
1. `lcre diff <binary_a> <binary_b>` - Get structural differences (sections, imports, exports)
2. `lcre query summary <binary_a>` - Get summary of first binary
3. `lcre query summary <binary_b>` - Get summary of second binary
4. `lcre query yara <binary_b>` - Check new binary for malware signatures

### ioc_extraction

Comprehensive IOC extraction for threat intelligence

**When to use:** When building threat intelligence from a malware sample - extracting network indicators, file paths, and other artifacts.

**Steps:**
1. `lcre query iocs <binary>` - Extract IOCs from cached analysis
2. `lcre query strings --pattern http <binary>` - Find URL-related strings
3. `lcre query strings --pattern "C:\\" <binary>` - Find Windows file paths
4. `lcre query imports --library ws2_32 <binary>` - Check for networking imports
5. `lcre query imports --library wininet <binary>` - Check for HTTP/internet imports

### function_tracing

Trace execution flow through functions

**When to use:** When understanding how a specific functionality is implemented or how a suspicious function is called.

**Steps:**
1. `lcre query functions --name <pattern> <binary>` - Find functions matching pattern
2. `lcre query function <binary> <func_name>` - Get function details including callers/callees
3. `lcre query callers <binary> <func_name>` - Find all functions that call this function
4. `lcre query callees <binary> <func_name>` - Find all functions called by this function
5. `lcre query decompile <binary> <func_name>` - Examine decompiled code

### packed_binary_analysis

Handle packed or obfuscated binaries

**When to use:** When YARA detects packing or section entropy is high. The binary needs to be unpacked first for meaningful analysis.

**Steps:**
1. `lcre query yara <binary>` - Check for packer signatures (UPX, VMProtect, etc.)
2. `lcre query sections <binary>` - Check section entropy (high entropy suggests packing)
3. `lcre query bytes <binary> 0x0 256` - Examine PE header for packer artifacts
4. `lcre query imports <binary>` - Check imports (packed binaries often have few imports)

### string_analysis

Detailed string analysis for artifact discovery

**When to use:** When looking for specific artifacts like config data, C2 servers, credentials, or debugging strings.

**Steps:**
1. `lcre query strings <binary>` - Get all strings
2. `lcre query strings --pattern password <binary>` - Search for credential-related strings
3. `lcre query strings --pattern config <binary>` - Search for configuration strings
4. `lcre query strings --at 0x<offset> <binary>` - Get string at specific offset

### remnux_enrichment

Enrich LCRE analysis with external REMnux tools via MCP

**When to use:** When a REMnux MCP server is available. Adds behavioral capabilities (capa), packer/compiler detection (diec), obfuscated strings (floss), and any other REMnux tool output to the LCRE cache.

**Steps:**
1. `lcre analyze <binary>` - Run native LCRE analysis first
2. `(upload binary to REMnux via MCP)` - Use mcp__remnux__upload_from_host to send binary
3. `(run capa -j on REMnux)` - Use mcp__remnux__run_tool for capa with JSON output
4. `(run diec --json on REMnux)` - Use mcp__remnux__run_tool for diec with JSON output
5. `(run floss -j on REMnux)` - Use mcp__remnux__run_tool for floss with JSON output
6. `lcre enrich <binary> --tool capa --input capa.json` - Import capa capabilities into cache
7. `lcre enrich <binary> --tool diec --input diec.json` - Import packer/compiler detections
8. `lcre enrich <binary> --tool floss --input floss.json` - Import obfuscated strings
9. `lcre query capabilities <binary>` - Review behavioral capabilities with ATT&CK mappings
10. `lcre query packer <binary>` - Check packer/compiler detections

