# LCRE Quick-Start Guide for Claude Code

This guide helps Claude Code (and other AI assistants) quickly understand and use LCRE for binary forensics investigations.

## Self-Discovery

Run this first to understand all available commands and workflows:

```bash
lcre capabilities
```

This outputs (markdown by default, or JSON with `-o json`):
- All commands and subcommands with their flags
- Investigation workflows with step-by-step guidance
- Example invocations for each command

## Quick Reference

### Command Structure

```
lcre analyze <binary>            # Fast one-shot analysis
lcre query <subcommand> <binary> # Cached interactive queries
lcre diff <binary_a> <binary_b>  # Compare two binaries
lcre cache <subcommand>          # Manage analysis cache
lcre capabilities                # Machine-readable command schema
```

### Initial Triage (Start Here)

```bash
# Fast risk assessment - always start with this
lcre query summary <binary>

# Summary with full metadata details (hashes, compiler, timestamp)
lcre query summary <binary> --full

# Extract IOCs (URLs, IPs, domains, file paths)
lcre query iocs <binary>
```

### Common Investigation Commands

| Task | Command |
|------|---------|
| Quick summary | `lcre query summary <binary>` |
| Full metadata | `lcre query summary <binary> --full` |
| Extract IOCs | `lcre query iocs <binary>` |
| List imports | `lcre query imports <binary>` |
| List sections | `lcre query sections <binary>` |
| Search strings | `lcre query strings <binary> --pattern <term>` |
| Compare binaries | `lcre diff <binary_a> <binary_b>` |
| Full analysis | `lcre analyze <binary>` |

### Ghidra Commands (Auto-triggered)

Commands that require Ghidra automatically trigger deep analysis on first use. No flags needed - just run the command and Ghidra analysis happens if required.

```bash
# List all functions (auto-triggers Ghidra)
lcre query functions <binary>
lcre query functions <binary> --name main

# Decompile a function
lcre query decompile <binary> <function_name>

# Find callers/callees
lcre query callers <binary> <function_name>
lcre query callees <binary> <function_name>

# Trace call path between functions
lcre query call-path <binary> <from_func> <to_func>

# Query cross-references
lcre query xrefs-to <binary> <address>
lcre query xrefs-from <binary> <address>
```

## Investigation Workflows

### 1. Quick Triage (Unknown Binary)

```bash
lcre query summary suspicious.exe        # Quick overview
lcre query summary suspicious.exe --full # Full metadata details
lcre query iocs suspicious.exe           # Network/file artifacts
```

### 2. Malware Deep Dive

```bash
lcre query summary malware.exe           # Initial assessment
lcre query functions malware.exe         # List all functions (auto-triggers Ghidra)
lcre query decompile malware.exe main    # Examine entry point
lcre query call-path malware.exe main suspicious_func  # Trace calls
```

### 3. IOC Extraction for Threat Intel

```bash
lcre analyze malware.exe --iocs          # Full analysis with IOC extraction
lcre query iocs malware.exe              # Query cached IOCs
lcre query strings malware.exe --pattern http   # Find URLs
lcre query strings malware.exe --pattern "C:\\" # Windows paths
lcre query imports malware.exe --library ws2_32 # Network APIs
```

### 4. Binary Comparison

```bash
lcre diff original.exe modified.exe      # Structural diff
lcre query summary original.exe          # Baseline
lcre query summary modified.exe          # Compare
```

### 5. Packed Binary Detection

```bash
lcre query sections <binary>             # Check entropy (>7.0 = packed)
lcre query imports <binary>              # Few imports = likely packed
```

## Output Formats

All commands output Markdown by default. Use `-o json` for JSON:

```bash
lcre query summary <binary>              # Markdown output (default)
lcre query summary <binary> -o json      # JSON output
lcre analyze <binary> -o json            # JSON output
```

## Key Flags

| Flag | Description |
|------|-------------|
| `-o json` / `-o md` | Output format (default: md) |
| `-v` | Verbose output |
| `-t 5m` | Set timeout |
| `--full` | Include full metadata (summary command) |
| `--iocs` | Extract IOCs (analyze command) |

## Tips for AI-Assisted Analysis

1. **Always start with `query summary`** - it gives format, architecture, and counts
2. **Use `--full` for detailed metadata** - includes all hashes, compiler info, timestamps
3. **Cache is automatic** - first query analyzes, subsequent queries are instant
4. **Ghidra commands auto-trigger** - no need for special flags, just run the command
5. **Extract IOCs early** - useful for threat intel correlation
6. **Use `diff` for versioning** - compare known-good vs suspicious

## Example Session

```bash
# Received suspicious binary for analysis
$ lcre query summary /tmp/suspicious.exe
# Binary Summary

**Format:** PE | **Arch:** x86_64 | **Size:** 245.3 KB
**SHA256:** a1b2c3d4...

## YARA Matches (2)
- suspicious_import [malware]
- packed_binary [packer]

## Counts
- Sections: 5
- Imports: 12
- Exports: 0
- Strings: 234
- Functions: 0
- IOCs: 8

# Check IOCs
$ lcre query iocs /tmp/suspicious.exe
# IOCs

## URLs (1)
- http://evil.com/beacon

## IPs (1)
- 192.168.1.100

## Domains (1)
- evil.com

# Deep dive - decompile main function (Ghidra auto-triggered)
$ lcre query decompile /tmp/suspicious.exe main
```

## Environment Variables

- `GHIDRA_HOME`: Path to Ghidra installation (required for function/decompile commands)
- `LCRE_SCRIPTS_PATH`: Path to LCRE Ghidra scripts

## Cache Management

```bash
lcre cache list              # List all cached analyses
lcre cache info <binary>     # Show cache info for a binary
lcre cache clear <binary>    # Clear cache for specific binary
lcre cache clear             # Clear all caches
```
