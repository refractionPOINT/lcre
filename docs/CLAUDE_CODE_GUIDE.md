# LCRE Quick-Start Guide for Claude Code

This guide helps Claude Code (and other AI assistants) quickly understand and use LCRE for binary forensics investigations.

## Self-Discovery

Run this first to understand all available commands and workflows:

```bash
lcre capabilities
```

This outputs JSON with:
- All commands and subcommands with their flags
- Investigation workflows with step-by-step guidance
- Example invocations for each command

## Quick Reference

### Initial Triage (Start Here)

```bash
# Fast risk assessment - always start with this
lcre query summary <binary>

# Check suspicious indicators
lcre query heuristics <binary>

# Extract IOCs (URLs, IPs, domains, file paths)
lcre query iocs <binary>
```

### Common Investigation Commands

| Task | Command |
|------|---------|
| Risk summary | `lcre query summary <binary>` |
| Suspicious indicators | `lcre query heuristics <binary>` |
| Extract IOCs | `lcre query iocs <binary>` |
| List imports | `lcre query imports <binary>` |
| List sections | `lcre query sections <binary>` |
| Search strings | `lcre query strings --pattern <term> <binary>` |
| Compare binaries | `lcre diff <binary_a> <binary_b>` |
| Full report | `lcre report <binary>` |

### Deep Analysis (Requires Ghidra)

```bash
# Enable deep analysis for function-level inspection
lcre query --deep functions <binary>
lcre query --deep decompile <binary> <function_name>
lcre query --deep callers <binary> <function_name>
lcre query --deep call-path <binary> <from_func> <to_func>
```

## Investigation Workflows

### 1. Quick Triage (Unknown Binary)

```bash
lcre query summary suspicious.exe        # Risk level + key findings
lcre query heuristics suspicious.exe     # All suspicious indicators
lcre query iocs suspicious.exe           # Network/file artifacts
```

### 2. Malware Deep Dive

```bash
lcre query summary malware.exe           # Initial assessment
lcre ghidra analyze --decompile malware.exe  # Deep analysis
lcre query --deep functions malware.exe  # List all functions
lcre query --deep decompile malware.exe main  # Examine entry point
lcre query --deep call-path malware.exe main suspicious_func  # Trace calls
```

### 3. IOC Extraction for Threat Intel

```bash
lcre iocs malware.exe                    # Quick extraction
lcre query strings --pattern http malware.exe   # Find URLs
lcre query strings --pattern "C:\\" malware.exe # Windows paths
lcre query imports --library ws2_32 malware.exe # Network APIs
```

### 4. Binary Comparison

```bash
lcre diff original.exe modified.exe      # Structural diff
lcre query summary original.exe          # Baseline
lcre query summary modified.exe          # Compare
lcre query heuristics modified.exe       # New indicators?
```

### 5. Packed Binary Detection

```bash
lcre query heuristics --category packer <binary>  # Packer signatures
lcre query sections <binary>             # Check entropy (>7.0 = packed)
lcre query imports <binary>              # Few imports = likely packed
```

## Output Formats

All commands support JSON (default) or Markdown output:

```bash
lcre query summary <binary>              # JSON output
lcre query summary <binary> -o md        # Markdown output
```

## Key Flags

| Flag | Description |
|------|-------------|
| `--deep` | Enable Ghidra deep analysis (query commands) |
| `-o json` / `-o md` | Output format |
| `-v` | Verbose output |
| `-t 5m` | Set timeout |

## Tips for AI-Assisted Analysis

1. **Always start with `query summary`** - it gives risk level and top findings
2. **Cache is automatic** - first query analyzes, subsequent queries are instant
3. **Use `--deep` sparingly** - it requires Ghidra and takes longer
4. **Check `heuristics` for red flags** - packer, injection, anti-debug indicators
5. **Extract IOCs early** - useful for threat intel correlation
6. **Use `diff` for versioning** - compare known-good vs suspicious

## Example Session

```bash
# Received suspicious binary for analysis
$ lcre query summary /tmp/suspicious.exe
{
  "risk_level": "high",
  "total_score": 85,
  "top_findings": [
    {"rule": "PACKER001", "name": "Packer Sections", "severity": "medium"},
    {"rule": "IMPORT001", "name": "Process Injection APIs", "severity": "high"}
  ],
  "counts": {"imports": 12, "strings": 234, "iocs": 8}
}

# High risk - check IOCs
$ lcre query iocs /tmp/suspicious.exe
{
  "urls": ["http://evil.com/beacon"],
  "ips": ["192.168.1.100"],
  "domains": ["evil.com"]
}

# Check what injection APIs are imported
$ lcre query imports --function CreateRemoteThread /tmp/suspicious.exe
```
