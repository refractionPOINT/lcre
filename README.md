# LCRE - Binary Forensics CLI Tool

LCRE is a CLI tool for static binary analysis and forensics automation. It provides fast triage via native Go parsing and deep analysis via Ghidra headless integration.

## Features

- **Fast Triage**: Native Go parsing for PE, ELF, and Mach-O binaries
- **Heuristic Analysis**: Detect packers, suspicious imports, and malware indicators
- **YARA Integration**: Signature-based malware detection with embedded rules for 13+ malware families
- **Import Hash (ImpHash)**: Calculate import hashes for fuzzy malware matching
- **PE Anomaly Detection**: Detect RWX sections, timestamp anomalies, metadata mismatches
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
# Basic triage (strings and heuristics enabled by default)
lcre triage sample.exe

# Disable strings extraction
lcre triage sample.exe --strings=false

# Disable heuristic analysis
lcre triage sample.exe --heuristics=false

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
lcre query exports /bin/ls
lcre query exports /bin/ls --name main

# Query IOCs
lcre query iocs /bin/ls
lcre query iocs /bin/ls --type url

# Query heuristic matches
lcre query heuristics /bin/ls
lcre query heuristics /bin/ls --category packer

# Get import hash (PE binaries only)
lcre query imphash sample.exe

# YARA signature scanning
lcre query yara sample.exe
lcre query yara sample.exe --rules /path/to/rules.yar
lcre query yara --list-families  # List covered malware families

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

lcre ghidra analyze sample.exe --ghidra-timeout 10m
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

### Example: AI-Powered Malware Analysis

We conducted an experiment where Claude Code was given an unknown malware sample and asked to determine if it was malicious using only LCRE commands. The AI performed:

- Initial triage and hash extraction
- Section entropy analysis (detected packing)
- IOC extraction (found Bitcoin addresses)
- String searches (found ransomware artifacts)
- Import analysis (identified crypto and persistence APIs)
- Ghidra deep analysis (decompiled key functions)

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

LCRE includes a comprehensive set of heuristic rules for detecting malware indicators. Each rule produces a severity-weighted score that contributes to the overall risk assessment.

### Rule Summary

| ID | Name | Category | Severity | Description |
|----|------|----------|----------|-------------|
| PACKER001 | Packer Sections | packer | Medium | Known packer section names |
| PACKER002 | High Entropy | packer | Medium | Encrypted/compressed sections |
| IMPORT001 | Process Injection | injection | High | Code injection APIs |
| IMPORT002 | Anti-Debug | anti-debug | Medium | Debugger detection APIs |
| IMPORT003 | Persistence | persistence | High | System persistence APIs |
| IMPORT004 | Crypto APIs | crypto | Low | Encryption APIs |
| IMPORT005 | Minimal Imports | packer | Medium | Suspiciously few imports |
| IMPORT006 | Low-Level Disk Access | evasion | High | Raw disk/MBR access |
| STRING001 | Network IOCs | network | Medium | URLs, IPs, domains |
| STRING002 | Suspicious Paths | evasion | Medium | Sensitive system paths |
| STRING003 | Suspicious Strings | anomaly | High | Ransomware/malware indicators |
| SECTION001 | Tiny Text | anomaly | Medium | Anomalous section sizes |
| ANOMALY001 | Entry Point Anomaly | anomaly | Medium | Unusual entry point location |
| ANOMALY002 | RWX Section | anomaly | High | Self-modifying code indicator |
| ANOMALY003 | Timestamp Anomaly | anomaly | Low | Suspicious compile times |
| ANOMALY004 | Section Count Anomaly | anomaly | Low | Unusual structure |
| ANOMALY005 | Metadata Mismatch | evasion | Medium | Vendor impersonation |
| YARA001 | YARA Signature Match | anomaly | Critical | Known malware signatures |
| YARA002 | Malware Family Patterns | anomaly | High | Malware family patterns |

### Packer Detection

**PACKER001 - Packer Sections**: Detects known packer/protector section names including:
- UPX: `UPX0`, `UPX1`, `UPX2`, `.upx`
- ASPack: `.aspack`, `.adata`
- VMProtect: `.vmp0`, `.vmp1`, `.vmp2`
- Themida: `.themida`
- Enigma: `.enigma1`, `.enigma2`
- PECompact: `.pec`, `.pec1`, `.pec2`
- And others: MPRESS, NsPack, Petite, SVK Protector

**PACKER002 - High Entropy**: Flags sections with Shannon entropy > 7.0 (max is 8.0), indicating encrypted or compressed data. Legitimate code typically has entropy between 5.0-6.5.

**IMPORT005 - Minimal Imports**: Detects PE binaries with fewer than 5 imports, or binaries where all imports are basic loader functions (`LoadLibrary`, `GetProcAddress`, `VirtualAlloc`). This is a strong indicator of packed executables that resolve their real imports at runtime.

### Suspicious Import Detection

**IMPORT001 - Process Injection**: Detects APIs used for injecting code into other processes:
- `CreateRemoteThread`, `WriteProcessMemory`, `VirtualAllocEx`
- `NtCreateThreadEx`, `RtlCreateUserThread`, `QueueUserAPC`
- `NtMapViewOfSection`, `NtUnmapViewOfSection`, `SetThreadContext`

**IMPORT002 - Anti-Debug**: Detects APIs used to detect or evade debuggers:
- `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`
- `NtQueryInformationProcess`, `NtSetInformationThread`
- `OutputDebugString`, `GetTickCount`, `QueryPerformanceCounter`

**IMPORT003 - Persistence**: Detects APIs used for establishing persistence:
- Registry: `RegSetValueEx`, `RegCreateKeyEx`, `SHSetValue`
- Services: `CreateService`, `ChangeServiceConfig`, `StartService`
- Scheduled tasks: `CreateScheduledTask`

**IMPORT004 - Crypto APIs**: Detects Windows cryptographic APIs that may indicate ransomware:
- CryptoAPI: `CryptEncrypt`, `CryptDecrypt`, `CryptGenKey`, `CryptAcquireContext`
- CNG: `BCryptEncrypt`, `BCryptDecrypt`, `BCryptGenerateSymmetricKey`

**IMPORT006 - Low-Level Disk Access**: Detects APIs for raw disk access (bootkit/MBR malware indicator):
- File APIs combined with `DeviceIoControl`
- Strings containing `\\.\PhysicalDrive`, `\\.\HardDisk`
- This is how malware like Petya accesses the MBR

### String-Based Detection

**STRING001 - Network IOCs**: Extracts and flags URLs, IP addresses, and domain names found in binary strings. Excludes common whitelisted domains (microsoft.com, google.com, etc.).

**STRING002 - Suspicious Paths**: Detects references to sensitive system paths:
- Linux: `/proc/`, `/etc/passwd`, `/etc/shadow`
- Windows: `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, `\AppData\`, `\Temp\`
- macOS: `/Library/LaunchAgents`, `/Library/LaunchDaemons`

**STRING003 - Suspicious Strings**: Detects strings commonly found in ransomware and malware (requires 2+ matches to trigger):
- Ransomware: "your files have been encrypted", "bitcoin", "decrypt", ".onion", "tor browser"
- Malware: "keylogger", "screenshot", "clipboard", "credential", "inject", "payload", "c2", "botnet"

### PE Anomaly Detection

**SECTION001 - Tiny Text**: Flags binaries with anomalously small `.text` sections (< 1KB) combined with large high-entropy sections (> 10KB). This pattern indicates the real code is packed elsewhere.

**ANOMALY001 - Entry Point Anomaly**: Detects entry points outside standard code sections. Normal executables have entry points in `.text` or `CODE` sections. Entry points in unusual sections suggest packing or tampering.

**ANOMALY002 - RWX Section**: Detects sections with Read-Write-Execute permissions. Legitimate software rarely needs RWX sections; this is common in:
- Packed executables (unpacker needs to write then execute)
- Shellcode and exploits
- Self-modifying code

**ANOMALY003 - Timestamp Anomaly**: Detects suspicious PE timestamps:
- Null timestamp (stripped)
- Future timestamps
- Very old timestamps (before 1995)
- Known fake timestamps (e.g., Delphi default: 0x2A425E19)

**ANOMALY004 - Section Count Anomaly**: Flags binaries with unusual section counts:
- Only 1 section (unusual for legitimate PE)
- More than 15 sections (may indicate tampering)

**ANOMALY005 - Metadata Mismatch**: Detects binaries that claim to be from trusted vendors (Microsoft, IBM, Adobe, Google, etc.) but are unsigned. This catches malware that impersonates legitimate software through version info strings.

### YARA Integration

**YARA001 - YARA Signature Match**: Runs the `yara` command-line tool against embedded signature rules. Requires YARA to be installed (`apt install yara` or `brew install yara`). Covers:
- **Ransomware**: Locky, Petya, NotPetya, WannaCry, Ryuk
- **APT**: Stuxnet, Duqu, Flame
- **Trojans**: Emotet, Trickbot, AgentTesla
- **Red Team Tools**: Cobalt Strike, Metasploit
- **Packers**: UPX, VMProtect, Themida, ASPack
- **Evasion**: Anti-VM/sandbox techniques

**YARA002 - Malware Family Patterns**: Lightweight pattern matching that works without the YARA binary. Searches for known malware family strings in the binary (e.g., ".locky", "PETYA", "WannaCry", "MRXCLS.SYS"). Requires 2+ pattern matches per family to reduce false positives.

### Risk Scoring

Each rule has a severity that contributes points to the total score:
- **Info**: 1 point
- **Low**: 5 points
- **Medium**: 15 points
- **High**: 30 points
- **Critical**: 50 points

Risk levels are determined by total score:
- **Info**: 0-10 points
- **Low**: 10-25 points
- **Medium**: 25-50 points
- **High**: 50-100 points
- **Critical**: 100+ points

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

- **YARA**: For full signature-based detection (`apt install yara` or `brew install yara`). Without YARA, the lightweight pattern matching (YARA002) still works.

## License

Apache License 2.0
