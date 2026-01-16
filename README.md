# LCRE - Binary Forensics CLI Tool

LCRE is a CLI tool for static binary analysis and forensics automation. It provides fast triage via native Go parsing and deep analysis via Ghidra headless integration.

## Features

- **Fast Triage**: Native Go parsing for PE, ELF, and Mach-O binaries
- **Heuristic Analysis**: Detect packers, suspicious imports, and malware indicators
- **IOC Extraction**: Extract URLs, IPs, domains, paths, and registry keys
- **Binary Diff**: Compare two binaries to identify changes
- **Ghidra Integration**: Deep analysis with decompilation and call graph extraction
- **Multiple Output Formats**: JSON and Markdown

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

### Ghidra Deep Analysis

```bash
# Requires Ghidra installation
export GHIDRA_HOME=/path/to/ghidra

lcre ghidra analyze sample.exe --timeout 10m
lcre ghidra analyze sample.exe --decompile
```

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
