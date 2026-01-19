# LCRE Blind Evaluation Test

This document describes how to run a blind evaluation of the LCRE binary forensics CLI tool.

## Overview

The evaluation tests LCRE's ability to correctly classify binaries as legitimate or malicious using only static analysis. Sub-agents analyze files without prior knowledge of their classification.

## Prerequisites

1. LCRE binary built and available
2. Git (to clone sample repositories)
3. wget/curl for downloading files
4. unzip for extracting archives

## Step 1: Acquire Sample Files

### Legitimate Samples

```bash
# Clone binary samples repository
git clone --depth 1 https://github.com/JonathanSalwan/binary-samples.git /tmp/binary-samples

# Download BusyBox
wget -q https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox -O /tmp/busybox

# Download Sysinternals Process Explorer (optional - Windows PE)
wget -q https://download.sysinternals.com/files/ProcessExplorer.zip -O /tmp/procexp.zip
unzip -q -o /tmp/procexp.zip -d /tmp/sysinternals/ 2>/dev/null || true
```

**Recommended legitimate samples:**
| # | Source Path | Format | Description |
|---|-------------|--------|-------------|
| 1 | `/tmp/binary-samples/elf-Linux-x64-bash` | ELF | Linux bash shell |
| 2 | `/tmp/binary-samples/elf-Linux-x86-ls` | ELF | Linux ls command |
| 3 | `/tmp/binary-samples/elf-Linux-ARM64-ls` | ELF | Linux ls for ARM64 |
| 4 | `/tmp/binary-samples/pe-Windows-x64-cmd` | PE | Windows cmd.exe |
| 5 | `/tmp/binary-samples/pe-Windows-x86-cmd` | PE | Windows cmd.exe |
| 6 | `/tmp/binary-samples/macho-macOS-x64-ls` | Mach-O | macOS ls command |
| 7 | `/tmp/busybox` | ELF | BusyBox multi-call binary |
| 8 | `/tmp/sysinternals/procexp64.exe` | PE | Process Explorer |
| 9 | `/tmp/binary-samples/elf-FreeBSD-x64-ls` | ELF | FreeBSD ls command |
| 10 | `/tmp/binary-samples/pe-cygwin-x86-ls` | PE | Cygwin ls |

### Malware Samples

```bash
# Clone theZoo malware repository (USE WITH CAUTION)
git clone --depth 1 https://github.com/ytisf/theZoo.git /tmp/theZoo

# Samples are in /tmp/theZoo/malware/Binaries/
# Each malware folder contains:
#   - Encrypted ZIP archive
#   - .pass file with password
#   - MD5 and SHA256 checksums
```

**Recommended malware samples:**
| # | theZoo Path | Format | Family | Description |
|---|-------------|--------|--------|-------------|
| 1 | `Ransomware.WannaCry` | PE | Ransomware | Encryption APIs, bitcoin addresses |
| 2 | `Mirai` | ELF | Botnet | IoT botnet with network scanning |
| 3 | `Trojan.Zeus` | PE | Banking | Credential theft trojan |
| 4 | `Trojan.Emotet` | PE | Loader | Banking trojan/loader |
| 5 | `Ransomware.Petya` | PE | Ransomware | MBR ransomware |
| 6 | `Ransomware.Locky` | PE | Ransomware | File encryption |
| 7 | `Ransomware.CryptoLocker` | PE | Ransomware | File encryption |
| 8 | `Worm.Conficker` | PE | Worm | Network propagation |
| 9 | `Linux.Gafgyt` | ELF | IoT Malware | DDoS botnet |
| 10 | `Trojan.Trickbot` | PE | Banking | Banking trojan |

## Step 2: Prepare Sample Directory

```bash
mkdir -p ./sample_files

# Function to copy and anonymize samples
# This creates a randomized mapping to prevent bias
```

Create `./sample_files/answers.md` with the ground truth (keep secret from sub-agents):

```markdown
# Ground Truth - DO NOT SHARE WITH ANALYSIS AGENTS

| Sample | Original Name | Source | Classification | Format |
|--------|--------------|--------|----------------|--------|
| sample_01 | ... | ... | LEGITIMATE/MALWARE | PE/ELF/Mach-O |
| sample_02 | ... | ... | LEGITIMATE/MALWARE | PE/ELF/Mach-O |
...
```

## Step 3: Sub-Agent Analysis Prompt

Use this prompt for each sub-agent (one per file):

```
You are performing a blind forensic analysis of a binary file. You must analyze
the file using ONLY the LCRE CLI tool and determine if the file is legitimate
or malicious.

IMPORTANT RULES:
1. Do NOT use any external knowledge about file hashes or known malware signatures
2. Base your conclusion SOLELY on what the LCRE tool reveals about the file
3. Document every command you run and its output
4. Explain your reasoning at each step

File to analyze: ./sample_files/sample_XX

Perform the following analysis steps:
1. Run `./lcre triage <file> -o md` for initial analysis
2. Run `./lcre query summary <file>` to get risk assessment
3. Run `./lcre query imports <file>` to examine imported functions
4. Run `./lcre query strings <file> --limit 100` to examine strings
5. Run `./lcre query iocs <file>` to extract indicators of compromise
6. Run `./lcre query heuristics <file>` to see heuristic matches
7. If suspicious, investigate further with:
   - `./lcre query sections <file>` to check entropy
   - `./lcre query strings <file> --pattern "<suspicious_pattern>"`

Based on your analysis, provide:
1. A classification: LEGITIMATE, SUSPICIOUS, or MALICIOUS
2. A confidence level: LOW, MEDIUM, or HIGH
3. Key findings that led to your conclusion
4. A detailed report with all commands run and their output

Format your response as a markdown report with these sections:
## File Information
## Analysis Commands and Output
## Key Findings
## Classification
## Reasoning
```

## Step 4: Running the Evaluation

### Configuration Options
| Option | Recommended | Alternatives |
|--------|-------------|--------------|
| Model | Opus | Sonnet (faster/cheaper), Haiku (fastest) |
| Execution | Sequential | Parallel (batches of 5) |
| Samples | 20 (10+10) | Adjust as needed |

```bash
# Build LCRE
go build -o lcre ./cmd/lcre

# Verify it works
./lcre --help

# Run analysis on each sample (via Claude Code sub-agents)
# Use Opus model for thorough forensic reasoning
# Run sequentially to avoid resource contention
# Each sub-agent will create a report: ./sample_files/report_sample_XX.md
```

## Step 5: Scoring and Results

After all analyses complete, create `./sample_files/evaluation_results.md`:

```markdown
# LCRE Evaluation Results

## Summary Metrics
- Total Samples: 20
- True Positives (Malware correctly identified): X/10
- True Negatives (Legitimate correctly identified): X/10
- False Positives (Legitimate flagged as malware): X
- False Negatives (Malware missed): X
- Accuracy: X%
- Precision: X%
- Recall: X%

## Detailed Results
| Sample | Predicted | Actual | Correct | Confidence |
|--------|-----------|--------|---------|------------|
| sample_01 | ... | ... | Yes/No | HIGH/MED/LOW |
...

## Analysis
- Which heuristics were most effective?
- What caused false positives?
- What caused false negatives?
```

## Expected Results

**Malware should trigger:**
- HIGH risk scores
- Heuristic matches for: PACKER, IMPORT001 (injection), IMPORT003 (persistence), IMPORT004 (crypto)
- IOCs: suspicious URLs, IPs, bitcoin addresses, registry keys
- High entropy sections (packed/encrypted)
- Suspicious API imports: CreateRemoteThread, VirtualAllocEx, CryptEncrypt, etc.

**Legitimate binaries should show:**
- LOW or INFO risk scores
- Minimal heuristic matches
- Normal entropy (< 7.0)
- Standard API imports

**Edge cases:**
- Sysinternals tools may show MEDIUM risk (they use system-level APIs)
- Some legitimate tools may trigger STRING002 (system paths)

## Re-running the Evaluation

To re-run with different samples or after LCRE changes:

1. Clear existing sample_files directory
2. Re-acquire fresh samples (repos may update)
3. Re-randomize sample assignment
4. Update answers.md with new ground truth
5. Run sub-agents with same prompt
6. Compare new results

## Notes

- Malware samples from theZoo require password extraction (see .pass files)
- Never execute malware samples - LCRE performs static analysis only
- Run in isolated environment as extra precaution
- Some theZoo samples may be corrupted or unavailable
