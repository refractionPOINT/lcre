# Forensic Analysis Report: sample_18

**Analysis Date:** 2026-01-18
**Analyst:** LCRE CLI Automated Analysis
**File:** ./sample_files/sample_18

---

## 1. Initial Triage Analysis

### Command
```bash
./lcre triage ./sample_files/sample_18 -o md
```

### Output (Key Information)
```json
{
  "metadata": {
    "path": "./sample_files/sample_18",
    "name": "sample_18",
    "size": 317530,
    "md5": "22dc1db1a876721727cca37c21d31655",
    "sha1": "98e057a4755e89fbfda043eaca1ab072674a3154",
    "sha256": "18884936d002839833a537921eb7ebdb073fa8a153bfeba587457b07b74fb3b2",
    "format": "ELF",
    "arch": "x86_64",
    "bits": 64,
    "endian": "little"
  }
}
```

### Thinking
The file is an ELF binary for 64-bit x86 Linux. The relatively small size (~310KB) suggests it could be a standalone tool or malware designed for portability. The ELF format indicates this is a Linux executable.

---

## 2. Risk Assessment Summary

### Command
```bash
./lcre query summary ./sample_files/sample_18
```

### Output
```json
{
  "metadata": {
    "format": "ELF",
    "arch": "x86_64",
    "size": 317530,
    "sha256": "18884936d002839833a537921eb7ebdb073fa8a153bfeba587457b07b74fb3b2"
  },
  "yara_match_count": 0,
  "counts": {
    "sections": 15,
    "imports": 0,
    "exports": 0,
    "strings": 4104,
    "functions": 0,
    "iocs": 4
  },
  "cached": true
}
```

### Thinking
- **0 imports detected** - This is unusual for an ELF binary and suggests the binary is statically linked (all dependencies compiled in), which is a common technique for malware to ensure portability across different Linux systems without dependency issues.
- **4 IOCs detected** - This is concerning and warrants investigation.
- **4104 strings** - Large number of strings indicates substantial functionality within the binary.
- **No YARA matches** - The sample does not match any standard YARA rules in the built-in ruleset.

---

## 3. Import Analysis

### Command
```bash
./lcre query imports ./sample_files/sample_18
```

### Output
```json
{
  "imports": [],
  "count": 0
}
```

### Thinking
The absence of dynamic imports confirms this is a **statically linked binary**. This is a significant red flag as it allows the malware to:
1. Run on any Linux system without requiring specific library versions
2. Avoid detection by import-based analysis
3. Be fully self-contained for easier distribution

---

## 4. Strings Analysis

### Command
```bash
./lcre query strings ./sample_files/sample_18 --limit 100
```

### Key Findings (Filtered Search Results)

```bash
# Ransomware-specific strings discovered:
"./index.crypto"
"./readme.crypto"
"Decrypting file: %s\n"
".encrypted"
"/README_FOR_DECRYPT.txt"
"Start encrypting..."
"decrypt"
"Start decrypting..."
```

### Cryptographic Library Strings (mbedTLS)
```
"mbedtls_pk_encrypt"
"mbedtls_pk_decrypt"
"mbedtls_aes_encrypt"
"aes_decrypt"
"mbedtls_rsa_rsaes_oaep_encrypt"
"mbedtls_rsa_rsaes_oaep_decrypt"
"AES-256-CBC"
"AES-256-GCM"
"-----BEGIN PUBLIC KEY-----"
"-----BEGIN RSA PRIVATE KEY-----"
"-----END ENCRYPTED PRIVATE KEY-----"
```

### Target Paths Found
```
"/root/.ssh"
"/etc/ssh"
"/root"
"/etc/passwd"
```

### Thinking
This is EXTREMELY SUSPICIOUS. The strings reveal:
1. **Ransom note file path**: `/README_FOR_DECRYPT.txt` - Classic ransomware indicator
2. **File encryption extension**: `.encrypted` and `.crypto` - Files are renamed after encryption
3. **Encryption workflow messages**: "Start encrypting..." and "Start decrypting..." - The binary has both encrypt and decrypt modes
4. **Cryptographic primitives**: Heavy use of mbedTLS library for AES and RSA encryption
5. **Target sensitive directories**: `/root/.ssh`, `/etc/ssh` - Targets SSH keys which would be devastating
6. **Password file access**: `/etc/passwd` - May be gathering user information

---

## 5. IOC Extraction

### Command
```bash
./lcre query iocs ./sample_files/sample_18
```

### Output
```json
{
  "iocs": [
    {
      "type": "domain",
      "value": "index.crypto",
      "offset": "0x2f111"
    },
    {
      "type": "domain",
      "value": "readme.crypto",
      "offset": "0x2f120"
    },
    {
      "type": "path",
      "value": "/etc/passwd",
      "offset": "0x394ce"
    },
    {
      "type": "path",
      "value": "/root/.ssh",
      "offset": "0x2f1fc"
    }
  ],
  "count": 4,
  "by_type": {
    "domain": 2,
    "path": 2
  }
}
```

### Thinking
The IOCs confirm ransomware behavior:
- **index.crypto** and **readme.crypto** - These are file names with the `.crypto` extension that suggest files created by the ransomware
- **/root/.ssh** - SSH directory targeting for maximum impact
- **/etc/passwd** - User enumeration or system information gathering

---

## 6. YARA Analysis

### Command
```bash
./lcre query yara ./sample_files/sample_18
```

### Output
```json
{
  "path": "/home/maxime/scratch/lcre/sample_files/sample_18",
  "yara_available": true
}
```

### Thinking
No built-in YARA rules matched. This could indicate:
1. A new or custom ransomware variant
2. The sample uses obfuscation techniques to avoid detection
3. The built-in ruleset does not have specific rules for this ransomware family

---

## 7. Section Entropy Analysis

### Command
```bash
./lcre query sections ./sample_files/sample_18
```

### Output
```json
{
  "sections": [
    {
      "name": ".text",
      "virtual_addr": "0x400100",
      "virtual_size": 192408,
      "raw_size": 192408,
      "entropy": 6.23,
      "permissions": "r-x",
      "high_entropy": false
    },
    {
      "name": ".rodata",
      "virtual_addr": "0x42f0a0",
      "virtual_size": 45223,
      "raw_size": 45223,
      "entropy": 6.23,
      "permissions": "r--",
      "high_entropy": false
    },
    {
      "name": ".data",
      "virtual_addr": "0x640030",
      "virtual_size": 296,
      "raw_size": 296,
      "entropy": 6.23,
      "permissions": "rw-",
      "high_entropy": false
    },
    {
      "name": ".bss",
      "virtual_addr": "0x640160",
      "virtual_size": 14048,
      "raw_size": 14048,
      "entropy": 6.23,
      "permissions": "rw-",
      "high_entropy": false
    }
  ],
  "count": 15
}
```

### Thinking
The sections have moderate entropy (~6.23) which is consistent with compiled code and doesn't indicate packing or additional encryption of the binary itself. The standard ELF sections (.text, .rodata, .data, .bss) are present with expected permissions:
- `.text` (executable code): r-x
- `.rodata` (read-only data): r--
- `.data` and `.bss`: rw-

---

## 8. Additional Malicious Indicators

### Cryptographic Function Analysis
The binary contains extensive mbedTLS cryptographic library functionality:
- **AES encryption modes**: ECB, CBC, CFB128, CTR, GCM, CCM (multiple key sizes: 128, 192, 256)
- **RSA operations**: Key generation, encryption, decryption, signing
- **Hash functions**: MD5, SHA-1, SHA-256, SHA-384, SHA-512, RIPEMD-160
- **Key derivation**: PBKDF2, PKCS#12

### Ransomware Workflow Functions
From string analysis:
- `encrypt_file` - Function to encrypt files
- `checkDirStart` - Directory traversal function
- `files_ext` - Likely file extension filtering
- `checkExclude` - Exclusion list checking (ransomware often excludes system files)
- `loadRSA` - RSA key loading function
- `extract` - Possible decryption/extraction function

---

## 9. Behavioral Summary

Based on the analysis, this binary appears to be a **Linux ransomware** with the following capabilities:

1. **File Encryption**: Uses AES (likely AES-256-CBC or AES-256-GCM) for symmetric encryption
2. **Key Protection**: Uses RSA for asymmetric key wrapping (public key encrypts AES key)
3. **File Targeting**: Recursively traverses directories with exclusion list support
4. **Extension Modification**: Appends `.encrypted` or `.crypto` extension to encrypted files
5. **Ransom Note**: Creates `README_FOR_DECRYPT.txt` with payment instructions
6. **High-Value Targeting**: Specifically targets `/root/.ssh` and `/etc/ssh` (SSH keys)
7. **Decrypt Mode**: Has built-in decryption capability (for victims who pay)
8. **Static Linking**: Fully self-contained for cross-system portability

---

## 10. Final Classification

### Classification: **MALICIOUS**

### Confidence Level: **HIGH**

### Key Findings Summary

| Finding | Evidence | Severity |
|---------|----------|----------|
| Ransom note creation | `/README_FOR_DECRYPT.txt` string | Critical |
| File encryption capability | "Start encrypting...", `encrypt_file`, `.encrypted` extension | Critical |
| Cryptographic toolkit | mbedTLS library with AES-256, RSA operations | High |
| Sensitive path targeting | `/root/.ssh`, `/etc/ssh`, `/etc/passwd` | Critical |
| Static linking | Zero imports, fully self-contained | Medium |
| Dual mode operation | Both encryption and decryption strings present | High |
| File extension usage | `.crypto`, `.encrypted` | High |

### Verdict
**This sample is a Linux ransomware binary.** The combination of:
- Ransom note file path
- File encryption functionality with the `.encrypted` extension
- Targeting of sensitive SSH directories
- Extensive cryptographic capabilities
- Static linking for portability

...provides overwhelming evidence that this is a ransomware threat designed to encrypt victim files and demand payment for decryption.

---

## Recommendations

1. **Do not execute** this binary under any circumstances
2. **Quarantine** the sample in a secure environment
3. **Block** the hash values on endpoint security solutions:
   - MD5: `22dc1db1a876721727cca37c21d31655`
   - SHA1: `98e057a4755e89fbfda043eaca1ab072674a3154`
   - SHA256: `18884936d002839833a537921eb7ebdb073fa8a153bfeba587457b07b74fb3b2`
4. **Hunt** for similar samples with strings like `README_FOR_DECRYPT.txt`
5. **Monitor** for access attempts to `/root/.ssh` and `/etc/ssh` directories
