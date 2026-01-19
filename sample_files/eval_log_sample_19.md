# Forensic Analysis Report: sample_19

## Analysis Date
2026-01-18

## File Information
- **File Path:** ./sample_files/sample_19
- **File Size:** 3,514,368 bytes
- **Format:** PE (Portable Executable)
- **Architecture:** x86 (32-bit)
- **Endianness:** Little endian

## Hashes
- **MD5:** 84c82835a5d21bbcf75a61706d8ab549
- **SHA1:** 5ff465afaabcbf0150d1a3ab2c2e74f3a4426467
- **SHA256:** ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa
- **ImpHash:** 4b1a88ce1ab9c1e09126fc3dc8069cf0

---

## Step 1: Initial Triage Analysis

### Command:
```bash
./lcre triage ./sample_files/sample_19 -o md
```

### Output (Key portions):
```json
{
  "metadata": {
    "path": "./sample_files/sample_19",
    "name": "sample_19",
    "size": 3514368,
    "md5": "84c82835a5d21bbcf75a61706d8ab549",
    "sha1": "5ff465afaabcbf0150d1a3ab2c2e74f3a4426467",
    "sha256": "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
    "format": "PE",
    "arch": "x86",
    "bits": 32,
    "endian": "little",
    "timestamp": 1290243905,
    "imphash": "4b1a88ce1ab9c1e09126fc3dc8069cf0"
  },
  "pe_info": {
    "checksum": 0,
    "calculated_checksum": 0,
    "image_base": 4194304,
    "section_alignment": 4096,
    "file_alignment": 4096,
    "size_of_headers": 4096,
    "subsystem": 2,
    "dll_characteristics": 0,
    "number_of_sections": 4,
    "entry_point_section": ".text"
  }
}
```

### Thinking:
The initial triage reveals a 32-bit PE executable with 4 sections. The PE checksum is 0, which is suspicious as legitimate software typically has a valid checksum. The timestamp (1290243905) corresponds to November 20, 2010, which may be an anomaly. The file is 3.5 MB in size, which is larger than typical utility executables.

---

## Step 2: Risk Assessment Summary

### Command:
```bash
./lcre query summary ./sample_files/sample_19
```

### Output:
```json
{
  "metadata": {
    "format": "PE",
    "arch": "x86",
    "size": 3514368,
    "sha256": "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"
  },
  "yara_match_count": 0,
  "counts": {
    "sections": 4,
    "imports": 114,
    "exports": 0,
    "strings": 10000,
    "functions": 0,
    "iocs": 12
  },
  "cached": true
}
```

### Thinking:
The summary shows 114 imports, which is relatively high, and 12 identified IOCs (Indicators of Compromise). The file has no exports, indicating it is not a DLL but an executable. 10,000 strings were extracted, suggesting significant embedded data or resources.

---

## Step 3: Import Analysis

### Command:
```bash
./lcre query imports ./sample_files/sample_19
```

### Output (Key suspicious imports):
```json
{
  "imports": [
    {"library": "CreateFileA", "function": "KERNEL32.dll"},
    {"library": "CreateProcessA", "function": "KERNEL32.dll"},
    {"library": "VirtualAlloc", "function": "KERNEL32.dll"},
    {"library": "VirtualProtect", "function": "KERNEL32.dll"},
    {"library": "LoadLibraryA", "function": "KERNEL32.dll"},
    {"library": "GetProcAddress", "function": "KERNEL32.dll"},
    {"library": "TerminateProcess", "function": "KERNEL32.dll"},
    {"library": "CreateServiceA", "function": "ADVAPI32.dll"},
    {"library": "OpenServiceA", "function": "ADVAPI32.dll"},
    {"library": "StartServiceA", "function": "ADVAPI32.dll"},
    {"library": "OpenSCManagerA", "function": "ADVAPI32.dll"},
    {"library": "CryptReleaseContext", "function": "ADVAPI32.dll"},
    {"library": "RegCreateKeyW", "function": "ADVAPI32.dll"},
    {"library": "RegSetValueExA", "function": "ADVAPI32.dll"},
    {"library": "RegQueryValueExA", "function": "ADVAPI32.dll"},
    {"library": "OpenMutexA", "function": "KERNEL32.dll"},
    {"library": "WriteFile", "function": "KERNEL32.dll"},
    {"library": "ReadFile", "function": "KERNEL32.dll"},
    {"library": "FindResourceA", "function": "KERNEL32.dll"},
    {"library": "LoadResource", "function": "KERNEL32.dll"},
    {"library": "LockResource", "function": "KERNEL32.dll"},
    {"library": "SizeofResource", "function": "KERNEL32.dll"}
  ],
  "count": 114
}
```

### Thinking:
The import table reveals extremely suspicious functionality:
1. **Service manipulation:** CreateServiceA, OpenServiceA, StartServiceA, OpenSCManagerA - Used to install and start Windows services for persistence
2. **Cryptographic functions:** CryptReleaseContext - Indicates cryptographic operations
3. **Registry manipulation:** RegCreateKeyW, RegSetValueExA, RegQueryValueExA - Used for persistence and configuration
4. **Process manipulation:** CreateProcessA, TerminateProcess - Can spawn and kill processes
5. **Memory manipulation:** VirtualAlloc, VirtualProtect - Often used for code injection or unpacking
6. **Mutex operations:** OpenMutexA - Used to ensure single instance execution (common malware technique)
7. **Resource extraction:** FindResourceA, LoadResource, LockResource - Indicates embedded payload extraction

---

## Step 4: String Analysis

### Command:
```bash
./lcre query strings ./sample_files/sample_19 --limit 100
```

### Additional searches for ransomware-specific strings:

**Ransomware/Crypto strings found:**
```
"WanaCrypt0r"
"WANACRY!"
"Microsoft Enhanced RSA and AES Cryptographic Provider"
"CryptGenKey"
"CryptDecrypt"
"CryptEncrypt"
"CryptDestroyKey"
"CryptImportKey"
"CryptAcquireContextA"
"Global\\MsWinZonesCacheCounterMutexA"
"c.wnry"
"t.wnry"
"b.wnryP8"
"msg/m_bulgarian.wnry"
```

**Suspicious file/system strings found:**
```
"cmd.exe /c \"%s\""
"tasksche.exe"
"icacls . /grant Everyone:F /T /C /Q"
"attrib +h ."
".key"
".cmd"
```

### Thinking:
The strings reveal definitive ransomware indicators:
1. **"WanaCrypt0r"** and **"WANACRY!"** - Direct references to the WannaCry ransomware name
2. **Cryptographic provider strings** - Uses Windows CryptoAPI for encryption
3. **".wnry" file extensions** - WannaCry's characteristic file format for encrypted data and resources
4. **Mutex name "Global\\MsWinZonesCacheCounterMutexA"** - Known WannaCry mutex to prevent multiple instances
5. **"icacls . /grant Everyone:F /T /C /Q"** - Grants full permissions to Everyone, enabling file encryption
6. **"attrib +h ."** - Hides files/directories
7. **"tasksche.exe"** - Known WannaCry component executable

---

## Step 5: IOC Extraction

### Command:
```bash
./lcre query iocs ./sample_files/sample_19
```

### Output:
```json
{
  "iocs": [
    {"type": "domain", "value": "c.wnry", "offset": "0xe010"},
    {"type": "domain", "value": "r.wnry", "offset": "0x53e6e"},
    {"type": "domain", "value": "s.wnry", "offset": "0x54076"},
    {"type": "domain", "value": "t.wnry", "offset": "0xf4f4"}
  ],
  "count": 12,
  "by_type": {
    "domain": 12
  }
}
```

### Thinking:
The IOC extraction identified patterns resembling domains, but these are actually WannaCry-specific file names:
- **c.wnry** - Contains configuration data
- **r.wnry** - Contains ransom message text
- **s.wnry** - Contains Tor client
- **t.wnry** - Contains the encryption payload

These are characteristic WannaCry resource files that get dropped during infection.

---

## Step 6: YARA Rule Matches

### Command:
```bash
./lcre query yara ./sample_files/sample_19
```

### Output:
```json
{
  "path": "/home/maxime/scratch/lcre/sample_files/sample_19",
  "yara_available": true,
  "matches": [
    {
      "rule": "WannaCry_Ransomware",
      "tags": [
        "description=\"Detects WannaCry ransomware\"",
        "category=\"ransomware\"",
        "family=\"WannaCry\""
      ],
      "strings": [
        "$wannacry1: W\\x00a\\x00n\\x00a\\x00C\\x00r\\x00y\\x00p\\x00t\\x000\\x00r\\x00",
        "$wannacry3: WANACRY",
        "$wannacry4: WNcry@2ol7",
        "$mutex: MsWinZonesCacheCounterMutexA"
      ]
    },
    {
      "rule": "Stuxnet_Indicators",
      "tags": [
        "description=\"Detects Stuxnet malware indicators\"",
        "category=\"apt\"",
        "family=\"Stuxnet\"",
        "reference=\"https://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/w32_stuxnet_dossier.pdf\""
      ],
      "strings": [
        "$tasksche: tasksche.exe"
      ]
    }
  ]
}
```

### Thinking:
YARA analysis confirms this is WannaCry ransomware with high confidence:
1. **WannaCry_Ransomware rule matched** with multiple string indicators:
   - "WanaCrypt0r" (Unicode)
   - "WANACRY"
   - "WNcry@2ol7" (password string)
   - "MsWinZonesCacheCounterMutexA" (mutex name)
2. **Stuxnet_Indicators partial match** - Only "tasksche.exe" matched, which is actually a WannaCry component, not Stuxnet. This is a coincidental name overlap.

---

## Step 7: Section Entropy Analysis

### Command:
```bash
./lcre query sections ./sample_files/sample_19
```

### Output:
```json
{
  "sections": [
    {
      "name": ".text",
      "virtual_addr": "0x1000",
      "virtual_size": 27056,
      "raw_size": 28672,
      "entropy": 7.995470941164685,
      "permissions": "r-x",
      "high_entropy": true
    },
    {
      "name": ".rdata",
      "virtual_addr": "0x8000",
      "virtual_size": 24432,
      "raw_size": 24576,
      "entropy": 7.995470941164685,
      "permissions": "r--",
      "high_entropy": true
    },
    {
      "name": ".data",
      "virtual_addr": "0xe000",
      "virtual_size": 6488,
      "raw_size": 8192,
      "entropy": 7.995470941164685,
      "permissions": "rw-",
      "high_entropy": true
    },
    {
      "name": ".rsrc",
      "virtual_addr": "0x10000",
      "virtual_size": 3448736,
      "raw_size": 3448832,
      "entropy": 7.995470941164685,
      "permissions": "r--",
      "high_entropy": true
    }
  ],
  "count": 4
}
```

### Thinking:
**CRITICAL FINDING:** All four sections have extremely high entropy (7.995/8.0). This is a major red flag:
1. **Entropy near 8.0** indicates encrypted or packed content
2. **ALL sections having high entropy** suggests the entire binary is packed/encrypted
3. **.rsrc section is 3.4 MB** with high entropy - contains the encrypted ransomware payload and Tor client
4. This level of packing/encryption is highly characteristic of malware attempting to evade static analysis

---

## Final Analysis Summary

### Key Findings:

| Category | Finding | Severity |
|----------|---------|----------|
| YARA Detection | **WannaCry_Ransomware rule matched** | CRITICAL |
| Strings | "WanaCrypt0r", "WANACRY!", WannaCry-specific file names (.wnry) | CRITICAL |
| Mutex | "Global\\MsWinZonesCacheCounterMutexA" - Known WannaCry mutex | CRITICAL |
| Entropy | All sections: 7.99/8.0 (packed/encrypted) | HIGH |
| Imports | Service manipulation, cryptography, registry modification | HIGH |
| Commands | "icacls . /grant Everyone:F /T /C /Q" - Permission escalation | HIGH |
| Commands | "attrib +h ." - File hiding | MEDIUM |
| Components | tasksche.exe, cmd.exe execution | HIGH |
| Cryptography | AES/RSA encryption via Windows CryptoAPI | CRITICAL |
| Resources | Large .rsrc section (3.4 MB) with packed payload | HIGH |

### Malicious Capabilities Identified:
1. **File Encryption:** Uses RSA/AES cryptography via Windows CryptoAPI
2. **Service Installation:** Can install itself as a Windows service for persistence
3. **Permission Modification:** Grants full access to all files for encryption
4. **File Hiding:** Uses attrib to hide malware components
5. **Command Execution:** Spawns cmd.exe for system commands
6. **Single Instance Control:** Uses mutex to prevent multiple infections
7. **Payload Extraction:** Contains embedded resources (Tor client, ransom notes, encryption modules)

---

## Classification

| Attribute | Value |
|-----------|-------|
| **Classification** | **MALICIOUS** |
| **Confidence Level** | **HIGH** |
| **Malware Family** | WannaCry Ransomware |
| **Category** | Ransomware |

### Justification:
This file is definitively identified as WannaCry ransomware based on:
1. Direct YARA signature match for WannaCry
2. Multiple WannaCry-specific strings (WanaCrypt0r, .wnry files, known mutex)
3. Cryptographic import functions consistent with ransomware
4. Service installation capabilities for persistence
5. Permission modification commands to enable file encryption
6. Extremely high entropy across all sections indicating packed malicious payload
7. Large embedded resources containing ransomware components

This sample represents one of the most notorious ransomware families responsible for the 2017 global outbreak that affected hundreds of thousands of systems worldwide.

---

## Recommendations:
1. **Do NOT execute this file** under any circumstances
2. Isolate any systems where this file was discovered
3. Check for indicators of compromise on the network
4. Ensure SMB port 445 is firewalled from external access (WannaCry spreads via EternalBlue exploit)
5. Verify MS17-010 patch is applied to all Windows systems
6. Report to security team for incident response
