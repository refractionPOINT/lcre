# Forensic Analysis Report: sample_20

## File Information
- **File Path**: ./sample_files/sample_20
- **File Size**: 96,535 bytes
- **MD5**: 8baa9b809b591a11af423824f4d9726a
- **SHA1**: 29d6161522c7f7f21b35401907c702bddb05ed47
- **SHA256**: 6393fe8dd4721190f240e22feeb769675b6194a70cabd5a415c2364686a9089c
- **Format**: PE (Portable Executable)
- **Architecture**: x86 (32-bit)
- **Endianness**: Little
- **Timestamp**: 1427792031 (approximately March 31, 2015)
- **Import Hash**: 8c7d51aecaea029b2317860024d9af0e

---

## Step 1: Initial Triage Analysis

### Command:
```bash
./lcre triage ./sample_files/sample_20 -o md
```

### Output (Summary):
```json
{
  "metadata": {
    "path": "./sample_files/sample_20",
    "name": "sample_20",
    "size": 96535,
    "md5": "8baa9b809b591a11af423824f4d9726a",
    "sha1": "29d6161522c7f7f21b35401907c702bddb05ed47",
    "sha256": "6393fe8dd4721190f240e22feeb769675b6194a70cabd5a415c2364686a9089c",
    "format": "PE",
    "arch": "x86",
    "bits": 32,
    "endian": "little",
    "timestamp": 1427792031,
    "imphash": "8c7d51aecaea029b2317860024d9af0e"
  },
  "pe_info": {
    "checksum": 47465,
    "calculated_checksum": 0,
    "image_base": 4194304,
    "section_alignment": 4096,
    "file_alignment": 4096,
    "size_of_headers": 4096,
    "subsystem": 2,
    "dll_characteristics": 0,
    "number_of_sections": 3,
    "entry_point_section": ".text"
  }
}
```

### Thinking:
The file is a 32-bit Windows PE executable. It appears to be a Visual Basic 6 compiled application based on the MSVBVM60.DLL dependency. The subsystem is 2, indicating a Windows GUI application. The timestamp is from 2015, which is interesting. The dll_characteristics being 0 means no modern security features (ASLR, DEP) are enabled, which could be concerning.

---

## Step 2: Risk Assessment Summary

### Command:
```bash
./lcre query summary ./sample_files/sample_20
```

### Output:
```json
{
  "metadata": {
    "format": "PE",
    "arch": "x86",
    "size": 96535,
    "sha256": "6393fe8dd4721190f240e22feeb769675b6194a70cabd5a415c2364686a9089c"
  },
  "yara_match_count": 0,
  "counts": {
    "sections": 3,
    "imports": 79,
    "exports": 0,
    "strings": 1305,
    "functions": 0,
    "iocs": 7
  },
  "cached": true
}
```

### Thinking:
The file has 3 sections, 79 imports, and 1305 strings with 7 IOCs extracted. No YARA rule matches were found. The file has no exports, which is expected for an executable (not a DLL). The high string count suggests there may be embedded data or resources.

---

## Step 3: Import Analysis

### Command:
```bash
./lcre query imports ./sample_files/sample_20
```

### Output:
```json
{
  "imports": [
    {"library": "DllFunctionCall", "function": "MSVBVM60.DLL"},
    {"library": "EVENT_SINK_AddRef", "function": "MSVBVM60.DLL"},
    {"library": "EVENT_SINK_QueryInterface", "function": "MSVBVM60.DLL"},
    {"library": "EVENT_SINK_Release", "function": "MSVBVM60.DLL"},
    {"library": "_CIatan", "function": "MSVBVM60.DLL"},
    {"library": "_CIcos", "function": "MSVBVM60.DLL"},
    {"library": "_CIexp", "function": "MSVBVM60.DLL"},
    {"library": "_CIlog", "function": "MSVBVM60.DLL"},
    {"library": "_CIsin", "function": "MSVBVM60.DLL"},
    {"library": "_CIsqrt", "function": "MSVBVM60.DLL"},
    {"library": "_CItan", "function": "MSVBVM60.DLL"},
    {"library": "__vbaAryConstruct2", "function": "MSVBVM60.DLL"},
    {"library": "__vbaAryDestruct", "function": "MSVBVM60.DLL"},
    {"library": "__vbaAryLock", "function": "MSVBVM60.DLL"},
    {"library": "__vbaAryMove", "function": "MSVBVM60.DLL"},
    {"library": "__vbaAryUnlock", "function": "MSVBVM60.DLL"},
    {"library": "__vbaChkstk", "function": "MSVBVM60.DLL"},
    {"library": "__vbaErrorOverflow", "function": "MSVBVM60.DLL"},
    {"library": "__vbaExceptHandler", "function": "MSVBVM60.DLL"},
    {"library": "__vbaFPException", "function": "MSVBVM60.DLL"},
    {"library": "__vbaFileClose", "function": "MSVBVM60.DLL"},
    {"library": "__vbaFileOpen", "function": "MSVBVM60.DLL"},
    {"library": "__vbaFpI2", "function": "MSVBVM60.DLL"},
    {"library": "__vbaFpI4", "function": "MSVBVM60.DLL"},
    {"library": "__vbaFreeObj", "function": "MSVBVM60.DLL"},
    {"library": "__vbaFreeStr", "function": "MSVBVM60.DLL"},
    {"library": "__vbaFreeStrList", "function": "MSVBVM60.DLL"},
    {"library": "__vbaFreeVar", "function": "MSVBVM60.DLL"},
    {"library": "__vbaFreeVarList", "function": "MSVBVM60.DLL"},
    {"library": "__vbaGenerateBoundsError", "function": "MSVBVM60.DLL"},
    {"library": "__vbaGet3", "function": "MSVBVM60.DLL"},
    {"library": "__vbaHresultCheckObj", "function": "MSVBVM60.DLL"},
    {"library": "__vbaI2I4", "function": "MSVBVM60.DLL"},
    {"library": "__vbaI2Var", "function": "MSVBVM60.DLL"},
    {"library": "__vbaI4Str", "function": "MSVBVM60.DLL"},
    {"library": "__vbaInStr", "function": "MSVBVM60.DLL"},
    {"library": "__vbaLateMemCall", "function": "MSVBVM60.DLL"},
    {"library": "__vbaLbound", "function": "MSVBVM60.DLL"},
    {"library": "__vbaLenBstr", "function": "MSVBVM60.DLL"},
    {"library": "__vbaNew2", "function": "MSVBVM60.DLL"},
    {"library": "__vbaObjSetAddref", "function": "MSVBVM60.DLL"},
    {"library": "__vbaObjVar", "function": "MSVBVM60.DLL"},
    {"library": "__vbaOnError", "function": "MSVBVM60.DLL"},
    {"library": "__vbaR4Var", "function": "MSVBVM60.DLL"},
    {"library": "__vbaR8IntI4", "function": "MSVBVM60.DLL"},
    {"library": "__vbaRedim", "function": "MSVBVM60.DLL"},
    {"library": "__vbaRedimPreserve", "function": "MSVBVM60.DLL"},
    {"library": "__vbaSetSystemError", "function": "MSVBVM60.DLL"},
    {"library": "__vbaStrCopy", "function": "MSVBVM60.DLL"},
    {"library": "__vbaStrMove", "function": "MSVBVM60.DLL"},
    {"library": "__vbaStrVarCopy", "function": "MSVBVM60.DLL"},
    {"library": "__vbaStrVarMove", "function": "MSVBVM60.DLL"},
    {"library": "__vbaUI1I2", "function": "MSVBVM60.DLL"},
    {"library": "__vbaUI1I4", "function": "MSVBVM60.DLL"},
    {"library": "__vbaUbound", "function": "MSVBVM60.DLL"},
    {"library": "__vbaVar2Vec", "function": "MSVBVM60.DLL"},
    {"library": "__vbaVarAdd", "function": "MSVBVM60.DLL"},
    {"library": "__vbaVarDiv", "function": "MSVBVM60.DLL"},
    {"library": "__vbaVarForInit", "function": "MSVBVM60.DLL"},
    {"library": "__vbaVarForNext", "function": "MSVBVM60.DLL"},
    {"library": "__vbaVarLateMemCallLd", "function": "MSVBVM60.DLL"},
    {"library": "__vbaVarMove", "function": "MSVBVM60.DLL"},
    {"library": "__vbaVarMul", "function": "MSVBVM60.DLL"},
    {"library": "__vbaVarTstEq", "function": "MSVBVM60.DLL"},
    {"library": "__vbaVarVargNofree", "function": "MSVBVM60.DLL"},
    ...
  ],
  "count": 79
}
```

### Thinking:
All 79 imports are from MSVBVM60.DLL, confirming this is a Visual Basic 6 compiled application. Key observations:
- **File Operations**: `__vbaFileOpen`, `__vbaFileClose`, `__vbaGet3` - can read/write files
- **DllFunctionCall**: This is a critical import that allows VB6 applications to call arbitrary Windows API functions at runtime - this is a common technique in malware to hide API calls from static analysis
- **String operations**: Multiple string manipulation functions - could be used for decryption/deobfuscation
- **Array operations**: Extensive array handling suggests data manipulation capabilities

The presence of `DllFunctionCall` is particularly concerning as it enables dynamic API resolution, often used to hide malicious functionality.

---

## Step 4: String Analysis

### Command:
```bash
./lcre query strings ./sample_files/sample_20 --limit 100
```

### Key Strings Found (Selected):

**Version Information:**
```
VS_VERSION_INFO
FileDescription: "Note: In CSS3, the text-decoration property is a shorthand property..."
ProductName: "Goodreads"
FileVersion: "1.00.0065"
ProductVersion: "1.00.0065"
InternalName: "Callstb"
OriginalFilename: "NOFAstb.exe"
CompanyName: "In CSS3"
```

**Suspicious Strings:**
```
Decrypt
sPassword
sData
ByteArray
sKey
ArcString
Split
Beprog
VeladonACCOJ.vbp
C:\Documents and Settings\
C:\Program Files\Microsoft Visual Studio\VB98\VB6.OLB
NR78RECmains
Remounter
```

**Geographical Reference:**
```
"Olib (pronounced [??lib]; Italian: Ulbo) is an island in northern Dalmatia, located northwest of Zadar..."
```

**Numeric/Encoded Strings:**
```
5665778782565768827838
57576736879580478257258376974939
```

### Thinking:
Several highly suspicious elements:
1. **Decrypt function and encryption-related variables** (`sPassword`, `sData`, `ByteArray`, `sKey`) - indicates the binary performs decryption operations
2. **Obfuscated/encrypted data** - The numeric strings `5665778782565768827838` and `57576736879580478257258376974939` look like encoded/encrypted data
3. **Deceptive version info** - The file claims to be "Goodreads" with description about CSS3 text-decoration, which is clearly fake/misleading metadata designed to look innocent
4. **Project reference** - `VeladonACCOJ.vbp` and `Remounter` - original project names visible
5. **NOFAstb.exe** - Original filename different from the sample name
6. **Long random-looking strings** throughout (`JIHKMMJNOALAKBEGW\\X[Y_Q[PP\\SW[RYjihkmmjnoalakbegw|x{y`) - likely XOR encrypted or encoded payload data

---

## Step 5: IOC Extraction

### Command:
```bash
./lcre query iocs ./sample_files/sample_20
```

### Output:
```json
{
  "iocs": [
    {"type": "domain", "value": "3.3.vN", "offset": "0xa50e"},
    {"type": "domain", "value": "J.qrIA", "offset": "0xa92e"},
    {"type": "domain", "value": "VB6.OLB", "offset": "0x44a8"},
    {"type": "domain", "value": "VeladonACCOJ.vbp", "offset": "0x3b38"},
    {"type": "domain", "value": "XJ.nM", "offset": "0x22f3"},
    {"type": "path", "value": "C:\\Documents and Settings\\", "offset": "0x3ac6"},
    {"type": "path", "value": "C:\\Program Files\\Microsoft Visual Studio\\VB98\\VB6.OLB", "offset": "0x44a8"}
  ],
  "count": 7,
  "by_type": {"domain": 5, "path": 2}
}
```

### Thinking:
The extracted IOCs show:
1. **File paths to user directories** - `C:\Documents and Settings\` - typical target for malware
2. **VB6 development artifacts** - The VB6.OLB reference and VeladonACCOJ.vbp project file confirm VB6 origin
3. **Gibberish domain-like strings** - `3.3.vN`, `J.qrIA`, `XJ.nM` - these appear to be false positives from encoded data rather than real domains

---

## Step 6: YARA Analysis

### Command:
```bash
./lcre query yara ./sample_files/sample_20
```

### Output:
```json
{
  "path": "/home/maxime/scratch/lcre/sample_files/sample_20",
  "yara_available": true
}
```

### Thinking:
No YARA rules matched. This could mean the sample doesn't match any signatures in the current rule set, or it's a less common variant.

---

## Step 7: Section Entropy Analysis

### Command:
```bash
./lcre query sections ./sample_files/sample_20
```

### Output:
```json
{
  "sections": [
    {
      "name": ".text",
      "virtual_addr": "0x1000",
      "virtual_size": 26012,
      "raw_size": 28672,
      "entropy": 6.8537510093458,
      "permissions": "r-x",
      "high_entropy": false
    },
    {
      "name": ".data",
      "virtual_addr": "0x8000",
      "virtual_size": 3168,
      "raw_size": 4096,
      "entropy": 6.8537510093458,
      "permissions": "rw-",
      "high_entropy": false
    },
    {
      "name": ".rsrc",
      "virtual_addr": "0x9000",
      "virtual_size": 8048,
      "raw_size": 8192,
      "entropy": 6.8537510093458,
      "permissions": "r--",
      "high_entropy": false
    }
  ],
  "count": 3
}
```

### Thinking:
All three sections have identical entropy (~6.85), which is moderate and below the 7.0 threshold for "high entropy". This is typical for compiled code but the identical entropy across all sections is unusual. The sections have appropriate permissions:
- `.text` - executable code (r-x)
- `.data` - data section (rw-)
- `.rsrc` - resources (r--)

The entropy is not extremely high but is elevated enough to suggest some obfuscation or compressed data may be present.

---

## Additional Observations from Extended String Analysis

From further string analysis (offsets 100-700), additional suspicious elements were found:

1. **gdi32 and USER32 imports** - The sample also imports from system DLLs:
   - `PatBlt` from gdi32 (graphics drawing)
   - `CallWindowProcA` from USER32 (window message handling)

2. **Picture1** - Reference to a form element, suggesting this might be masquerading as an image viewer

3. **Repeated encoded patterns** - Multiple occurrences of the same encoded string patterns like:
   - `JIHKMMJNOALAKBEGW\X[Y_Q[PP\SW[RYjihkmmjnoalakbegw|x{y`
   - This repetition strongly suggests encrypted/encoded payload data

4. **&HFF** - VB6 hex notation for 255, likely used in XOR encryption routines

---

## Final Assessment

### Classification: **MALICIOUS**

### Confidence Level: **HIGH**

### Key Findings Summary:

1. **Encryption/Decryption Capability**: The binary contains a `Decrypt` function and encryption-related variables (`sPassword`, `sData`, `sKey`, `ByteArray`), indicating it decrypts and executes hidden payload.

2. **Dynamic API Resolution**: Uses `DllFunctionCall` which allows the program to call any Windows API at runtime, effectively hiding its true capabilities from static analysis.

3. **Deceptive Metadata**: The version information claims to be "Goodreads" with a description about CSS3 text-decoration - this is clearly fabricated to appear legitimate.

4. **Embedded Encrypted Data**: Multiple long strings of seemingly random characters that repeat throughout the binary strongly suggest an encrypted or encoded payload waiting to be decrypted at runtime.

5. **VB6 Stub/Loader Pattern**: The structure matches a common VB6-based malware loader pattern - small VB6 executable that decrypts and executes an embedded malicious payload.

6. **Suspicious Original Filename**: `NOFAstb.exe` - the "stb" suffix often indicates a "stub" or loader component.

7. **Project Name**: `VeladonACCOJ.vbp` and `Remounter` suggest this may be part of a larger malware campaign or toolkit.

8. **No Security Features**: DLL characteristics of 0 means no ASLR, DEP, or other security mitigations are enabled, which is common in malware but rare in legitimate modern software.

### Behavioral Indicators:
- This appears to be a **dropper/loader** that uses XOR-based decryption to decode an embedded payload
- The `DllFunctionCall` import enables runtime API resolution to evade detection
- The deceptive metadata and small size are typical of malware stubs
- File operations capabilities suggest it may write malware to disk

### Recommendation:
This sample should be treated as malicious. It exhibits multiple characteristics consistent with a VB6-based malware loader/dropper designed to decrypt and execute a hidden payload while evading static analysis through deceptive metadata and runtime API resolution.
