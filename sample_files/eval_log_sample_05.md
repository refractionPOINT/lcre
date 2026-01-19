# Forensic Analysis Report: sample_05

**Analysis Date:** 2026-01-18
**Analyst Tool:** LCRE CLI
**File Path:** ./sample_files/sample_05

---

## 1. Initial Triage Analysis

### Command:
```bash
./lcre triage ./sample_files/sample_05 -o md
```

### Output (Metadata):
```json
{
  "metadata": {
    "path": "./sample_files/sample_05",
    "name": "sample_05",
    "size": 64400,
    "md5": "9a0e765eecc5433af3dc726206ecc56e",
    "sha1": "5996d02c142588b6c1ed850e461845458bd94d17",
    "sha256": "35ff79dd456fe3054a60fe0a16f38bf5fc3928e1e8439ca4d945573f8c48c0b8",
    "format": "ELF",
    "arch": "x86",
    "bits": 32,
    "endian": "little"
  }
}
```

### Thinking:
- This is a 32-bit x86 ELF binary (Linux executable)
- File size is 64,400 bytes - relatively small
- The format being ELF means this is a Linux/Unix binary

---

## 2. Risk Assessment Summary

### Command:
```bash
./lcre query summary ./sample_files/sample_05
```

### Output:
```json
{
  "metadata": {
    "format": "ELF",
    "arch": "x86",
    "size": 64400,
    "sha256": "35ff79dd456fe3054a60fe0a16f38bf5fc3928e1e8439ca4d945573f8c48c0b8"
  },
  "yara_match_count": 0,
  "counts": {
    "sections": 21,
    "imports": 74,
    "exports": 237,
    "strings": 908,
    "functions": 0,
    "iocs": 31
  },
  "cached": true
}
```

### Thinking:
- **237 exports** is EXTREMELY unusual for a normal application - this is excessive
- **31 IOCs** extracted is concerning
- **74 imports** shows heavy use of system libraries
- **0 YARA matches** - no known signatures matched, but this doesn't mean it's clean

---

## 3. Imported Functions Analysis

### Command:
```bash
./lcre query imports ./sample_files/sample_05
```

### Output (74 imports):
Notable suspicious imports:
- **Network operations:** `socket`, `connect`, `send`, `recv`, `gethostbyname`, `setsockopt`, `shutdown`
- **Process manipulation:** `fork`, `execl`, `execlp`, `kill`, `waitpid`, `getpid`
- **File operations:** `fopen64`, `fread`, `fwrite`, `remove`, `rename`, `chmod`
- **Dynamic loading:** `dlopen`, `dlsym`, `dlclose` - runtime library loading
- **Daemon behavior:** `setsid`, `umask`, `chdir`
- **Threading:** `pthread_create`, `pthread_mutex_lock`, `pthread_mutex_unlock`

### Thinking:
This combination of imports is HIGHLY suspicious:
1. Network capabilities (`socket`, `connect`, `send`, `recv`) for C2 communication
2. `setsid` is used to create daemon processes (persistence)
3. `dlopen`/`dlsym` for dynamic loading (evasion technique)
4. Process execution (`execl`, `execlp`, `fork`) for spawning processes
5. File manipulation capabilities for data theft or modification

---

## 4. Exported Functions Analysis (from triage)

### Critical Exports Found:
The binary exports 237 functions. Key malicious indicators:

**Password/Credential Stealing:**
- `GetPidginPasswords` - Steals Pidgin IM passwords
- `GetGoogleChromePasswords` - Steals Chrome passwords
- `GetChromiumPasswords` - Steals Chromium passwords
- `GetMozillaProductPasswords` - Steals Firefox/Thunderbird passwords
- `GetOperaWand` - Steals Opera password manager data
- `DecryptLoginData` - Decrypts stolen login data
- `LoadMozillaLibs` - Loads Mozilla NSS libraries for decryption

**Keylogger Functionality:**
- `cpStartKeyLogger` - Starts keylogger
- `LogKey` - Logs keystrokes
- `KeyLoggerState` - Keylogger state management
- `KeyLoggerFileName` - Keylogger output file
- `KeyLoggerEncode` - Encodes logged keys
- `LoadKeyLoggerAPI` - Loads X11 input APIs for keylogging

**Remote Access/RAT Capabilities:**
- `BindShell` - Creates bind shell for remote access
- `StartReverseSocks` - Reverse SOCKS proxy
- `HandleSocks4`, `HandleSocks4a`, `HandleSocks5` - SOCKS proxy support
- `HandleReverseSocks` - Reverse proxy functionality
- `EstablishConnection`, `EstablishConnectionLoop` - C2 connection
- `SendAuthenticationPacket`, `ParseAuthenticationPacket` - C2 authentication
- `ResolveHost` - DNS resolution for C2

**Screen Capture:**
- `CaptureScreen`, `cpScreenCapture`, `CaptureScreenToJPEG`
- `SaveXImageToBitmap`, `BitmapToJPEG`

**Persistence:**
- `InstallHost`, `UninstallHost`, `UpdateHost` - Self-installation
- `RunAsDaemon` - Daemonization
- `StartupKeyName1`, `StartupKeyName2` - Autostart registry
- `OpenMutexHandle`, `CloseMutexHandle` - Single instance mutex

**Remote Control:**
- `cpMouseMove`, `cpMouseDown`, `cpMouseUp` - Mouse control
- `cpKeyDown`, `cpKeyUp` - Keyboard control
- `ListWindows`, `EnumerateWindows`, `ChangeWindowTitle`, `WindowOperation`

**File Operations:**
- `cpDownloadFile`, `TransferFile`, `FileUploadWrite`
- `cpCopyFile`, `cpDeleteFile`, `cpRenameFile`
- `cpListFiles`, `cpListDrives`, `cpSearchFiles`
- `cpExecuteFile` - Execute downloaded files

**Encryption:**
- `AESBlockEncrypt`, `AESBlockDecrypt`, `AESCryptCFB`
- `RC4Setup`, `RC4Crypt`
- `BuilderEncryptionKey`, `DecryptSettings`

### Thinking:
The exports reveal this is a **fully-featured Remote Access Trojan (RAT)** with:
- Credential theft from multiple applications
- Keylogging
- Screen capture
- Remote shell access
- SOCKS proxy capabilities
- Remote desktop control
- File exfiltration
- Persistence mechanisms

---

## 5. String Analysis

### Command:
```bash
./lcre query strings ./sample_files/sample_05 --limit 100
```

### Key Strings Found:

**Credential Stealing Paths:**
- `%s/.mozilla/firefox/profiles.ini`
- `%s/.thunderbird/profiles.ini`
- `%s/.mozilla/seamonkey/profiles.ini`
- `%s/signons.sqlite` - Firefox password database
- `%s/.opera/wand.dat` - Opera password storage
- `%s/.purple/accounts.xml` - Pidgin accounts
- `%s/.config/google-chrome/Default/Login Data`
- `%s/.config/chromium/Default/Login Data`

**Mozilla NSS Functions (for password decryption):**
- `NSS_Init`, `PK11_GetInternalKeySlot`, `PK11_Authenticate`
- `NSSBase64_DecodeBuffer`, `PK11SDR_Decrypt`
- `sqlite3_open`, `sqlite3_prepare_v2`, `select * from moz_logins`

**Shell Execution:**
- `/bin/sh`
- `/bin/bash`
- `\r\nexit\r\n\r\nexit\n\n`

**Persistence (Linux autostart):**
- `%s/.config/autostart/%s.desktop`
- `[Desktop Entry]\nType=Application\nExec="%s"\nHidden=false\nName=%s\n`
- `%s/.xinitrc`

**Keylogger Key Names:**
- `[Ctrl+%d]`, `[Ctrl+%c]`
- `[Caps Lock]`, `[Shift Lock]`
- `[Arrow Left]`, `[Arrow Up]`, `[Arrow Right]`, `[Arrow Down]`
- `[Backspace]`, `[Delete]`, `[Tab]`, `[Enter]`, `[Esc]`
- `[F%d]`, `[Home]`, `[End]`, `[Page Up]`, `[Page Down]`
- `[Print Screen]`, `[Alt]`, `[Insert]`, `[Scroll Lock]`

**Network/C2:**
- `CONNECT %s:%d HTTP/1.0\n\n` - HTTP CONNECT proxy method
- `GET %s HTTP/1.1\r\nHost: %s \r\nConnection: close\r\n\r\n`
- `http://%s%s`
- `200 OK`

**Process Enumeration:**
- `/proc/%i/exe`
- `/proc/%s/exe`
- `/proc/%s/stat`
- `/proc/stat`
- `/proc/`

**Temporary Files:**
- `/tmp/%s`
- `/tmp/.%s` (hidden files)

**X11 Functions (for keylogging/screen capture):**
- `XOpenDisplay`, `XQueryTree`, `XGetWMName`
- `XListInputDevices`, `XSelectExtensionEvent`
- `XGetImage`, `XGetInputFocus`
- `XInputExtension`, `System keyboard`

### Thinking:
The strings definitively confirm:
1. Targets multiple password managers and browsers on Linux
2. Uses Mozilla NSS libraries to decrypt Firefox passwords
3. Keylogger with full keyboard event capture
4. Linux persistence via .desktop autostart files and .xinitrc
5. HTTP-based C2 communication
6. Process enumeration via /proc filesystem

---

## 6. Indicators of Compromise (IOCs)

### Command:
```bash
./lcre query iocs ./sample_files/sample_05
```

### Output:
```json
{
  "iocs": [
    {"type": "path", "value": "/proc/%i/exe"},
    {"type": "path", "value": "/proc/%s/exe"},
    {"type": "path", "value": "/proc/%s/stat"},
    {"type": "path", "value": "/proc/stat"},
    {"type": "path", "value": "/tmp/%s"},
    {"type": "path", "value": "/tmp/.%s"},
    {"type": "url", "value": "http://%s%s"},
    {"type": "domain", "value": "accounts.xml"},
    {"type": "domain", "value": "profiles.ini"},
    {"type": "domain", "value": "signons.sqlite"},
    {"type": "domain", "value": "libmozsqlite3.so"},
    {"type": "domain", "value": "libnss3.so"},
    {"type": "domain", "value": "libX11.so"},
    {"type": "domain", "value": "libXi.so"}
  ],
  "count": 31,
  "by_type": {
    "domain": 24,
    "path": 6,
    "url": 1
  }
}
```

### Thinking:
- The `/tmp/.%s` path with dot prefix indicates hidden file creation
- References to Mozilla libraries (libnss3.so, libmozsqlite3.so) for credential theft
- X11 libraries for screen capture and keylogging
- Dynamic URL construction pattern for C2

---

## 7. YARA Rule Analysis

### Command:
```bash
./lcre query yara ./sample_files/sample_05
```

### Output:
```json
{
  "path": "/home/maxime/scratch/lcre/sample_files/sample_05",
  "yara_available": true
}
```

### Thinking:
No YARA rules matched, but this doesn't indicate the file is clean. The binary may not match known malware signatures but clearly exhibits malicious functionality based on behavioral analysis.

---

## 8. Section Entropy Analysis

### Command:
```bash
./lcre query sections ./sample_files/sample_05
```

### Output:
| Section | Virtual Size | Permissions | Entropy |
|---------|-------------|-------------|---------|
| .text | 40594 | r-x | 6.24 |
| .rodata | 2797 | r-- | 6.24 |
| .data | 1560 | rw- | 6.24 |
| .bss | 15204 | rw- | 6.24 |

### Thinking:
- Entropy around 6.24 is within normal range (not packed/encrypted)
- The .text section at 40KB is the main code
- No high entropy sections indicating packed/encrypted payloads
- This appears to be a straightforward compiled binary, not obfuscated

---

## 9. Build Information

From strings:
```
GCC: (Ubuntu/Linaro 4.6.2-10ubuntu1~10.04.2) 4.6.2
GCC: (Ubuntu 4.4.3-4ubuntu5) 4.4.3
```

### Thinking:
- Compiled with GCC on Ubuntu 10.04 (Lucid Lynx)
- This is an older compiler, suggesting the malware was created several years ago
- The 32-bit architecture also suggests older development

---

## 10. Summary of Capabilities

This binary is a **Linux Remote Access Trojan (RAT)** with the following capabilities:

### Credential Theft:
- Firefox/Thunderbird/SeaMonkey passwords via NSS library decryption
- Google Chrome/Chromium saved passwords
- Opera browser passwords (wand.dat)
- Pidgin instant messenger accounts

### Surveillance:
- Keylogger with X11 input extension support
- Screen capture to JPEG
- Window enumeration and monitoring

### Remote Access:
- Bind shell functionality
- Reverse SOCKS proxy (SOCKS4/4a/5)
- HTTP tunneling
- Encrypted C2 communication (AES, RC4)

### Remote Control:
- Mouse movement and click simulation
- Keyboard input simulation
- Window manipulation (close, minimize, change title)

### Persistence:
- Linux autostart via .desktop files
- .xinitrc modification
- Daemon mode operation
- Mutex for single instance

### File Operations:
- Download and upload files
- Execute downloaded payloads
- File search, copy, delete, rename

---

## Final Classification

| Attribute | Value |
|-----------|-------|
| **Classification** | **MALICIOUS** |
| **Confidence** | **HIGH** |
| **Malware Type** | Linux Remote Access Trojan (RAT) |
| **Threat Level** | Critical |

### Key Findings Summary:

1. **237 exported functions** with explicit RAT functionality names (GetPidginPasswords, cpStartKeyLogger, BindShell, CaptureScreen, etc.)

2. **Multi-application credential theft** targeting Firefox, Chrome, Chromium, Opera, Thunderbird, SeaMonkey, and Pidgin

3. **Full keylogger implementation** using X11 input extension API

4. **Remote access capabilities** including bind shell, reverse SOCKS proxy, and HTTP tunneling

5. **Screen capture and remote desktop control** functionality

6. **Persistence mechanisms** via Linux autostart and daemon mode

7. **Encrypted communications** using AES and RC4

8. **No legitimate purpose** - the combination of features is exclusively used for malicious remote access and data theft

### Conclusion:

This binary is unambiguously a **fully-featured Linux RAT** designed for:
- Stealing credentials from multiple applications
- Monitoring user activity via keylogging and screen capture
- Providing remote access to the attacker
- Maintaining persistent access on compromised systems

The explicit function names and comprehensive feature set leave no doubt about the malicious intent of this software.
