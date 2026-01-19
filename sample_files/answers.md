# LCRE Blind Test - Ground Truth

## Sample Directory Contents

| Sample | Original Name | Source | Expected | Format | Description |
|--------|--------------|--------|----------|--------|-------------|
| sample_01 | Cygwin ls | binary-samples/pe-cygwin-ls.exe | LEGITIMATE | PE x86 | Cygwin ls command |
| sample_02 | Locky | theZoo/Ransomware.Locky | MALWARE | PE x86 | File encryption ransomware |
| sample_03 | Windows cmd x86 | binary-samples/pe-Windows-x86-cmd | LEGITIMATE | PE x86 | Windows cmd.exe |
| sample_04 | Petya | theZoo/Ransomware.Petya | MALWARE | PE x86 | MBR ransomware |
| sample_05 | Linux.Wirenet | theZoo/Linux.Wirenet | MALWARE | ELF x86 | Linux trojan - password stealer |
| sample_06 | Windows cmd x64 | binary-samples/pe-Windows-x64-cmd | LEGITIMATE | PE x64 | Windows cmd.exe |
| sample_07 | macOS ls | binary-samples/MachO-OSX-x64-ls | LEGITIMATE | Mach-O x64 | macOS ls command |
| sample_08 | FreeBSD echo | binary-samples/elf-FreeBSD-x86_64-echo | LEGITIMATE | ELF x64 | FreeBSD echo command |
| sample_09 | CryptoLocker | theZoo/CryptoLocker_10Sep2013 | MALWARE | PE x86 | Ransomware |
| sample_10 | Linux bash ARM64 | binary-samples/elf-Linux-ARM64-bash | LEGITIMATE | ELF ARM64 | Linux bash for ARM64 |
| sample_11 | Process Explorer | Sysinternals/procexp64.exe | LEGITIMATE | PE x64 | Sysinternals Process Explorer |
| sample_12 | Linux bash | binary-samples/elf-Linux-x64-bash | LEGITIMATE | ELF x64 | Linux bash shell |
| sample_13 | Mirai | theZoo/Linux.Mirai.B | MALWARE | ELF | IoT botnet - network scanning, DDoS |
| sample_14 | Linux ls ARMv7 | binary-samples/elf-Linux-ARMv7-ls | LEGITIMATE | ELF ARMv7 | Linux ls command |
| sample_15 | ZeusVM | theZoo/Win32.ZeusVM | MALWARE | PE x86 | Banking trojan - credential theft |
| sample_16 | BusyBox | busybox.net | LEGITIMATE | ELF x64 | BusyBox multi-call binary |
| sample_17 | Stuxnet | theZoo/TrojanWin32.Duqu.Stuxnet | MALWARE | PE x86 | Industrial control system malware |
| sample_18 | Linux.Encoder | theZoo/Linux.Encoder.1 | MALWARE | ELF x64 | Linux ransomware |
| sample_19 | WannaCry | theZoo/Ransomware.WannaCry | MALWARE | PE x64 | Ransomware - encrypts files |
| sample_20 | Emotet | theZoo/Win32.Emotet | MALWARE | PE x86 | Banking trojan/loader |

## Summary Statistics

- **Total samples:** 20
- **Legitimate samples:** 10 (samples 01, 03, 06, 07, 08, 10, 11, 12, 14, 16)
- **Malware samples:** 10 (samples 02, 04, 05, 09, 13, 15, 17, 18, 19, 20)

## File Formats

- **PE (Windows):** 12 samples
- **ELF (Linux/Unix):** 7 samples
- **Mach-O (macOS):** 1 sample

## Malware Families

1. **Ransomware:** WannaCry, Petya, Locky, CryptoLocker, Linux.Encoder
2. **Banking Trojans:** ZeusVM, Emotet
3. **Botnets:** Mirai
4. **APT Malware:** Stuxnet
5. **Linux Trojans:** Linux.Wirenet
