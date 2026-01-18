package yara

import (
	"os"
	"path/filepath"
)

// EmbeddedRules contains YARA rules for common malware families
// These rules are based on public YARA rule repositories and malware research
const EmbeddedRules = `
/*
 * LCRE Embedded YARA Rules
 * Based on public malware research and YARA rule repositories
 */

// ============== PACKERS AND PROTECTORS ==============

rule UPX_Packed {
    meta:
        description = "Detects UPX packed executables"
        category = "packer"
    strings:
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
        $upx2 = "UPX2" ascii
        $sig = { 55 50 58 21 }
    condition:
        uint16(0) == 0x5A4D and (any of ($upx*) or $sig)
}

rule VMProtect_Packed {
    meta:
        description = "Detects VMProtect packed executables"
        category = "packer"
    strings:
        $vmp0 = ".vmp0" ascii
        $vmp1 = ".vmp1" ascii
        $vmprotect = "VMProtect" ascii wide
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule Themida_Packed {
    meta:
        description = "Detects Themida/WinLicense packed executables"
        category = "packer"
    strings:
        $themida = ".themida" ascii
        $winlicense = "WinLicense" ascii wide
        $oreans = "Oreans" ascii wide
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule ASPack_Packed {
    meta:
        description = "Detects ASPack packed executables"
        category = "packer"
    strings:
        $aspack = ".aspack" ascii
        $adata = ".adata" ascii
    condition:
        uint16(0) == 0x5A4D and any of them
}

// ============== RANSOMWARE FAMILIES ==============

rule Locky_Ransomware {
    meta:
        description = "Detects Locky ransomware indicators"
        category = "ransomware"
        family = "Locky"
        reference = "https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Ransom:Win32/Locky"
    strings:
        $ext1 = ".locky" ascii wide nocase
        $ext2 = ".zepto" ascii wide nocase
        $ext3 = ".odin" ascii wide nocase
        $ext4 = ".thor" ascii wide nocase
        $ext5 = ".aesir" ascii wide nocase
        $msg1 = "_HELP_instructions" ascii wide nocase
        $msg2 = "DECRYPT" ascii wide nocase
        $msg3 = "All of your files were protected" ascii wide nocase
        $ransom1 = "bitcoin" ascii wide nocase
        $ransom2 = ".onion" ascii wide nocase
        $api1 = "CryptGenKey" ascii
        $api2 = "CryptEncrypt" ascii
        $api3 = "CryptDestroyKey" ascii
    condition:
        uint16(0) == 0x5A4D and (
            (any of ($ext*) and any of ($msg*)) or
            (any of ($ext*) and 2 of ($api*)) or
            (any of ($msg*) and any of ($ransom*) and 2 of ($api*))
        )
}

rule Petya_Ransomware {
    meta:
        description = "Detects Petya/NotPetya/GoldenEye ransomware"
        category = "ransomware"
        family = "Petya"
        reference = "https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Ransom:Win32/Petya"
    strings:
        $petya1 = "PETYA" ascii wide
        $petya2 = "petya" ascii wide
        $goldeneye = "GoldenEye" ascii wide
        $ransom1 = "Your important files are encrypted" ascii wide nocase
        $ransom2 = "Ooops, your important files are encrypted" ascii wide nocase
        $ransom3 = "wowsmith123456" ascii wide
        $disk1 = "\\\\.\\PhysicalDrive" ascii wide nocase
        $disk2 = "DeviceIoControl" ascii
        $wmic = "wmic" ascii wide nocase
        $psexec = "psexec" ascii wide nocase
        $perfc = "perfc.dat" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and (
            any of ($petya*) or
            $goldeneye or
            (any of ($ransom*) and any of ($disk*)) or
            (any of ($ransom*) and ($wmic or $psexec)) or
            ($perfc and any of ($disk*))
        )
}

rule NotPetya_Variant {
    meta:
        description = "Detects NotPetya specific indicators"
        category = "ransomware"
        family = "NotPetya"
    strings:
        $medoc = "MeDoc" ascii wide nocase
        $eternalblue = { 31 C9 41 B8 01 00 00 00 }
        $wmi1 = "Win32_Process" ascii wide
        $wmi2 = "Win32_OperatingSystem" ascii wide
        $key = "27WishMaster" ascii wide
    condition:
        uint16(0) == 0x5A4D and (
            $medoc or
            ($eternalblue and any of ($wmi*)) or
            $key
        )
}

rule WannaCry_Ransomware {
    meta:
        description = "Detects WannaCry ransomware"
        category = "ransomware"
        family = "WannaCry"
    strings:
        $wannacry1 = "WanaCrypt0r" ascii wide
        $wannacry2 = "WannaCry" ascii wide
        $wannacry3 = "WANACRY" ascii wide
        $wannacry4 = "WNcry@2ol7" ascii wide
        $ransom = "@Please_Read_Me@.txt" ascii wide
        $ext = ".WNCRY" ascii wide
        $mutex = "MsWinZonesCacheCounterMutexA" ascii wide
        $killswitch = "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea" ascii wide
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule Ryuk_Ransomware {
    meta:
        description = "Detects Ryuk ransomware"
        category = "ransomware"
        family = "Ryuk"
    strings:
        $ryuk1 = "RYUK" ascii wide
        $ryuk2 = "RyukReadMe" ascii wide
        $ext = ".RYK" ascii wide
        $ransom = "balance of shadow universe" ascii wide nocase
        $cmd1 = "vssadmin Delete Shadows" ascii wide nocase
        $cmd2 = "bcdedit /set" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and (
            any of ($ryuk*) or
            $ext or
            ($ransom and any of ($cmd*))
        )
}

// ============== APT / SOPHISTICATED MALWARE ==============

rule Stuxnet_Indicators {
    meta:
        description = "Detects Stuxnet malware indicators"
        category = "apt"
        family = "Stuxnet"
        reference = "https://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/w32_stuxnet_dossier.pdf"
    strings:
        $str1 = "b:\\myrtus\\src" ascii wide nocase
        $str2 = "\\driver\\mrxcls" ascii wide nocase
        $str3 = "\\driver\\mrxnet" ascii wide nocase
        $mrxcls = "MRXCLS.SYS" ascii wide nocase
        $mrxnet = "MRXNET.SYS" ascii wide nocase
        $siemens1 = "WinCC" ascii wide nocase
        $siemens2 = "Step7" ascii wide nocase
        $siemens3 = "S7OTBXDX" ascii wide nocase
        $siemens4 = "SIMATIC" ascii wide nocase
        $plc = "PLC" ascii wide
        $profibus = "profibus" ascii wide nocase
        $opc1 = "OPCServer" ascii wide
        $opc2 = "OPCEnum" ascii wide
        $realtek = "Realtek Semiconductor" ascii wide
        $jmicron = "JMicron Technology" ascii wide
        $tasksche = "tasksche.exe" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and (
            any of ($str*) or
            any of ($mrx*) or
            (2 of ($siemens*)) or
            (($plc or $profibus) and any of ($opc*)) or
            ($realtek and $jmicron) or
            $tasksche
        )
}

rule Duqu_Malware {
    meta:
        description = "Detects Duqu malware (Stuxnet-related)"
        category = "apt"
        family = "Duqu"
    strings:
        $duqu1 = "~DQ" ascii wide
        $duqu2 = "~DF" ascii wide
        $font = "Dexter Regular" ascii wide
    condition:
        uint16(0) == 0x5A4D and (any of ($duqu*) or $font)
}

rule Flame_Malware {
    meta:
        description = "Detects Flame/Flamer malware"
        category = "apt"
        family = "Flame"
    strings:
        $flame1 = "FLAME::" ascii wide
        $flame2 = "~DEB93D.tmp" ascii wide
        $lss = "Local Security Authority" ascii wide
        $mssecmgr = "mssecmgr.ocx" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and any of them
}

// ============== TROJANS AND BACKDOORS ==============

rule Emotet_Trojan {
    meta:
        description = "Detects Emotet trojan"
        category = "trojan"
        family = "Emotet"
    strings:
        $str1 = "BCryptGenRandom" ascii
        $str2 = "BCryptEncrypt" ascii
        $ua = "Mozilla/5.0" ascii wide
        $reg1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide
        $proc = "CreateProcessW" ascii
    condition:
        uint16(0) == 0x5A4D and
        all of ($str*) and $proc and ($ua or $reg1)
}

rule Trickbot_Trojan {
    meta:
        description = "Detects Trickbot trojan"
        category = "trojan"
        family = "Trickbot"
    strings:
        $trick1 = "moduleconfig" ascii wide nocase
        $trick2 = "dpost" ascii wide nocase
        $trick3 = "pwgrab" ascii wide nocase
        $trick4 = "networkDll" ascii wide nocase
        $cmd1 = "ipconfig /all" ascii wide
        $cmd2 = "net view" ascii wide
    condition:
        uint16(0) == 0x5A4D and (
            2 of ($trick*) or
            (any of ($trick*) and any of ($cmd*))
        )
}

rule AgentTesla_Stealer {
    meta:
        description = "Detects AgentTesla information stealer"
        category = "stealer"
        family = "AgentTesla"
    strings:
        $dotnet1 = "_CorExeMain" ascii
        $smtp = "SmtpClient" ascii wide
        $ftp = "FtpWebRequest" ascii wide
        $steal1 = "\\logins.json" ascii wide
        $steal2 = "\\Login Data" ascii wide
        $steal3 = "Cookies" ascii wide
        $browser1 = "chrome" ascii wide nocase
        $browser2 = "firefox" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and $dotnet1 and (
            ($smtp or $ftp) and
            2 of ($steal*) and
            any of ($browser*)
        )
}

// ============== COBALT STRIKE AND RED TEAM TOOLS ==============

rule CobaltStrike_Beacon {
    meta:
        description = "Detects Cobalt Strike Beacon"
        category = "c2"
        family = "CobaltStrike"
    strings:
        $str1 = "%s.4444" ascii
        $str2 = "%s as %s\\%s: %d" ascii
        $str3 = "beacon.dll" ascii wide
        $str4 = "ReflectiveLoader" ascii
        $config = { 00 01 00 01 00 02 ?? ?? 00 02 00 01 00 02 ?? ?? }
        $xor_key = { 69 68 69 68 }
    condition:
        uint16(0) == 0x5A4D and (
            2 of ($str*) or
            $config or
            $xor_key
        )
}

rule Metasploit_Payload {
    meta:
        description = "Detects Metasploit shellcode/payload"
        category = "exploit"
        family = "Metasploit"
    strings:
        $meterp1 = "metsrv" ascii wide
        $meterp2 = "meterpreter" ascii wide nocase
        $shell1 = { FC E8 82 00 00 00 60 89 E5 }
        $shell2 = { FC 48 83 E4 F0 E8 }
        $stage = "stage" ascii wide
    condition:
        uint16(0) == 0x5A4D and any of them
}

// ============== GENERIC SUSPICIOUS PATTERNS ==============

rule Suspicious_PDB_Path {
    meta:
        description = "Detects suspicious PDB paths often found in malware"
        category = "suspicious"
    strings:
        $pdb1 = "C:\\Users\\Admin\\" ascii wide nocase
        $pdb2 = "C:\\Users\\user\\" ascii wide nocase
        $pdb3 = "\\Desktop\\malware" ascii wide nocase
        $pdb4 = "\\Release\\payload" ascii wide nocase
        $pdb5 = "\\Debug\\inject" ascii wide nocase
        $pdb6 = "C:\\hack\\" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule Suspicious_Strings_Generic {
    meta:
        description = "Detects generic suspicious strings"
        category = "suspicious"
    strings:
        $cmd1 = "cmd.exe /c" ascii wide nocase
        $cmd2 = "powershell -e" ascii wide nocase
        $cmd3 = "powershell -enc" ascii wide nocase
        $ps1 = "FromBase64String" ascii wide
        $ps2 = "Invoke-Expression" ascii wide
        $ps3 = "-WindowStyle Hidden" ascii wide nocase
        $amsi = "AmsiScanBuffer" ascii
        $etw = "EtwEventWrite" ascii
    condition:
        uint16(0) == 0x5A4D and (
            all of ($cmd*) or
            2 of ($ps*) or
            ($amsi and $etw)
        )
}

rule AntiVM_Techniques {
    meta:
        description = "Detects anti-VM/anti-sandbox techniques"
        category = "evasion"
    strings:
        $vm1 = "VMware" ascii wide nocase
        $vm2 = "VirtualBox" ascii wide nocase
        $vm3 = "VBOX" ascii wide nocase
        $vm4 = "Virtual HD" ascii wide nocase
        $vm5 = "Hyper-V" ascii wide nocase
        $sand1 = "SbieDll" ascii wide
        $sand2 = "Sandboxie" ascii wide nocase
        $sand3 = "cuckoomon" ascii wide nocase
        $sand4 = "vmcheck" ascii wide nocase
        $timing1 = "GetTickCount" ascii
        $timing2 = "QueryPerformanceCounter" ascii
        $timing3 = "rdtsc" ascii
        $sleep = "kernel32.dll" ascii wide
    condition:
        uint16(0) == 0x5A4D and (
            3 of ($vm*) or
            2 of ($sand*) or
            (2 of ($timing*) and $sleep)
        )
}
`

// WriteEmbeddedRules writes the embedded rules to a temporary file and returns the path
func WriteEmbeddedRules() (string, error) {
	tmpDir := os.TempDir()
	rulesPath := filepath.Join(tmpDir, "lcre_yara_rules.yar")

	err := os.WriteFile(rulesPath, []byte(EmbeddedRules), 0644)
	if err != nil {
		return "", err
	}

	return rulesPath, nil
}

// GetRuleCategories returns the categories of rules available
func GetRuleCategories() []string {
	return []string{
		"packer",
		"ransomware",
		"apt",
		"trojan",
		"stealer",
		"c2",
		"exploit",
		"suspicious",
		"evasion",
	}
}

// GetRuleFamilies returns malware families covered by embedded rules
func GetRuleFamilies() []string {
	return []string{
		"Locky",
		"Petya",
		"NotPetya",
		"WannaCry",
		"Ryuk",
		"Stuxnet",
		"Duqu",
		"Flame",
		"Emotet",
		"Trickbot",
		"AgentTesla",
		"CobaltStrike",
		"Metasploit",
	}
}
