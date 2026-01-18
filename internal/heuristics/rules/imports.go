package rules

import (
	"context"
	"fmt"
	"strings"

	"github.com/maxime/lcre/internal/model"
)

// Suspicious import patterns
var processInjectionImports = []string{
	"CreateRemoteThread",
	"WriteProcessMemory",
	"VirtualAllocEx",
	"NtCreateThreadEx",
	"RtlCreateUserThread",
	"NtWriteVirtualMemory",
	"NtAllocateVirtualMemory",
	"QueueUserAPC",
	"SetThreadContext",
	"NtQueueApcThread",
	"NtMapViewOfSection",
	"NtUnmapViewOfSection",
}

var antiDebugImports = []string{
	"IsDebuggerPresent",
	"CheckRemoteDebuggerPresent",
	"NtQueryInformationProcess",
	"OutputDebugString",
	"GetTickCount",
	"QueryPerformanceCounter",
	"NtSetInformationThread",
	"ZwSetInformationThread",
	"NtQuerySystemInformation",
	"CloseHandle", // used with invalid handle for anti-debug
}

var persistenceImports = []string{
	"RegSetValueEx",
	"RegCreateKeyEx",
	"CreateService",
	"ChangeServiceConfig",
	"StartService",
	"CreateScheduledTask",
	"SHSetValue",
	"WritePrivateProfileString",
}

var cryptoImports = []string{
	"CryptEncrypt",
	"CryptDecrypt",
	"CryptGenKey",
	"CryptAcquireContext",
	"CryptCreateHash",
	"CryptHashData",
	"CryptDeriveKey",
	"BCryptEncrypt",
	"BCryptDecrypt",
	"BCryptGenerateSymmetricKey",
}

// ProcessInjectionRule detects process injection capabilities
type ProcessInjectionRule struct{}

func NewProcessInjectionRule() *ProcessInjectionRule { return &ProcessInjectionRule{} }

func (r *ProcessInjectionRule) ID() string              { return "IMPORT001" }
func (r *ProcessInjectionRule) Name() string            { return "Process Injection APIs" }
func (r *ProcessInjectionRule) Category() model.Category { return model.CategoryInjection }
func (r *ProcessInjectionRule) Severity() model.Severity { return model.SeverityHigh }

func (r *ProcessInjectionRule) Description() string {
	return "Binary imports APIs commonly used for process injection"
}

func (r *ProcessInjectionRule) Evaluate(ctx context.Context, result *model.AnalysisResult) (bool, []string) {
	return checkImports(result, processInjectionImports)
}

// AntiDebugRule detects anti-debugging capabilities
type AntiDebugRule struct{}

func NewAntiDebugRule() *AntiDebugRule { return &AntiDebugRule{} }

func (r *AntiDebugRule) ID() string              { return "IMPORT002" }
func (r *AntiDebugRule) Name() string            { return "Anti-Debug APIs" }
func (r *AntiDebugRule) Category() model.Category { return model.CategoryAntiDebug }
func (r *AntiDebugRule) Severity() model.Severity { return model.SeverityMedium }

func (r *AntiDebugRule) Description() string {
	return "Binary imports APIs commonly used for anti-debugging"
}

func (r *AntiDebugRule) Evaluate(ctx context.Context, result *model.AnalysisResult) (bool, []string) {
	return checkImports(result, antiDebugImports)
}

// PersistenceRule detects persistence capabilities
type PersistenceRule struct{}

func NewPersistenceRule() *PersistenceRule { return &PersistenceRule{} }

func (r *PersistenceRule) ID() string              { return "IMPORT003" }
func (r *PersistenceRule) Name() string            { return "Persistence APIs" }
func (r *PersistenceRule) Category() model.Category { return model.CategoryPersistence }
func (r *PersistenceRule) Severity() model.Severity { return model.SeverityHigh }

func (r *PersistenceRule) Description() string {
	return "Binary imports APIs commonly used for persistence mechanisms"
}

func (r *PersistenceRule) Evaluate(ctx context.Context, result *model.AnalysisResult) (bool, []string) {
	return checkImports(result, persistenceImports)
}

// CryptoRule detects cryptographic capabilities
type CryptoRule struct{}

func NewCryptoRule() *CryptoRule { return &CryptoRule{} }

func (r *CryptoRule) ID() string              { return "IMPORT004" }
func (r *CryptoRule) Name() string            { return "Cryptographic APIs" }
func (r *CryptoRule) Category() model.Category { return model.CategoryCrypto }
func (r *CryptoRule) Severity() model.Severity { return model.SeverityLow }

func (r *CryptoRule) Description() string {
	return "Binary imports cryptographic APIs (potential ransomware indicator)"
}

func (r *CryptoRule) Evaluate(ctx context.Context, result *model.AnalysisResult) (bool, []string) {
	return checkImports(result, cryptoImports)
}

// checkImports is a helper to check for suspicious imports
func checkImports(result *model.AnalysisResult, suspicious []string) (bool, []string) {
	var evidence []string

	for _, imp := range result.Imports {
		for _, sus := range suspicious {
			if strings.EqualFold(imp.Function, sus) {
				evidence = append(evidence, imp.Library+":"+imp.Function)
			}
		}
	}

	return len(evidence) > 0, evidence
}

// MinimalImportsRule detects binaries with suspiciously few imports (likely packed)
type MinimalImportsRule struct {
	minImports int
}

func NewMinimalImportsRule() *MinimalImportsRule {
	return &MinimalImportsRule{minImports: 5}
}

func (r *MinimalImportsRule) ID() string              { return "IMPORT005" }
func (r *MinimalImportsRule) Name() string            { return "Minimal Imports" }
func (r *MinimalImportsRule) Category() model.Category { return model.CategoryPacker }
func (r *MinimalImportsRule) Severity() model.Severity { return model.SeverityMedium }

func (r *MinimalImportsRule) Description() string {
	return "Binary has suspiciously few imports, suggesting packing or obfuscation"
}

func (r *MinimalImportsRule) Evaluate(ctx context.Context, result *model.AnalysisResult) (bool, []string) {
	// Only check PE files - ELF and Mach-O typically have different import patterns
	if result.Metadata.Format != model.FormatPE {
		return false, nil
	}

	// Count unique imports, excluding very basic loader functions
	basicImports := map[string]bool{
		"LoadLibraryA":       true,
		"LoadLibraryW":       true,
		"GetProcAddress":     true,
		"GetModuleHandleA":   true,
		"GetModuleHandleW":   true,
		"VirtualAlloc":       true,
		"VirtualProtect":     true,
		"ExitProcess":        true,
	}

	totalImports := len(result.Imports)
	nonBasicCount := 0

	for _, imp := range result.Imports {
		if !basicImports[imp.Function] {
			nonBasicCount++
		}
	}

	// Very few imports is suspicious for PE files
	if totalImports > 0 && totalImports < r.minImports {
		var evidence []string
		evidence = append(evidence, fmt.Sprintf("Only %d total imports detected", totalImports))

		// Check if it's mostly just loader functions
		if nonBasicCount == 0 {
			evidence = append(evidence, "All imports are basic loader functions (LoadLibrary, GetProcAddress)")
		}

		return true, evidence
	}

	// Also flag if ONLY loader functions are present (common packer pattern)
	if totalImports > 0 && nonBasicCount == 0 {
		return true, []string{
			fmt.Sprintf("%d imports, but all are basic loader functions (LoadLibrary, GetProcAddress)", totalImports),
			"Typical pattern for packed executables that resolve imports at runtime",
		}
	}

	return false, nil
}

// DiskAccessRule detects low-level disk access APIs (MBR/bootkit indicator)
type DiskAccessRule struct{}

func NewDiskAccessRule() *DiskAccessRule { return &DiskAccessRule{} }

func (r *DiskAccessRule) ID() string              { return "IMPORT006" }
func (r *DiskAccessRule) Name() string            { return "Low-Level Disk Access" }
func (r *DiskAccessRule) Category() model.Category { return model.CategoryEvasion }
func (r *DiskAccessRule) Severity() model.Severity { return model.SeverityHigh }

func (r *DiskAccessRule) Description() string {
	return "Binary imports APIs for low-level disk access (potential bootkit/MBR malware)"
}

var diskAccessImports = []string{
	"CreateFileA",
	"CreateFileW",
	"DeviceIoControl",
	"WriteFile",
	"ReadFile",
	"SetFilePointer",
	"SetFilePointerEx",
	"NtCreateFile",
	"NtWriteFile",
	"NtReadFile",
	"ZwCreateFile",
	"ZwWriteFile",
	"ZwReadFile",
}

func (r *DiskAccessRule) Evaluate(ctx context.Context, result *model.AnalysisResult) (bool, []string) {
	// First check for disk access imports
	hasFileAPI := false
	hasDeviceIoControl := false
	var evidence []string

	for _, imp := range result.Imports {
		fnLower := strings.ToLower(imp.Function)
		for _, diskAPI := range diskAccessImports {
			if strings.EqualFold(imp.Function, diskAPI) {
				if diskAPI == "DeviceIoControl" {
					hasDeviceIoControl = true
				}
				if strings.HasPrefix(fnLower, "createfile") || strings.HasPrefix(fnLower, "ntcreatefile") || strings.HasPrefix(fnLower, "zwcreatefile") {
					hasFileAPI = true
				}
			}
		}
	}

	// Check for PhysicalDrive or raw disk access patterns in strings
	if hasFileAPI {
		for _, s := range result.Strings {
			strLower := strings.ToLower(s.Value)
			if strings.Contains(strLower, "physicaldrive") ||
				strings.Contains(strLower, "\\\\.\\") ||
				strings.Contains(strLower, "harddisk") {
				evidence = append(evidence, fmt.Sprintf("Raw disk access pattern: %q", s.Value))
			}
		}
	}

	// DeviceIoControl with file APIs is very suspicious for disk manipulation
	if hasDeviceIoControl && hasFileAPI && len(evidence) > 0 {
		evidence = append([]string{"Imports DeviceIoControl with CreateFile APIs"}, evidence...)
		return true, evidence
	}

	// Just having the string patterns is suspicious even without DeviceIoControl
	if len(evidence) > 0 {
		return true, evidence
	}

	return false, nil
}
