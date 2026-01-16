package rules

import (
	"context"
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
