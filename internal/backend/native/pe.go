package native

import (
	"context"
	"crypto/md5"
	"debug/pe"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/refractionPOINT/lcre/internal/model"
)

// Ordinal to function name mappings for common DLLs
// These are the most common ordinals that malware uses to evade string-based detection
var ordinalMap = map[string]map[int]string{
	"oleaut32.dll": {
		2:   "SysAllocString",
		4:   "SysAllocStringByteLen",
		6:   "SysFreeString",
		7:   "SysReAllocStringLen",
		8:   "VariantInit",
		9:   "VariantClear",
		10:  "VariantCopy",
		147: "VarI4FromStr",
	},
	"ws2_32.dll": {
		1:   "accept",
		2:   "bind",
		3:   "closesocket",
		4:   "connect",
		9:   "getpeername",
		10:  "getsockname",
		11:  "getsockopt",
		12:  "htonl",
		13:  "htons",
		14:  "ioctlsocket",
		15:  "inet_addr",
		16:  "inet_ntoa",
		17:  "listen",
		18:  "ntohl",
		19:  "ntohs",
		20:  "recv",
		21:  "recvfrom",
		22:  "select",
		23:  "send",
		24:  "sendto",
		25:  "setsockopt",
		26:  "shutdown",
		27:  "socket",
		51:  "gethostbyname",
		52:  "gethostbyaddr",
		111: "WSAStartup",
		115: "WSACleanup",
		116: "WSASetLastError",
		151: "WSASend",
		152: "WSASendTo",
		153: "WSARecv",
		154: "WSARecvFrom",
	},
}

// parsePE parses a PE binary and populates the result
func parsePE(ctx context.Context, path string, result *model.AnalysisResult) error {
	f, err := pe.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open PE file: %w", err)
	}
	defer f.Close()

	// Check for context cancellation
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// Set architecture info
	switch f.Machine {
	case pe.IMAGE_FILE_MACHINE_I386:
		result.Metadata.Arch = "x86"
		result.Metadata.Bits = 32
	case pe.IMAGE_FILE_MACHINE_AMD64:
		result.Metadata.Arch = "x86_64"
		result.Metadata.Bits = 64
	case pe.IMAGE_FILE_MACHINE_ARM:
		result.Metadata.Arch = "ARM"
		result.Metadata.Bits = 32
	case pe.IMAGE_FILE_MACHINE_ARM64:
		result.Metadata.Arch = "ARM64"
		result.Metadata.Bits = 64
	default:
		result.Metadata.Arch = fmt.Sprintf("unknown (0x%x)", f.Machine)
	}

	result.Metadata.Endian = "little"
	result.Metadata.Timestamp = int64(f.FileHeader.TimeDateStamp)

	// Initialize PE info
	peInfo := &model.PEInfo{
		NumberOfSections: len(f.Sections),
	}

	// Get optional header info
	var entryPointRVA uint32
	if optHdr, ok := f.OptionalHeader.(*pe.OptionalHeader32); ok {
		peInfo.Checksum = optHdr.CheckSum
		peInfo.ImageBase = uint64(optHdr.ImageBase)
		peInfo.SectionAlignment = optHdr.SectionAlignment
		peInfo.FileAlignment = optHdr.FileAlignment
		peInfo.SizeOfHeaders = optHdr.SizeOfHeaders
		peInfo.Subsystem = optHdr.Subsystem
		peInfo.DllCharacteristics = optHdr.DllCharacteristics
		entryPointRVA = optHdr.AddressOfEntryPoint
		result.EntryPoints = append(result.EntryPoints, model.EntryPoint{
			Name:    "main",
			Address: uint64(optHdr.AddressOfEntryPoint),
			Type:    "entry",
		})
	} else if optHdr, ok := f.OptionalHeader.(*pe.OptionalHeader64); ok {
		peInfo.Checksum = optHdr.CheckSum
		peInfo.ImageBase = optHdr.ImageBase
		peInfo.SectionAlignment = optHdr.SectionAlignment
		peInfo.FileAlignment = optHdr.FileAlignment
		peInfo.SizeOfHeaders = optHdr.SizeOfHeaders
		peInfo.Subsystem = optHdr.Subsystem
		peInfo.DllCharacteristics = optHdr.DllCharacteristics
		entryPointRVA = optHdr.AddressOfEntryPoint
		result.EntryPoints = append(result.EntryPoints, model.EntryPoint{
			Name:    "main",
			Address: uint64(optHdr.AddressOfEntryPoint),
			Type:    "entry",
		})
	}

	// Parse sections and find entry point section
	for _, sec := range f.Sections {
		section := model.Section{
			Name:            sec.Name,
			VirtualAddr:     uint64(sec.VirtualAddress),
			VirtualSize:     uint64(sec.VirtualSize),
			RawSize:         uint64(sec.Size),
			Characteristics: sec.Characteristics,
			Permissions:     pePermissions(sec.Characteristics),
		}
		result.Sections = append(result.Sections, section)

		// Check if entry point is in this section
		secStart := sec.VirtualAddress
		secEnd := secStart + sec.VirtualSize
		if entryPointRVA >= secStart && entryPointRVA < secEnd {
			peInfo.EntryPointSection = sec.Name
		}
	}

	result.PEInfo = peInfo

	// Parse imports and calculate imphash
	var impHashParts []string
	imports, err := f.ImportedSymbols()
	if err == nil {
		for _, imp := range imports {
			lib, fn := splitImport(imp)
			result.Imports = append(result.Imports, model.Import{
				Library:  lib,
				Function: fn,
			})

			// Prepare for imphash calculation
			// Normalize: lowercase, remove extension
			libLower := strings.ToLower(lib)
			libLower = strings.TrimSuffix(libLower, ".dll")
			libLower = strings.TrimSuffix(libLower, ".ocx")
			libLower = strings.TrimSuffix(libLower, ".sys")

			fnLower := strings.ToLower(fn)

			// Try to resolve ordinal imports
			if ordinals, ok := ordinalMap[strings.ToLower(lib)]; ok {
				// Check if fn is an ordinal reference
				var ordinal int
				if _, err := fmt.Sscanf(fn, "#%d", &ordinal); err == nil {
					if name, ok := ordinals[ordinal]; ok {
						fnLower = strings.ToLower(name)
					}
				}
			}

			impHashParts = append(impHashParts, libLower+"."+fnLower)
		}

		// Calculate imphash (MD5 of comma-separated import list)
		if len(impHashParts) > 0 {
			impHashStr := strings.Join(impHashParts, ",")
			hash := md5.Sum([]byte(impHashStr))
			result.Metadata.ImpHash = hex.EncodeToString(hash[:])
		}
	}

	return nil
}

// pePermissions converts PE section characteristics to permission string
func pePermissions(chars uint32) string {
	perms := ""
	if chars&pe.IMAGE_SCN_MEM_READ != 0 {
		perms += "r"
	} else {
		perms += "-"
	}
	if chars&pe.IMAGE_SCN_MEM_WRITE != 0 {
		perms += "w"
	} else {
		perms += "-"
	}
	if chars&pe.IMAGE_SCN_MEM_EXECUTE != 0 {
		perms += "x"
	} else {
		perms += "-"
	}
	return perms
}

// splitImport splits a PE import string (dll:function) into library and function
func splitImport(imp string) (string, string) {
	for i := len(imp) - 1; i >= 0; i-- {
		if imp[i] == ':' {
			return imp[:i], imp[i+1:]
		}
	}
	return "", imp
}
