package native

import (
	"context"
	"debug/pe"
	"fmt"

	"github.com/maxime/lcre/internal/model"
)

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

	// Get timestamp from optional header
	if optHdr, ok := f.OptionalHeader.(*pe.OptionalHeader32); ok {
		result.Metadata.Timestamp = int64(optHdr.SizeOfStackCommit) // Using as placeholder, real timestamp is in FileHeader
	} else if optHdr, ok := f.OptionalHeader.(*pe.OptionalHeader64); ok {
		_ = optHdr // Using as placeholder
	}
	result.Metadata.Timestamp = int64(f.FileHeader.TimeDateStamp)

	// Parse sections
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
	}

	// Parse imports
	imports, err := f.ImportedSymbols()
	if err == nil {
		for _, imp := range imports {
			lib, fn := splitImport(imp)
			result.Imports = append(result.Imports, model.Import{
				Library:  lib,
				Function: fn,
			})
		}
	}

	// Parse exports (PE files can have exports too)
	// The standard library doesn't expose this directly, so we'll skip for now
	// Could be added with custom PE parsing

	// Parse entry point
	if optHdr, ok := f.OptionalHeader.(*pe.OptionalHeader32); ok {
		result.EntryPoints = append(result.EntryPoints, model.EntryPoint{
			Name:    "main",
			Address: uint64(optHdr.AddressOfEntryPoint),
			Type:    "entry",
		})
	} else if optHdr, ok := f.OptionalHeader.(*pe.OptionalHeader64); ok {
		result.EntryPoints = append(result.EntryPoints, model.EntryPoint{
			Name:    "main",
			Address: uint64(optHdr.AddressOfEntryPoint),
			Type:    "entry",
		})
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

// PE section characteristics constants
const (
	IMAGE_SCN_MEM_READ    = 0x40000000
	IMAGE_SCN_MEM_WRITE   = 0x80000000
	IMAGE_SCN_MEM_EXECUTE = 0x20000000
)
