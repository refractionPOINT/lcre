package native

import (
	"context"
	"debug/macho"
	"fmt"

	"github.com/maxime/lcre/internal/model"
)

// parseMachO parses a Mach-O binary and populates the result
func parseMachO(ctx context.Context, path string, result *model.AnalysisResult) error {
	f, err := macho.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open Mach-O file: %w", err)
	}
	defer f.Close()

	// Check for context cancellation
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// Set architecture info
	switch f.Cpu {
	case macho.Cpu386:
		result.Metadata.Arch = "x86"
		result.Metadata.Bits = 32
	case macho.CpuAmd64:
		result.Metadata.Arch = "x86_64"
		result.Metadata.Bits = 64
	case macho.CpuArm:
		result.Metadata.Arch = "ARM"
		result.Metadata.Bits = 32
	case macho.CpuArm64:
		result.Metadata.Arch = "ARM64"
		result.Metadata.Bits = 64
	case macho.CpuPpc:
		result.Metadata.Arch = "PPC"
		result.Metadata.Bits = 32
	case macho.CpuPpc64:
		result.Metadata.Arch = "PPC64"
		result.Metadata.Bits = 64
	default:
		result.Metadata.Arch = fmt.Sprintf("unknown (0x%x)", f.Cpu)
	}

	// Mach-O byte order
	if f.ByteOrder.String() == "LittleEndian" {
		result.Metadata.Endian = "little"
	} else {
		result.Metadata.Endian = "big"
	}

	// Parse sections (within segments)
	for _, sec := range f.Sections {
		if sec == nil {
			continue
		}
		section := model.Section{
			Name:        sec.Name,
			VirtualAddr: sec.Addr,
			VirtualSize: sec.Size,
			RawSize:     uint64(sec.Size),
			Permissions: machoPermissions(sec.Flags),
		}
		result.Sections = append(result.Sections, section)
	}

	// Parse imports
	imports, err := f.ImportedSymbols()
	if err == nil {
		for _, imp := range imports {
			result.Imports = append(result.Imports, model.Import{
				Function: imp,
			})
		}
	}

	// Parse imported libraries
	libs, err := f.ImportedLibraries()
	if err == nil {
		for _, lib := range libs {
			result.Imports = append(result.Imports, model.Import{
				Library:  lib,
				Function: "*",
			})
		}
	}

	// Parse symbols for exports
	if f.Symtab != nil {
		for _, sym := range f.Symtab.Syms {
			// External symbols that are defined (have a value)
			if sym.Type&0x01 != 0 && sym.Value != 0 {
				result.Exports = append(result.Exports, model.Export{
					Name:    sym.Name,
					Address: sym.Value,
				})
			}
		}
	}

	// Entry point (LC_MAIN or LC_UNIXTHREAD)
	// The standard library doesn't directly expose this, so we use a placeholder
	// In a real implementation, we'd parse the load commands directly
	result.EntryPoints = append(result.EntryPoints, model.EntryPoint{
		Name:    "main",
		Address: 0, // Would need custom parsing to get actual entry point
		Type:    "entry",
	})

	return nil
}

// machoPermissions converts Mach-O section flags to permission string
func machoPermissions(flags uint32) string {
	// Mach-O section flags don't directly encode permissions
	// Permissions are in the segment, not the section
	// We make educated guesses based on section type
	perms := "r"

	// Check for code sections
	sectionType := flags & 0xFF
	if sectionType == 0x80000000 { // S_ATTR_PURE_INSTRUCTIONS
		return "r-x"
	}
	if flags&0x80000000 != 0 { // S_ATTR_PURE_INSTRUCTIONS
		perms += "-x"
	} else if flags&0x400 != 0 { // S_ATTR_SOME_INSTRUCTIONS
		perms += "-x"
	} else {
		perms += "w-"
	}

	return perms
}
