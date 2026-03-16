package native

import (
	"context"
	"debug/macho"
	"fmt"

	"github.com/refractionPOINT/lcre/internal/model"
)

// parseMachO parses a Mach-O binary and populates the result.
// Handles both single-architecture and fat/universal (0xCAFEBABE) binaries.
func parseMachO(ctx context.Context, path string, result *model.AnalysisResult) error {
	f, err := macho.Open(path)
	if err != nil {
		// Try opening as a fat/universal binary
		return parseMachOFat(ctx, path, result)
	}
	defer f.Close()

	return parseMachOFile(ctx, f, result)
}

// parseMachOFat handles fat/universal Mach-O binaries containing multiple architectures.
func parseMachOFat(ctx context.Context, path string, result *model.AnalysisResult) error {
	fat, err := macho.OpenFat(path)
	if err != nil {
		return fmt.Errorf("failed to open Mach-O file: %w", err)
	}
	defer fat.Close()

	if len(fat.Arches) == 0 {
		return fmt.Errorf("fat Mach-O contains no architectures")
	}

	// Record all architectures present in the fat binary
	var archNames []string
	for _, arch := range fat.Arches {
		archNames = append(archNames, machoArchName(arch.Cpu))
	}
	if len(archNames) > 1 {
		result.Metadata.Arch = fmt.Sprintf("universal (%s)", joinArchNames(archNames))
	}

	// Parse the first architecture for detailed analysis
	return parseMachOFile(ctx, fat.Arches[0].File, result)
}

func joinArchNames(names []string) string {
	result := names[0]
	for _, n := range names[1:] {
		result += ", " + n
	}
	return result
}

// parseMachOFile extracts metadata from a single-architecture Mach-O file.
func parseMachOFile(ctx context.Context, f *macho.File, result *model.AnalysisResult) error {
	// Check for context cancellation
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// Set architecture info (only if not already set by fat binary handler)
	if result.Metadata.Arch == "" {
		result.Metadata.Arch = machoArchName(f.Cpu)
	}
	result.Metadata.Bits = machoBits(f.Cpu)

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

func machoArchName(cpu macho.Cpu) string {
	switch cpu {
	case macho.Cpu386:
		return "x86"
	case macho.CpuAmd64:
		return "x86_64"
	case macho.CpuArm:
		return "ARM"
	case macho.CpuArm64:
		return "ARM64"
	case macho.CpuPpc:
		return "PPC"
	case macho.CpuPpc64:
		return "PPC64"
	default:
		return fmt.Sprintf("unknown (0x%x)", cpu)
	}
}

func machoBits(cpu macho.Cpu) int {
	switch cpu {
	case macho.Cpu386, macho.CpuArm, macho.CpuPpc:
		return 32
	case macho.CpuAmd64, macho.CpuArm64, macho.CpuPpc64:
		return 64
	default:
		return 0
	}
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
