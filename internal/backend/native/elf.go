package native

import (
	"context"
	"debug/elf"
	"fmt"

	"github.com/refractionPOINT/lcre/internal/model"
)

// parseELF parses an ELF binary and populates the result
func parseELF(ctx context.Context, path string, result *model.AnalysisResult) error {
	f, err := elf.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open ELF file: %w", err)
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
	case elf.EM_386:
		result.Metadata.Arch = "x86"
		result.Metadata.Bits = 32
	case elf.EM_X86_64:
		result.Metadata.Arch = "x86_64"
		result.Metadata.Bits = 64
	case elf.EM_ARM:
		result.Metadata.Arch = "ARM"
		result.Metadata.Bits = 32
	case elf.EM_AARCH64:
		result.Metadata.Arch = "ARM64"
		result.Metadata.Bits = 64
	case elf.EM_MIPS:
		result.Metadata.Arch = "MIPS"
		result.Metadata.Bits = 32
	case elf.EM_PPC:
		result.Metadata.Arch = "PPC"
		result.Metadata.Bits = 32
	case elf.EM_PPC64:
		result.Metadata.Arch = "PPC64"
		result.Metadata.Bits = 64
	case elf.EM_RISCV:
		result.Metadata.Arch = "RISC-V"
		if f.Class == elf.ELFCLASS64 {
			result.Metadata.Bits = 64
		} else {
			result.Metadata.Bits = 32
		}
	default:
		result.Metadata.Arch = fmt.Sprintf("unknown (0x%x)", f.Machine)
	}

	// Set endianness
	switch f.Data {
	case elf.ELFDATA2LSB:
		result.Metadata.Endian = "little"
	case elf.ELFDATA2MSB:
		result.Metadata.Endian = "big"
	default:
		result.Metadata.Endian = "unknown"
	}

	// Parse sections
	for _, sec := range f.Sections {
		if sec == nil {
			continue
		}
		section := model.Section{
			Name:        sec.Name,
			VirtualAddr: sec.Addr,
			VirtualSize: sec.Size,
			RawSize:     sec.FileSize,
			Permissions: elfPermissions(sec.Flags),
		}
		result.Sections = append(result.Sections, section)
	}

	// Parse imports (dynamic symbols)
	symbols, err := f.ImportedSymbols()
	if err == nil {
		for _, sym := range symbols {
			result.Imports = append(result.Imports, model.Import{
				Library:  sym.Library,
				Function: sym.Name,
			})
		}
	}

	// Parse dynamic libraries
	libs, err := f.ImportedLibraries()
	if err == nil {
		for _, lib := range libs {
			// Check if we already have imports from this library
			found := false
			for _, imp := range result.Imports {
				if imp.Library == lib {
					found = true
					break
				}
			}
			if !found {
				result.Imports = append(result.Imports, model.Import{
					Library:  lib,
					Function: "*",
				})
			}
		}
	}

	// Parse exported symbols
	dynsyms, err := f.DynamicSymbols()
	if err == nil {
		for _, sym := range dynsyms {
			// Only include defined symbols (exports)
			if sym.Section != elf.SHN_UNDEF && sym.Value != 0 {
				result.Exports = append(result.Exports, model.Export{
					Name:    sym.Name,
					Address: sym.Value,
				})
			}
		}
	}

	// Entry point
	result.EntryPoints = append(result.EntryPoints, model.EntryPoint{
		Name:    "_start",
		Address: f.Entry,
		Type:    "entry",
	})

	return nil
}

// elfPermissions converts ELF section flags to permission string
func elfPermissions(flags elf.SectionFlag) string {
	perms := ""
	// ELF sections don't have direct permission flags like segments
	// We infer from section type and flags
	if flags&elf.SHF_ALLOC != 0 {
		perms += "r"
	} else {
		perms += "-"
	}
	if flags&elf.SHF_WRITE != 0 {
		perms += "w"
	} else {
		perms += "-"
	}
	if flags&elf.SHF_EXECINSTR != 0 {
		perms += "x"
	} else {
		perms += "-"
	}
	return perms
}
