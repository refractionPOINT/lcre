package util

import (
	"os"

	"github.com/maxime/lcre/internal/model"
)

// Magic bytes for different binary formats
var (
	peMagic    = []byte{0x4D, 0x5A}             // MZ
	elfMagic   = []byte{0x7F, 0x45, 0x4C, 0x46} // \x7FELF
	machoMagic32 = []byte{0xFE, 0xED, 0xFA, 0xCE} // 32-bit
	machoMagic64 = []byte{0xFE, 0xED, 0xFA, 0xCF} // 64-bit
	machoMagic32Rev = []byte{0xCE, 0xFA, 0xED, 0xFE} // 32-bit reversed
	machoMagic64Rev = []byte{0xCF, 0xFA, 0xED, 0xFE} // 64-bit reversed
	machoUniversal = []byte{0xCA, 0xFE, 0xBA, 0xBE} // Universal binary
)

// DetectFormat detects the binary format from the file header
func DetectFormat(path string) (model.BinaryFormat, error) {
	f, err := os.Open(path)
	if err != nil {
		return model.FormatUnknown, err
	}
	defer f.Close()

	header := make([]byte, 4)
	n, err := f.Read(header)
	if err != nil || n < 2 {
		return model.FormatUnknown, err
	}

	return DetectFormatFromBytes(header), nil
}

// DetectFormatFromBytes detects the binary format from header bytes
func DetectFormatFromBytes(header []byte) model.BinaryFormat {
	if len(header) < 2 {
		return model.FormatUnknown
	}

	// Check PE (MZ header)
	if header[0] == peMagic[0] && header[1] == peMagic[1] {
		return model.FormatPE
	}

	if len(header) < 4 {
		return model.FormatUnknown
	}

	// Check ELF
	if header[0] == elfMagic[0] && header[1] == elfMagic[1] &&
		header[2] == elfMagic[2] && header[3] == elfMagic[3] {
		return model.FormatELF
	}

	// Check Mach-O
	if matchMagic(header, machoMagic32) || matchMagic(header, machoMagic64) ||
		matchMagic(header, machoMagic32Rev) || matchMagic(header, machoMagic64Rev) ||
		matchMagic(header, machoUniversal) {
		return model.FormatMachO
	}

	return model.FormatUnknown
}

func matchMagic(header, magic []byte) bool {
	if len(header) < len(magic) {
		return false
	}
	for i := range magic {
		if header[i] != magic[i] {
			return false
		}
	}
	return true
}

// FileSize returns the size of a file
func FileSize(path string) (int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

// FileExists checks if a file exists
func FileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
