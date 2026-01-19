package native

import (
	"math"
	"os"

	"github.com/refractionPOINT/lcre/internal/model"
)

// calculateSectionEntropy calculates entropy for a section
func calculateSectionEntropy(path string, section *model.Section) error {
	if section.RawSize == 0 {
		section.Entropy = 0
		return nil
	}

	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	// Read section data
	// Note: For real implementation, we'd need to map VirtualAddr to file offset
	// For now, we read from the beginning of the file and use RawSize as an approximation
	// This is a simplification - proper implementation would need PE/ELF/Mach-O parsing
	// to find the actual file offset of the section

	// For simplicity, calculate entropy of the whole file in chunks
	// A more accurate implementation would calculate per-section entropy

	stat, err := f.Stat()
	if err != nil {
		return err
	}

	// Read entire file for entropy calculation
	data := make([]byte, stat.Size())
	_, err = f.Read(data)
	if err != nil {
		return err
	}

	section.Entropy = CalculateEntropy(data)
	return nil
}

// CalculateEntropy computes Shannon entropy of data
func CalculateEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	// Count byte frequencies
	freq := make([]int, 256)
	for _, b := range data {
		freq[b]++
	}

	// Calculate entropy
	var entropy float64
	dataLen := float64(len(data))

	for _, count := range freq {
		if count > 0 {
			probability := float64(count) / dataLen
			entropy -= probability * math.Log2(probability)
		}
	}

	return entropy
}

// CalculateEntropyFromFile calculates entropy of an entire file
func CalculateEntropyFromFile(path string) (float64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return CalculateEntropy(data), nil
}

// IsHighEntropy checks if entropy indicates packed/encrypted content
func IsHighEntropy(entropy float64) bool {
	// Typical thresholds:
	// < 6.0: Normal executable code
	// 6.0-7.0: Possibly compressed/packed
	// > 7.0: Likely encrypted or highly compressed
	return entropy > 7.0
}

// IsPossiblyPacked checks if entropy suggests packing
func IsPossiblyPacked(entropy float64) bool {
	return entropy > 6.5
}
