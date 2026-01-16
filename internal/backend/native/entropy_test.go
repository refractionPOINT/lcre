package native

import (
	"math"
	"testing"
)

func TestCalculateEntropy(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		minExpected float64
		maxExpected float64
	}{
		{
			name:        "Empty data",
			data:        []byte{},
			minExpected: 0,
			maxExpected: 0,
		},
		{
			name:        "Single byte repeated",
			data:        []byte{0x00, 0x00, 0x00, 0x00},
			minExpected: 0,
			maxExpected: 0,
		},
		{
			name:        "Two different bytes",
			data:        []byte{0x00, 0xFF, 0x00, 0xFF},
			minExpected: 0.9, // Should be close to 1.0
			maxExpected: 1.1,
		},
		{
			name:        "All different bytes",
			data:        func() []byte { b := make([]byte, 256); for i := range b { b[i] = byte(i) }; return b }(),
			minExpected: 7.9, // Maximum entropy for 8-bit data
			maxExpected: 8.1,
		},
		{
			name:        "ASCII text",
			data:        []byte("The quick brown fox jumps over the lazy dog"),
			minExpected: 3.5, // Typical text entropy
			maxExpected: 5.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entropy := CalculateEntropy(tt.data)
			if entropy < tt.minExpected || entropy > tt.maxExpected {
				t.Errorf("entropy %.2f not in expected range [%.2f, %.2f]",
					entropy, tt.minExpected, tt.maxExpected)
			}
		})
	}
}

func TestIsHighEntropy(t *testing.T) {
	tests := []struct {
		entropy  float64
		expected bool
	}{
		{6.0, false},
		{6.9, false},
		{7.0, false}, // Exactly at threshold
		{7.1, true},
		{8.0, true},
	}

	for _, tt := range tests {
		result := IsHighEntropy(tt.entropy)
		if result != tt.expected {
			t.Errorf("IsHighEntropy(%.1f): expected %v, got %v", tt.entropy, tt.expected, result)
		}
	}
}

func TestIsPossiblyPacked(t *testing.T) {
	tests := []struct {
		entropy  float64
		expected bool
	}{
		{5.0, false},
		{6.4, false},
		{6.5, false}, // At threshold
		{6.6, true},
		{7.5, true},
	}

	for _, tt := range tests {
		result := IsPossiblyPacked(tt.entropy)
		if result != tt.expected {
			t.Errorf("IsPossiblyPacked(%.1f): expected %v, got %v", tt.entropy, tt.expected, result)
		}
	}
}

func TestEntropyConsistency(t *testing.T) {
	// Same data should always produce same entropy
	data := []byte("This is a test string for entropy calculation")

	entropy1 := CalculateEntropy(data)
	entropy2 := CalculateEntropy(data)

	if math.Abs(entropy1-entropy2) > 0.0001 {
		t.Errorf("Entropy not consistent: %f vs %f", entropy1, entropy2)
	}
}
