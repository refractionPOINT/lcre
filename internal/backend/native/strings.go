package native

import (
	"bufio"
	"encoding/binary"
	"os"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/maxime/lcre/internal/model"
)

// ExtractStrings extracts ASCII and UTF-16 strings from a binary
func ExtractStrings(path string, minLength, maxStrings int) ([]model.ExtractedString, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var strings []model.ExtractedString

	// Extract ASCII strings
	asciiStrings, err := extractASCII(f, minLength)
	if err != nil {
		return nil, err
	}
	strings = append(strings, asciiStrings...)

	// Reset file position
	if _, err := f.Seek(0, 0); err != nil {
		return nil, err
	}

	// Extract UTF-16 LE strings
	utf16Strings, err := extractUTF16LE(f, minLength)
	if err != nil {
		return nil, err
	}
	strings = append(strings, utf16Strings...)

	// Sort by offset and limit
	sortStringsByOffset(strings)
	if maxStrings > 0 && len(strings) > maxStrings {
		strings = strings[:maxStrings]
	}

	return strings, nil
}

// extractASCII extracts printable ASCII strings
func extractASCII(f *os.File, minLength int) ([]model.ExtractedString, error) {
	var result []model.ExtractedString
	reader := bufio.NewReader(f)

	var current []byte
	var startOffset uint64
	var offset uint64

	for {
		b, err := reader.ReadByte()
		if err != nil {
			break
		}

		if isPrintableASCII(b) {
			if len(current) == 0 {
				startOffset = offset
			}
			current = append(current, b)
		} else {
			if len(current) >= minLength {
				result = append(result, model.ExtractedString{
					Value:    string(current),
					Offset:   startOffset,
					Encoding: "ascii",
				})
			}
			current = current[:0]
		}
		offset++
	}

	// Handle final string
	if len(current) >= minLength {
		result = append(result, model.ExtractedString{
			Value:    string(current),
			Offset:   startOffset,
			Encoding: "ascii",
		})
	}

	return result, nil
}

// extractUTF16LE extracts UTF-16 Little Endian strings
func extractUTF16LE(f *os.File, minLength int) ([]model.ExtractedString, error) {
	var result []model.ExtractedString

	stat, err := f.Stat()
	if err != nil {
		return nil, err
	}
	fileSize := stat.Size()

	var current []uint16
	var startOffset uint64
	var offset uint64

	buf := make([]byte, 2)
	for offset < uint64(fileSize)-1 {
		n, err := f.Read(buf)
		if err != nil || n < 2 {
			break
		}

		char := binary.LittleEndian.Uint16(buf)

		if isPrintableUTF16(char) {
			if len(current) == 0 {
				startOffset = offset
			}
			current = append(current, char)
		} else {
			if len(current) >= minLength {
				str := string(utf16.Decode(current))
				if utf8.ValidString(str) {
					result = append(result, model.ExtractedString{
						Value:    str,
						Offset:   startOffset,
						Encoding: "utf-16le",
					})
				}
			}
			current = current[:0]
		}
		offset += 2
	}

	// Handle final string
	if len(current) >= minLength {
		str := string(utf16.Decode(current))
		if utf8.ValidString(str) {
			result = append(result, model.ExtractedString{
				Value:    str,
				Offset:   startOffset,
				Encoding: "utf-16le",
			})
		}
	}

	return result, nil
}

// isPrintableASCII checks if a byte is printable ASCII
func isPrintableASCII(b byte) bool {
	return (b >= 0x20 && b <= 0x7E) || b == '\t' || b == '\n' || b == '\r'
}

// isPrintableUTF16 checks if a UTF-16 code point is printable
func isPrintableUTF16(c uint16) bool {
	return (c >= 0x20 && c <= 0x7E) || c == '\t' || c == '\n' || c == '\r'
}

// sortStringsByOffset sorts strings by their file offset
func sortStringsByOffset(strings []model.ExtractedString) {
	// Simple insertion sort (good enough for most cases)
	for i := 1; i < len(strings); i++ {
		j := i
		for j > 0 && strings[j-1].Offset > strings[j].Offset {
			strings[j-1], strings[j] = strings[j], strings[j-1]
			j--
		}
	}
}
