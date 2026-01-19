package cli

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
)

var queryBytesCmd = &cobra.Command{
	Use:   "bytes <binary> <offset> <length>",
	Short: "Hex dump bytes",
	Long:  "Get a hex dump of bytes at a specific offset.",
	Args:  cobra.ExactArgs(3),
	RunE:  runQueryBytes,
}

var querySearchBytesCmd = &cobra.Command{
	Use:   "search-bytes <binary> <pattern>",
	Short: "Search byte pattern",
	Long: `Search for a hex byte pattern in the binary.
Pattern format: hex string like "4D5A9000" or "4D 5A 90 00"`,
	Args: cobra.ExactArgs(2),
	RunE: runQuerySearchBytes,
}

func init() {
	queryCmd.AddCommand(queryBytesCmd)
	queryCmd.AddCommand(querySearchBytesCmd)
}

type BytesOutput struct {
	Offset  string `json:"offset"`
	Length  int    `json:"length"`
	Hex     string `json:"hex"`
	ASCII   string `json:"ascii"`
}

type ByteSearchOutput struct {
	Pattern  string        `json:"pattern"`
	Matches  []ByteMatch   `json:"matches"`
	Count    int           `json:"count"`
}

type ByteMatch struct {
	Offset string `json:"offset"`
}

func runQueryBytes(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	binaryPath := args[0]
	absPath, err := filepath.Abs(binaryPath)
	if err != nil {
		return err
	}

	offset := parseAddressArg(args[1])
	length := parseAddressArg(args[2])

	if offset < 0 {
		return fmt.Errorf("offset must be non-negative")
	}
	if length <= 0 || length > 4096 {
		return fmt.Errorf("length must be between 1 and 4096")
	}

	// Ensure binary is analyzed (for consistency)
	_, db, _, err := ensureAnalyzed(ctx, absPath, queryDeep)
	if err != nil {
		return err
	}
	db.Close()

	// Read bytes directly from file
	f, err := os.Open(absPath)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := f.Seek(offset, 0); err != nil {
		return err
	}

	buf := make([]byte, length)
	n, err := io.ReadFull(f, buf)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return err
	}
	buf = buf[:n]

	output := BytesOutput{
		Offset: formatAddress(offset),
		Length: n,
		Hex:    hex.EncodeToString(buf),
		ASCII:  bytesToASCII(buf),
	}

	if outputFormat == "json" {
		outputJSON(output)
	} else {
		printHexDump(offset, buf)
	}

	return nil
}

func runQuerySearchBytes(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	binaryPath := args[0]
	absPath, err := filepath.Abs(binaryPath)
	if err != nil {
		return err
	}

	// Parse pattern (remove spaces, validate hex)
	patternStr := strings.ReplaceAll(args[1], " ", "")
	patternStr = strings.ReplaceAll(patternStr, "-", "")
	if !regexp.MustCompile(`^[0-9a-fA-F]+$`).MatchString(patternStr) {
		return fmt.Errorf("invalid hex pattern: %s", args[1])
	}
	if len(patternStr)%2 != 0 {
		return fmt.Errorf("hex pattern must have even number of characters")
	}

	pattern, err := hex.DecodeString(patternStr)
	if err != nil {
		return err
	}

	// Ensure binary is analyzed (for consistency)
	_, db, _, err := ensureAnalyzed(ctx, absPath, queryDeep)
	if err != nil {
		return err
	}
	db.Close()

	// Check file size before reading (limit to 100MB for search)
	const maxSearchSize = 100 * 1024 * 1024 // 100MB
	fileInfo, err := os.Stat(absPath)
	if err != nil {
		return err
	}
	if fileInfo.Size() > maxSearchSize {
		return fmt.Errorf("file too large for byte search (max %d bytes, got %d)", maxSearchSize, fileInfo.Size())
	}

	// Read entire file and search
	data, err := os.ReadFile(absPath)
	if err != nil {
		return err
	}

	var matches []ByteMatch
	for i := 0; i <= len(data)-len(pattern); i++ {
		if matchBytes(data[i:], pattern) {
			matches = append(matches, ByteMatch{
				Offset: formatAddress(int64(i)),
			})
			// Limit results
			if len(matches) >= 100 {
				break
			}
		}
	}

	output := ByteSearchOutput{
		Pattern: hex.EncodeToString(pattern),
		Matches: matches,
		Count:   len(matches),
	}

	if outputFormat == "json" {
		outputJSON(output)
	} else {
		fmt.Printf("# Byte Search: %s\n\n", output.Pattern)
		if output.Count == 0 {
			fmt.Println("No matches found.")
		} else {
			fmt.Printf("Found %d matches:\n", output.Count)
			for _, m := range matches {
				fmt.Printf("- %s\n", m.Offset)
			}
		}
	}

	return nil
}

func matchBytes(data, pattern []byte) bool {
	if len(data) < len(pattern) {
		return false
	}
	for i, b := range pattern {
		if data[i] != b {
			return false
		}
	}
	return true
}

func bytesToASCII(data []byte) string {
	var sb strings.Builder
	for _, b := range data {
		if b >= 32 && b < 127 {
			sb.WriteByte(b)
		} else {
			sb.WriteByte('.')
		}
	}
	return sb.String()
}

func printHexDump(offset int64, data []byte) {
	for i := 0; i < len(data); i += 16 {
		// Address
		fmt.Printf("%08x  ", offset+int64(i))

		// Hex bytes
		for j := 0; j < 16; j++ {
			if i+j < len(data) {
				fmt.Printf("%02x ", data[i+j])
			} else {
				fmt.Print("   ")
			}
			if j == 7 {
				fmt.Print(" ")
			}
		}

		// ASCII
		fmt.Print(" |")
		for j := 0; j < 16 && i+j < len(data); j++ {
			b := data[i+j]
			if b >= 32 && b < 127 {
				fmt.Printf("%c", b)
			} else {
				fmt.Print(".")
			}
		}
		fmt.Println("|")
	}
}
