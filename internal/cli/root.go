package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	// Register backends
	_ "github.com/refractionPOINT/lcre/internal/backend/ghidra"
)

// Exit codes
const (
	ExitSuccess = 0
	ExitError   = 1
	ExitPartial = 2
)

// Global flags
var (
	outputFormat string
	verbose      bool
	timeout      time.Duration
)

// rootCmd is the base command
var rootCmd = &cobra.Command{
	Use:   "lcre",
	Short: "LCRE - Binary Forensics CLI Tool",
	Long: `LCRE (LimaCharlie Reverse Engineering) is a CLI tool for static binary
analysis and forensics automation.

It provides fast triage via native Go parsing and deep analysis via Ghidra
headless integration.`,
	SilenceUsage: true,
}

// Execute runs the CLI
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(ExitError)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "json", "Output format (json, md)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	rootCmd.PersistentFlags().DurationVarP(&timeout, "timeout", "t", 120*time.Second, "Analysis timeout")
}

// validateBinaryPath checks if the binary exists and is readable
func validateBinaryPath(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("file not found: %s", path)
		}
		return fmt.Errorf("cannot access file: %w", err)
	}
	if info.IsDir() {
		return fmt.Errorf("path is a directory: %s", path)
	}
	return nil
}
