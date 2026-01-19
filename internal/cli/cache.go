package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/refractionPOINT/lcre/internal/cache"
	"github.com/spf13/cobra"
)

var cacheCmd = &cobra.Command{
	Use:   "cache",
	Short: "Manage analysis cache",
	Long:  "List, clear, and manage cached binary analyses.",
}

var cacheListCmd = &cobra.Command{
	Use:   "list",
	Short: "List cached analyses",
	Long:  "List all cached binary analyses with their metadata.",
	RunE:  runCacheList,
}

var cacheClearCmd = &cobra.Command{
	Use:   "clear [binary_or_hash]",
	Short: "Clear cached analyses",
	Long: `Clear cached analyses. Without arguments, clears all caches.
With a binary path or SHA256 hash, clears only that specific cache.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runCacheClear,
}

var cacheInfoCmd = &cobra.Command{
	Use:   "info <binary>",
	Short: "Show cache info for a binary",
	Long:  "Show detailed cache information for a specific binary.",
	Args:  cobra.ExactArgs(1),
	RunE:  runCacheInfo,
}

func init() {
	cacheCmd.AddCommand(cacheListCmd)
	cacheCmd.AddCommand(cacheClearCmd)
	cacheCmd.AddCommand(cacheInfoCmd)
	rootCmd.AddCommand(cacheCmd)
}

func runCacheList(cmd *cobra.Command, args []string) error {
	mgr, err := cache.NewManager()
	if err != nil {
		return err
	}

	entries, err := mgr.List()
	if err != nil {
		return err
	}

	if outputFormat == "json" {
		output := struct {
			Entries []cache.ListCacheEntry `json:"entries"`
			Count   int                    `json:"count"`
		}{
			Entries: entries,
			Count:   len(entries),
		}
		data, _ := json.MarshalIndent(output, "", "  ")
		fmt.Println(string(data))
	} else {
		if len(entries) == 0 {
			fmt.Println("No cached analyses found.")
			return nil
		}

		fmt.Printf("Cached Analyses (%d):\n\n", len(entries))
		for _, e := range entries {
			fmt.Printf("SHA256: %s\n", e.SHA256)
			if e.Path != "" {
				fmt.Printf("  Path: %s\n", e.Path)
			}
			if !e.CreatedAt.IsZero() {
				fmt.Printf("  Created: %s\n", e.CreatedAt.Format("2006-01-02 15:04:05"))
			}
			fmt.Printf("  Size: %s\n", formatBytes(e.Size))
			fmt.Printf("  Deep Analysis: %v\n", e.DeepAnalysis)
			fmt.Println()
		}
	}

	return nil
}

func runCacheClear(cmd *cobra.Command, args []string) error {
	mgr, err := cache.NewManager()
	if err != nil {
		return err
	}

	if len(args) == 0 {
		// Clear all
		if err := mgr.ClearAll(); err != nil {
			return err
		}
		if outputFormat == "json" {
			fmt.Println(`{"status": "cleared", "message": "All caches cleared"}`)
		} else {
			fmt.Println("All caches cleared.")
		}
		return nil
	}

	target := args[0]

	// Check if it's a file path
	if _, err := os.Stat(target); err == nil {
		// It's a file, clear by path
		if err := mgr.Clear(target); err != nil {
			return err
		}
		if outputFormat == "json" {
			fmt.Printf(`{"status": "cleared", "path": %q}`+"\n", target)
		} else {
			fmt.Printf("Cache cleared for: %s\n", target)
		}
		return nil
	}

	// Try as SHA256 hash
	if len(target) == 64 {
		if err := mgr.ClearBySHA256(target); err != nil {
			return err
		}
		if outputFormat == "json" {
			fmt.Printf(`{"status": "cleared", "sha256": %q}`+"\n", target)
		} else {
			fmt.Printf("Cache cleared for SHA256: %s\n", target)
		}
		return nil
	}

	return fmt.Errorf("invalid target: %s (must be a file path or SHA256 hash)", target)
}

func runCacheInfo(cmd *cobra.Command, args []string) error {
	binaryPath := args[0]

	// Resolve to absolute path
	absPath, err := filepath.Abs(binaryPath)
	if err != nil {
		return err
	}

	mgr, err := cache.NewManager()
	if err != nil {
		return err
	}

	exists, err := mgr.Exists(absPath)
	if err != nil {
		return err
	}

	if !exists {
		if outputFormat == "json" {
			fmt.Printf(`{"cached": false, "path": %q}`+"\n", absPath)
		} else {
			fmt.Printf("No cache found for: %s\n", absPath)
		}
		return nil
	}

	meta, err := mgr.LoadMetadata(absPath)
	if err != nil {
		return fmt.Errorf("load metadata: %w", err)
	}

	if outputFormat == "json" {
		data, _ := json.MarshalIndent(meta, "", "  ")
		fmt.Println(string(data))
	} else {
		fmt.Printf("Cache Info for: %s\n\n", absPath)
		fmt.Printf("SHA256: %s\n", meta.Entry.SHA256)
		fmt.Printf("Created: %s\n", meta.Entry.CreatedAt.Format("2006-01-02 15:04:05"))
		fmt.Printf("Backend: %s\n", meta.Backend)
		fmt.Printf("Deep Analysis: %v\n", meta.DeepAnalysis)
		fmt.Printf("Analysis Time: %.2fs\n", meta.AnalysisTime)
		fmt.Printf("\nCounts:\n")
		fmt.Printf("  Strings: %d\n", meta.StringCount)
		fmt.Printf("  Functions: %d\n", meta.FunctionCount)
		fmt.Printf("  Imports: %d\n", meta.ImportCount)
		fmt.Printf("  Exports: %d\n", meta.ExportCount)
		fmt.Printf("  YARA Matches: %d\n", meta.YARAMatchCount)
	}

	return nil
}

func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
