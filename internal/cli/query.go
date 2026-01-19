package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/refractionPOINT/lcre/internal/backend"
	"github.com/refractionPOINT/lcre/internal/cache"
	"github.com/refractionPOINT/lcre/internal/ioc"
	"github.com/refractionPOINT/lcre/internal/model"
	"github.com/refractionPOINT/lcre/internal/yara"
	"github.com/spf13/cobra"
)

var queryCmd = &cobra.Command{
	Use:   "query <binary> <subcommand>",
	Short: "Query binary analysis data",
	Long: `Query cached binary analysis data interactively.
First query on a binary triggers analysis and caching.
Subsequent queries are instant.

Commands that require Ghidra (functions, decompile, callers, callees,
call-path, xrefs) will automatically trigger deep analysis on first use.`,
}

func init() {
	rootCmd.AddCommand(queryCmd)
}

// ensureAnalyzed ensures the binary is analyzed and cached.
// Returns the cache manager, database, and whether a new analysis was performed.
func ensureAnalyzed(ctx context.Context, binaryPath string, forceDeep bool) (*cache.Manager, *cache.DB, bool, error) {
	absPath, err := filepath.Abs(binaryPath)
	if err != nil {
		return nil, nil, false, fmt.Errorf("resolve path: %w", err)
	}

	// Check if file exists
	if _, err := os.Stat(absPath); err != nil {
		return nil, nil, false, fmt.Errorf("file not found: %s", absPath)
	}

	mgr, err := cache.NewManager()
	if err != nil {
		return nil, nil, false, err
	}

	// Check if already cached
	exists, err := mgr.Exists(absPath)
	if err != nil {
		return nil, nil, false, err
	}

	needsAnalysis := !exists
	needsDeepAnalysis := false

	if exists && forceDeep {
		hasDeep, _ := mgr.HasDeepAnalysis(absPath)
		needsDeepAnalysis = !hasDeep
	}

	if needsAnalysis || needsDeepAnalysis {
		// Perform analysis
		if err := runAnalysis(ctx, mgr, absPath, forceDeep || needsDeepAnalysis); err != nil {
			return nil, nil, false, err
		}
	}

	db, err := mgr.Open(absPath)
	if err != nil {
		return nil, nil, false, err
	}

	return mgr, db, needsAnalysis || needsDeepAnalysis, nil
}

// runAnalysis performs the actual analysis and stores results in cache.
// If isUpdate is true, only the deep analysis data (functions, call graph) is added to existing cache.
func runAnalysis(ctx context.Context, mgr *cache.Manager, binaryPath string, deep bool) error {
	start := time.Now()

	// Check if this is an update to existing cache
	exists, _ := mgr.Exists(binaryPath)
	isUpdate := exists && deep

	// Get appropriate backend
	var b backend.Backend
	var err error
	if deep {
		b, err = backend.DefaultRegistry.Get("ghidra")
		if err != nil {
			return fmt.Errorf("ghidra backend not available for deep analysis: %w", err)
		}
		if avail, reason := b.Available(); !avail {
			return fmt.Errorf("ghidra backend not available: %s", reason)
		}
		// Set decompiled directory for caching decompiled functions
		cacheDir, _ := mgr.GetCacheDir(binaryPath)
		if gb, ok := b.(interface{ SetDecompiledDir(string) }); ok && cacheDir != "" {
			decompiledDir := filepath.Join(cacheDir, "decompiled")
			if err := os.MkdirAll(decompiledDir, 0755); err != nil {
				return fmt.Errorf("failed to create decompiled directory: %w", err)
			}
			gb.SetDecompiledDir(decompiledDir)
		}
	} else {
		b, err = backend.DefaultRegistry.Default()
		if err != nil {
			return fmt.Errorf("no backend available: %w", err)
		}
	}

	// Set up options
	opts := backend.DefaultOptions()
	opts.Timeout = timeout
	opts.IncludeStrings = true
	opts.DeepAnalysis = deep

	if verbose {
		fmt.Fprintf(os.Stderr, "Analyzing %s with %s backend...\n", filepath.Base(binaryPath), b.Name())
	}

	// Run analysis
	result, err := b.Analyze(ctx, binaryPath, opts)
	if err != nil {
		return fmt.Errorf("analysis failed: %w", err)
	}

	// For updates (adding deep analysis to existing cache), use UpdateWithDeepAnalysis
	if isUpdate {
		if err := cache.UpdateWithDeepAnalysis(mgr, binaryPath, result); err != nil {
			return fmt.Errorf("cache update failed: %w", err)
		}
		if verbose {
			fmt.Fprintf(os.Stderr, "Deep analysis complete in %.2fs (cached)\n", time.Since(start).Seconds())
		}
		return nil
	}

	// Run YARA scan
	scanner := yara.NewScanner()
	yaraResult, scanErr := scanner.Scan(ctx, binaryPath)
	if scanErr != nil {
		result.AddError(fmt.Sprintf("YARA scan failed: %v", scanErr))
	} else {
		result.YARA = yaraResult
	}

	// Extract IOCs
	extractor := ioc.NewExtractor()
	var iocResult *model.IOCResult
	if len(result.Strings) > 0 {
		iocResult = extractor.ExtractFromStrings(result.Strings)
	}

	// Store in cache
	if err := cache.StoreAnalysisResult(mgr, binaryPath, result, iocResult); err != nil {
		return fmt.Errorf("cache storage failed: %w", err)
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "Analysis complete in %.2fs (cached)\n", time.Since(start).Seconds())
	}

	return nil
}

// outputJSON outputs data as JSON.
func outputJSON(v interface{}) {
	data, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(data))
}

// formatAddress formats an address as hex string.
func formatAddress(addr int64) string {
	return fmt.Sprintf("0x%x", addr)
}

// parseAddress parses a hex or decimal address string.
func parseAddressArg(s string) int64 {
	var addr int64
	if len(s) > 2 && (s[:2] == "0x" || s[:2] == "0X") {
		// Use %x format which handles both 0x and 0X prefixes
		fmt.Sscanf(s[2:], "%x", &addr)
	} else {
		fmt.Sscanf(s, "%d", &addr)
	}
	return addr
}
