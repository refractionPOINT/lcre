package cache

import (
	"time"

	"github.com/maxime/lcre/internal/model"
)

// StoreAnalysisResult stores a complete analysis result in the cache.
func StoreAnalysisResult(mgr *Manager, binaryPath string, result *model.AnalysisResult, iocs *model.IOCResult) error {
	db, cacheDir, created, err := mgr.OpenOrCreate(binaryPath)
	if err != nil {
		return err
	}
	defer db.Close()

	// If cache already exists and has content, skip storing
	if !created {
		count := 0
		db.db.QueryRow("SELECT COUNT(*) FROM sections").Scan(&count)
		if count > 0 {
			return nil
		}
	}

	// Store sections
	if len(result.Sections) > 0 {
		if err := db.InsertSections(result.Sections); err != nil {
			return err
		}
	}

	// Store imports
	if len(result.Imports) > 0 {
		if err := db.InsertImports(result.Imports); err != nil {
			return err
		}
	}

	// Store exports
	if len(result.Exports) > 0 {
		if err := db.InsertExports(result.Exports); err != nil {
			return err
		}
	}

	// Store strings
	if len(result.Strings) > 0 {
		if err := db.InsertStrings(result.Strings); err != nil {
			return err
		}
	}

	// Store functions
	if len(result.Functions) > 0 {
		if err := db.InsertFunctions(result.Functions); err != nil {
			return err
		}
	}

	// Store call graph edges
	if result.CallGraph != nil && len(result.CallGraph.Edges) > 0 {
		if err := db.InsertCalls(result.CallGraph.Edges); err != nil {
			return err
		}
	}

	// Store entry points
	if len(result.EntryPoints) > 0 {
		if err := db.InsertEntryPoints(result.EntryPoints); err != nil {
			return err
		}
	}

	// Store heuristics
	if result.Heuristics != nil && len(result.Heuristics.Matches) > 0 {
		if err := db.InsertHeuristics(result.Heuristics.Matches); err != nil {
			return err
		}
	}

	// Store IOCs
	if iocs != nil {
		allIOCs := collectAllIOCs(iocs)
		if len(allIOCs) > 0 {
			if err := db.InsertIOCs(allIOCs); err != nil {
				return err
			}
		}
	}

	// Store binary metadata as JSON
	if err := db.StoreMetadataJSON("binary_metadata", result.Metadata); err != nil {
		return err
	}

	// Store heuristics result as JSON (includes score and risk level)
	if result.Heuristics != nil {
		if err := db.StoreMetadataJSON("heuristics_result", result.Heuristics); err != nil {
			return err
		}
	}

	// Get hash for cache entry
	hash, err := mgr.GetHash(binaryPath)
	if err != nil {
		return err
	}

	// Determine counts
	functionCount := len(result.Functions)
	stringCount := len(result.Strings)
	importCount := len(result.Imports)
	exportCount := len(result.Exports)
	heuristicCount := 0
	riskLevel := "info"
	totalScore := 0

	if result.Heuristics != nil {
		heuristicCount = len(result.Heuristics.Matches)
		riskLevel = string(result.Heuristics.RiskLevel)
		totalScore = result.Heuristics.TotalScore
	}

	// Determine if this was a deep analysis (has functions/callgraph)
	deepAnalysis := len(result.Functions) > 0 || (result.CallGraph != nil && len(result.CallGraph.Edges) > 0)

	// Save quick-access metadata
	meta := &CachedMetadata{
		Entry: CacheEntry{
			Path:         binaryPath,
			SHA256:       hash,
			CacheDir:     cacheDir,
			CreatedAt:    time.Now(),
			DeepAnalysis: deepAnalysis,
		},
		Binary:         result.Metadata,
		Backend:        result.Backend,
		AnalysisTime:   result.Duration,
		DeepAnalysis:   deepAnalysis,
		StringCount:    stringCount,
		FunctionCount:  functionCount,
		ImportCount:    importCount,
		ExportCount:    exportCount,
		HeuristicCount: heuristicCount,
		RiskLevel:      riskLevel,
		TotalScore:     totalScore,
	}

	return mgr.SaveMetadata(binaryPath, meta)
}

// collectAllIOCs collects all IOCs from an IOCResult into a flat slice.
func collectAllIOCs(iocs *model.IOCResult) []model.IOC {
	var all []model.IOC

	for _, ioc := range iocs.URLs {
		all = append(all, model.IOC{
			Type:    model.IOCURL,
			Value:   ioc.Value,
			Offset:  ioc.Offset,
			Section: ioc.Section,
			Context: ioc.Context,
		})
	}

	for _, ioc := range iocs.Domains {
		all = append(all, model.IOC{
			Type:    model.IOCDomain,
			Value:   ioc.Value,
			Offset:  ioc.Offset,
			Section: ioc.Section,
			Context: ioc.Context,
		})
	}

	for _, ioc := range iocs.IPs {
		all = append(all, model.IOC{
			Type:    model.IOCIP,
			Value:   ioc.Value,
			Offset:  ioc.Offset,
			Section: ioc.Section,
			Context: ioc.Context,
		})
	}

	for _, ioc := range iocs.Emails {
		all = append(all, model.IOC{
			Type:    model.IOCEmail,
			Value:   ioc.Value,
			Offset:  ioc.Offset,
			Section: ioc.Section,
			Context: ioc.Context,
		})
	}

	for _, ioc := range iocs.Paths {
		all = append(all, model.IOC{
			Type:    model.IOCPath,
			Value:   ioc.Value,
			Offset:  ioc.Offset,
			Section: ioc.Section,
			Context: ioc.Context,
		})
	}

	for _, ioc := range iocs.Registry {
		all = append(all, model.IOC{
			Type:    model.IOCRegistry,
			Value:   ioc.Value,
			Offset:  ioc.Offset,
			Section: ioc.Section,
			Context: ioc.Context,
		})
	}

	for _, ioc := range iocs.Hashes {
		all = append(all, model.IOC{
			Type:    model.IOCHash,
			Value:   ioc.Value,
			Offset:  ioc.Offset,
			Section: ioc.Section,
			Context: ioc.Context,
		})
	}

	return all
}

// UpdateWithDeepAnalysis updates an existing cache with deep analysis results.
func UpdateWithDeepAnalysis(mgr *Manager, binaryPath string, result *model.AnalysisResult) error {
	db, err := mgr.Open(binaryPath)
	if err != nil {
		return err
	}
	defer db.Close()

	// Store functions
	if len(result.Functions) > 0 {
		if err := db.InsertFunctions(result.Functions); err != nil {
			return err
		}
	}

	// Store call graph edges
	if result.CallGraph != nil && len(result.CallGraph.Edges) > 0 {
		if err := db.InsertCalls(result.CallGraph.Edges); err != nil {
			return err
		}
	}

	// Update metadata to reflect deep analysis
	meta, err := mgr.LoadMetadata(binaryPath)
	if err != nil {
		return err
	}

	meta.DeepAnalysis = true
	meta.Entry.DeepAnalysis = true
	meta.FunctionCount = len(result.Functions)

	return mgr.SaveMetadata(binaryPath, meta)
}

// StoreXrefs stores cross-references in the cache.
func StoreXrefs(mgr *Manager, binaryPath string, xrefs []Xref) error {
	db, err := mgr.Open(binaryPath)
	if err != nil {
		return err
	}
	defer db.Close()

	return db.InsertXrefs(xrefs)
}
