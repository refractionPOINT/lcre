package cache

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/refractionPOINT/lcre/internal/model"
)

func TestEnrichmentCRUD(t *testing.T) {
	dir, err := os.MkdirTemp("", "cache-enrichment-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	db, err := OpenDB(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer db.Close()

	// Insert enrichment
	now := time.Now().Truncate(time.Second)
	err = db.InsertEnrichment(model.Enrichment{
		Tool:      "capa",
		Timestamp: now,
		RawOutput: `{"rules": {}}`,
	})
	if err != nil {
		t.Fatalf("failed to insert enrichment: %v", err)
	}

	// Query all enrichments
	enrichments, err := db.QueryEnrichments("")
	if err != nil {
		t.Fatalf("failed to query enrichments: %v", err)
	}
	if len(enrichments) != 1 {
		t.Fatalf("expected 1 enrichment, got %d", len(enrichments))
	}
	if enrichments[0].Tool != "capa" {
		t.Errorf("expected tool 'capa', got '%s'", enrichments[0].Tool)
	}

	// Query by tool name
	enrichments, err = db.QueryEnrichments("capa")
	if err != nil {
		t.Fatalf("failed to query by tool: %v", err)
	}
	if len(enrichments) != 1 {
		t.Fatalf("expected 1 enrichment for capa, got %d", len(enrichments))
	}

	// Query non-existent tool
	enrichments, err = db.QueryEnrichments("nonexistent")
	if err != nil {
		t.Fatalf("failed to query non-existent: %v", err)
	}
	if len(enrichments) != 0 {
		t.Errorf("expected 0 enrichments for nonexistent tool, got %d", len(enrichments))
	}
}

func TestCapabilitiesCRUD(t *testing.T) {
	dir, err := os.MkdirTemp("", "cache-capabilities-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	db, err := OpenDB(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer db.Close()

	caps := []model.Capability{
		{
			Name:      "create process",
			Namespace: "host-interaction/process/create",
			AttackIDs: []string{"T1106"},
			MBCIDs:    []string{"C0017"},
		},
		{
			Name:      "encrypt data using AES",
			Namespace: "data-manipulation/encryption/aes",
			AttackIDs: []string{"T1486"},
		},
	}

	err = db.InsertCapabilities(caps)
	if err != nil {
		t.Fatalf("failed to insert capabilities: %v", err)
	}

	// Query all
	results, err := db.QueryCapabilities("", "")
	if err != nil {
		t.Fatalf("failed to query all capabilities: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 capabilities, got %d", len(results))
	}

	// Query by namespace prefix
	results, err = db.QueryCapabilities("host-interaction", "")
	if err != nil {
		t.Fatalf("failed to query by namespace: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 capability in host-interaction, got %d", len(results))
	}

	// Query by name pattern
	results, err = db.QueryCapabilities("", "encrypt")
	if err != nil {
		t.Fatalf("failed to query by name: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 capability matching 'encrypt', got %d", len(results))
	}

	// Verify ATT&CK IDs survived the round-trip
	if len(results[0].AttackIDs) != 1 || results[0].AttackIDs[0] != "T1486" {
		t.Errorf("ATT&CK IDs didn't round-trip: %v", results[0].AttackIDs)
	}
}

func TestPackerDetectionsCRUD(t *testing.T) {
	dir, err := os.MkdirTemp("", "cache-packer-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	db, err := OpenDB(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer db.Close()

	dets := []model.PackerDetection{
		{Type: "compiler", Name: "GCC", Version: "11.2"},
		{Type: "packer", Name: "UPX", Version: "3.96", String: "UPX(3.96)[NRV2B]"},
	}

	err = db.InsertPackerDetections(dets)
	if err != nil {
		t.Fatalf("failed to insert packer detections: %v", err)
	}

	// Query all
	results, err := db.QueryPackerDetections("")
	if err != nil {
		t.Fatalf("failed to query all: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 detections, got %d", len(results))
	}

	// Query by type
	results, err = db.QueryPackerDetections("packer")
	if err != nil {
		t.Fatalf("failed to query by type: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 packer detection, got %d", len(results))
	}
	if results[0].Name != "UPX" {
		t.Errorf("expected UPX, got %s", results[0].Name)
	}
}

func TestClearEnrichment(t *testing.T) {
	dir, err := os.MkdirTemp("", "cache-clear-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	db, err := OpenDB(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer db.Close()

	// Insert capa enrichment + capabilities
	db.InsertEnrichment(model.Enrichment{
		Tool:      "capa",
		Timestamp: time.Now(),
		RawOutput: "{}",
	})
	db.InsertCapabilities([]model.Capability{
		{Name: "test cap", Namespace: "test"},
	})

	// Clear capa enrichment
	err = db.ClearEnrichment("capa")
	if err != nil {
		t.Fatalf("failed to clear: %v", err)
	}

	// Verify enrichment gone
	enrichments, _ := db.QueryEnrichments("capa")
	if len(enrichments) != 0 {
		t.Error("enrichment not cleared")
	}

	// Verify capabilities gone
	caps, _ := db.QueryCapabilities("", "")
	if len(caps) != 0 {
		t.Error("capabilities not cleared")
	}
}
