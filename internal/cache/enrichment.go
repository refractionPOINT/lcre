package cache

import (
	"database/sql"
	"encoding/json"
	"strings"
	"time"

	"github.com/refractionPOINT/lcre/internal/model"
)

// InsertEnrichment stores raw tool output. Replaces any existing entry for the same tool.
func (d *DB) InsertEnrichment(e model.Enrichment) error {
	_, err := d.db.Exec(
		"INSERT OR REPLACE INTO enrichments (tool, timestamp, raw_output) VALUES (?, ?, ?)",
		e.Tool, e.Timestamp.Format(time.RFC3339), e.RawOutput,
	)
	return err
}

// QueryEnrichments returns all stored enrichments, optionally filtered by tool name.
func (d *DB) QueryEnrichments(tool string) ([]model.Enrichment, error) {
	var rows *sql.Rows
	var err error

	if tool != "" {
		rows, err = d.db.Query(
			"SELECT tool, timestamp, raw_output FROM enrichments WHERE tool = ? ORDER BY tool",
			tool,
		)
	} else {
		rows, err = d.db.Query("SELECT tool, timestamp, raw_output FROM enrichments ORDER BY tool")
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []model.Enrichment
	for rows.Next() {
		var e model.Enrichment
		var ts string
		if err := rows.Scan(&e.Tool, &ts, &e.RawOutput); err != nil {
			return nil, err
		}
		e.Timestamp, _ = time.Parse(time.RFC3339, ts)
		results = append(results, e)
	}
	return results, rows.Err()
}

// InsertCapabilities stores capabilities in bulk.
func (d *DB) InsertCapabilities(caps []model.Capability) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(
		"INSERT INTO capabilities (name, namespace, author, scope, attack_ids, mbc_ids) VALUES (?, ?, ?, ?, ?, ?)",
	)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, c := range caps {
		attackIDs, _ := json.Marshal(c.AttackIDs)
		mbcIDs, _ := json.Marshal(c.MBCIDs)
		_, err := stmt.Exec(c.Name, c.Namespace, c.Author, c.Scope, string(attackIDs), string(mbcIDs))
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

// QueryCapabilities returns capabilities, optionally filtered by namespace prefix or name pattern.
func (d *DB) QueryCapabilities(namespace, namePattern string) ([]model.Capability, error) {
	query := "SELECT name, namespace, author, scope, attack_ids, mbc_ids FROM capabilities WHERE 1=1"
	var args []interface{}

	if namespace != "" {
		query += " AND namespace LIKE ?"
		args = append(args, namespace+"%")
	}
	if namePattern != "" {
		query += " AND LOWER(name) LIKE LOWER(?)"
		args = append(args, "%"+namePattern+"%")
	}
	query += " ORDER BY namespace, name"

	rows, err := d.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []model.Capability
	for rows.Next() {
		var c model.Capability
		var attackStr, mbcStr string
		if err := rows.Scan(&c.Name, &c.Namespace, &c.Author, &c.Scope, &attackStr, &mbcStr); err != nil {
			return nil, err
		}
		if attackStr != "" {
			json.Unmarshal([]byte(attackStr), &c.AttackIDs)
		}
		if mbcStr != "" {
			json.Unmarshal([]byte(mbcStr), &c.MBCIDs)
		}
		results = append(results, c)
	}
	return results, rows.Err()
}

// InsertPackerDetections stores packer/compiler detection results in bulk.
func (d *DB) InsertPackerDetections(detections []model.PackerDetection) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(
		"INSERT INTO packer_detections (type, name, version, string) VALUES (?, ?, ?, ?)",
	)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, det := range detections {
		_, err := stmt.Exec(det.Type, det.Name, det.Version, det.String)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

// QueryPackerDetections returns packer/compiler detections, optionally filtered by type.
func (d *DB) QueryPackerDetections(detType string) ([]model.PackerDetection, error) {
	var rows *sql.Rows
	var err error

	if detType != "" {
		rows, err = d.db.Query(
			"SELECT type, name, version, string FROM packer_detections WHERE LOWER(type) = LOWER(?) ORDER BY type, name",
			detType,
		)
	} else {
		rows, err = d.db.Query("SELECT type, name, version, string FROM packer_detections ORDER BY type, name")
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []model.PackerDetection
	for rows.Next() {
		var det model.PackerDetection
		if err := rows.Scan(&det.Type, &det.Name, &det.Version, &det.String); err != nil {
			return nil, err
		}
		results = append(results, det)
	}
	return results, rows.Err()
}

// ClearEnrichment removes an enrichment and its associated structured data.
func (d *DB) ClearEnrichment(tool string) error {
	tool = strings.ToLower(tool)
	if _, err := d.db.Exec("DELETE FROM enrichments WHERE tool = ?", tool); err != nil {
		return err
	}
	switch tool {
	case "capa":
		_, err := d.db.Exec("DELETE FROM capabilities")
		return err
	case "diec":
		_, err := d.db.Exec("DELETE FROM packer_detections")
		return err
	case "floss":
		_, err := d.db.Exec("DELETE FROM strings WHERE section LIKE 'floss:%'")
		return err
	}
	return nil
}
