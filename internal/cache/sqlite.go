package cache

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/refractionPOINT/lcre/internal/model"
	_ "modernc.org/sqlite"
)

// DB wraps a SQLite database connection for analysis caching.
type DB struct {
	db *sql.DB
}

// OpenDB opens or creates a SQLite database at the given path.
func OpenDB(path string) (*DB, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)")
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	// Initialize schema
	if _, err := db.Exec(Schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("initialize schema: %w", err)
	}

	return &DB{db: db}, nil
}

// Close closes the database connection.
func (d *DB) Close() error {
	return d.db.Close()
}

// SetMetadata stores a metadata key-value pair.
func (d *DB) SetMetadata(key, value string) error {
	_, err := d.db.Exec(
		"INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
		key, value,
	)
	return err
}

// GetMetadata retrieves a metadata value by key.
func (d *DB) GetMetadata(key string) (string, error) {
	var value string
	err := d.db.QueryRow("SELECT value FROM metadata WHERE key = ?", key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return value, err
}

// StoreMetadataJSON stores a struct as JSON metadata.
func (d *DB) StoreMetadataJSON(key string, v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return d.SetMetadata(key, string(data))
}

// LoadMetadataJSON loads JSON metadata into a struct.
func (d *DB) LoadMetadataJSON(key string, v interface{}) error {
	data, err := d.GetMetadata(key)
	if err != nil {
		return err
	}
	if data == "" {
		return sql.ErrNoRows
	}
	return json.Unmarshal([]byte(data), v)
}

// InsertStrings inserts strings in bulk.
func (d *DB) InsertStrings(strings []model.ExtractedString) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare("INSERT INTO strings (value, offset, section, encoding) VALUES (?, ?, ?, ?)")
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, s := range strings {
		_, err := stmt.Exec(s.Value, s.Offset, s.Section, s.Encoding)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

// QueryStrings searches strings with optional pattern matching.
func (d *DB) QueryStrings(pattern string, limit, offset int) ([]model.ExtractedString, int, error) {
	var results []model.ExtractedString
	var total int

	// Use FTS if pattern looks like a word search, otherwise use LIKE
	var rows *sql.Rows
	var err error

	if pattern != "" {
		// Check if pattern is a simple alphanumeric search (use FTS) or regex-like (use LIKE)
		if isSimplePattern(pattern) {
			// Use FTS for simple patterns
			countQuery := `SELECT COUNT(*) FROM strings_fts WHERE strings_fts MATCH ?`
			err = d.db.QueryRow(countQuery, escapeForFTS(pattern)).Scan(&total)
			if err != nil {
				return nil, 0, err
			}

			query := `
				SELECT s.value, s.offset, s.section, s.encoding
				FROM strings s
				JOIN strings_fts f ON s.id = f.rowid
				WHERE f.strings_fts MATCH ?
				ORDER BY s.offset
				LIMIT ? OFFSET ?
			`
			rows, err = d.db.Query(query, escapeForFTS(pattern), limit, offset)
		} else {
			// Use LIKE for patterns with wildcards
			likePattern := "%" + pattern + "%"
			countQuery := `SELECT COUNT(*) FROM strings WHERE value LIKE ?`
			err = d.db.QueryRow(countQuery, likePattern).Scan(&total)
			if err != nil {
				return nil, 0, err
			}

			query := `
				SELECT value, offset, section, encoding
				FROM strings
				WHERE value LIKE ?
				ORDER BY offset
				LIMIT ? OFFSET ?
			`
			rows, err = d.db.Query(query, likePattern, limit, offset)
		}
	} else {
		// No pattern - return all
		err = d.db.QueryRow("SELECT COUNT(*) FROM strings").Scan(&total)
		if err != nil {
			return nil, 0, err
		}

		rows, err = d.db.Query(
			"SELECT value, offset, section, encoding FROM strings ORDER BY offset LIMIT ? OFFSET ?",
			limit, offset,
		)
	}

	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	for rows.Next() {
		var s model.ExtractedString
		if err := rows.Scan(&s.Value, &s.Offset, &s.Section, &s.Encoding); err != nil {
			return nil, 0, err
		}
		results = append(results, s)
	}

	return results, total, rows.Err()
}

// GetStringAt returns the string at a specific offset.
func (d *DB) GetStringAt(offset int64) (*model.ExtractedString, error) {
	var s model.ExtractedString
	err := d.db.QueryRow(
		"SELECT value, offset, section, encoding FROM strings WHERE offset = ?",
		offset,
	).Scan(&s.Value, &s.Offset, &s.Section, &s.Encoding)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// InsertSections inserts sections in bulk.
func (d *DB) InsertSections(sections []model.Section) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(
		"INSERT INTO sections (name, virtual_addr, virtual_size, raw_size, entropy, permissions, characteristics) VALUES (?, ?, ?, ?, ?, ?, ?)",
	)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, s := range sections {
		_, err := stmt.Exec(s.Name, s.VirtualAddr, s.VirtualSize, s.RawSize, s.Entropy, s.Permissions, s.Characteristics)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

// QuerySections returns all sections or filtered by name.
func (d *DB) QuerySections(name string) ([]model.Section, error) {
	var rows *sql.Rows
	var err error

	if name != "" {
		rows, err = d.db.Query(
			"SELECT name, virtual_addr, virtual_size, raw_size, entropy, permissions, characteristics FROM sections WHERE name = ?",
			name,
		)
	} else {
		rows, err = d.db.Query(
			"SELECT name, virtual_addr, virtual_size, raw_size, entropy, permissions, characteristics FROM sections ORDER BY virtual_addr",
		)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []model.Section
	for rows.Next() {
		var s model.Section
		if err := rows.Scan(&s.Name, &s.VirtualAddr, &s.VirtualSize, &s.RawSize, &s.Entropy, &s.Permissions, &s.Characteristics); err != nil {
			return nil, err
		}
		results = append(results, s)
	}

	return results, rows.Err()
}

// InsertImports inserts imports in bulk.
func (d *DB) InsertImports(imports []model.Import) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(
		"INSERT INTO imports (library, function, ordinal, address) VALUES (?, ?, ?, ?)",
	)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, imp := range imports {
		_, err := stmt.Exec(imp.Library, imp.Function, imp.Ordinal, imp.Address)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

// QueryImports returns imports filtered by library and/or function pattern.
func (d *DB) QueryImports(library, functionPattern string) ([]model.Import, error) {
	query := "SELECT library, function, ordinal, address FROM imports WHERE 1=1"
	var args []interface{}

	if library != "" {
		query += " AND LOWER(library) LIKE LOWER(?)"
		args = append(args, "%"+library+"%")
	}
	if functionPattern != "" {
		query += " AND LOWER(function) LIKE LOWER(?)"
		args = append(args, "%"+functionPattern+"%")
	}

	query += " ORDER BY library, function"

	rows, err := d.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []model.Import
	for rows.Next() {
		var imp model.Import
		if err := rows.Scan(&imp.Library, &imp.Function, &imp.Ordinal, &imp.Address); err != nil {
			return nil, err
		}
		results = append(results, imp)
	}

	return results, rows.Err()
}

// InsertExports inserts exports in bulk.
func (d *DB) InsertExports(exports []model.Export) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare("INSERT INTO exports (name, ordinal, address) VALUES (?, ?, ?)")
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, exp := range exports {
		_, err := stmt.Exec(exp.Name, exp.Ordinal, exp.Address)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

// QueryExports returns exports filtered by name pattern.
func (d *DB) QueryExports(namePattern string) ([]model.Export, error) {
	var rows *sql.Rows
	var err error

	if namePattern != "" {
		rows, err = d.db.Query(
			"SELECT name, ordinal, address FROM exports WHERE LOWER(name) LIKE LOWER(?) ORDER BY name",
			"%"+namePattern+"%",
		)
	} else {
		rows, err = d.db.Query("SELECT name, ordinal, address FROM exports ORDER BY name")
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []model.Export
	for rows.Next() {
		var exp model.Export
		if err := rows.Scan(&exp.Name, &exp.Ordinal, &exp.Address); err != nil {
			return nil, err
		}
		results = append(results, exp)
	}

	return results, rows.Err()
}

// InsertFunctions inserts functions in bulk.
func (d *DB) InsertFunctions(functions []model.Function) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(
		"INSERT OR REPLACE INTO functions (address, name, size, signature, is_external, is_thunk) VALUES (?, ?, ?, ?, ?, ?)",
	)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, f := range functions {
		_, err := stmt.Exec(f.Address, f.Name, f.Size, f.Signature, f.IsExternal, f.IsThunk)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

// QueryFunctions returns functions filtered by name or address.
func (d *DB) QueryFunctions(namePattern string, address int64, limit int) ([]model.Function, error) {
	query := "SELECT address, name, size, signature, is_external, is_thunk FROM functions WHERE 1=1"
	var args []interface{}

	if namePattern != "" {
		query += " AND LOWER(name) LIKE LOWER(?)"
		args = append(args, "%"+namePattern+"%")
	}
	if address > 0 {
		query += " AND address = ?"
		args = append(args, address)
	}

	query += " ORDER BY address"
	if limit > 0 {
		query += " LIMIT ?"
		args = append(args, limit)
	}

	rows, err := d.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []model.Function
	for rows.Next() {
		var f model.Function
		if err := rows.Scan(&f.Address, &f.Name, &f.Size, &f.Signature, &f.IsExternal, &f.IsThunk); err != nil {
			return nil, err
		}
		results = append(results, f)
	}

	return results, rows.Err()
}

// GetFunction returns a single function by name or address.
func (d *DB) GetFunction(nameOrAddr string) (*model.Function, error) {
	var f model.Function

	// Try as address first
	addr := parseAddress(nameOrAddr)
	if addr > 0 {
		err := d.db.QueryRow(
			"SELECT address, name, size, signature, is_external, is_thunk FROM functions WHERE address = ?",
			addr,
		).Scan(&f.Address, &f.Name, &f.Size, &f.Signature, &f.IsExternal, &f.IsThunk)
		if err == nil {
			return &f, nil
		}
		if err != sql.ErrNoRows {
			return nil, err
		}
	}

	// Try as name
	err := d.db.QueryRow(
		"SELECT address, name, size, signature, is_external, is_thunk FROM functions WHERE name = ?",
		nameOrAddr,
	).Scan(&f.Address, &f.Name, &f.Size, &f.Signature, &f.IsExternal, &f.IsThunk)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &f, nil
}

// InsertCalls inserts call relationships in bulk.
func (d *DB) InsertCalls(calls []model.CallGraphEdge) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare("INSERT OR IGNORE INTO calls (caller, callee) VALUES (?, ?)")
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, c := range calls {
		_, err := stmt.Exec(c.From, c.To)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

// GetCallers returns functions that call the given function.
func (d *DB) GetCallers(address int64) ([]model.Function, error) {
	rows, err := d.db.Query(`
		SELECT f.address, f.name, f.size, f.signature, f.is_external, f.is_thunk
		FROM functions f
		JOIN calls c ON f.address = c.caller
		WHERE c.callee = ?
		ORDER BY f.address
	`, address)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []model.Function
	for rows.Next() {
		var f model.Function
		if err := rows.Scan(&f.Address, &f.Name, &f.Size, &f.Signature, &f.IsExternal, &f.IsThunk); err != nil {
			return nil, err
		}
		results = append(results, f)
	}

	return results, rows.Err()
}

// GetCallees returns functions called by the given function.
func (d *DB) GetCallees(address int64) ([]model.Function, error) {
	rows, err := d.db.Query(`
		SELECT f.address, f.name, f.size, f.signature, f.is_external, f.is_thunk
		FROM functions f
		JOIN calls c ON f.address = c.callee
		WHERE c.caller = ?
		ORDER BY f.address
	`, address)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []model.Function
	for rows.Next() {
		var f model.Function
		if err := rows.Scan(&f.Address, &f.Name, &f.Size, &f.Signature, &f.IsExternal, &f.IsThunk); err != nil {
			return nil, err
		}
		results = append(results, f)
	}

	return results, rows.Err()
}

// InsertXrefs inserts cross-references in bulk.
func (d *DB) InsertXrefs(xrefs []Xref) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare("INSERT OR IGNORE INTO xrefs (from_addr, to_addr, type) VALUES (?, ?, ?)")
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, x := range xrefs {
		_, err := stmt.Exec(x.From, x.To, x.Type)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

// Xref represents a cross-reference entry.
type Xref struct {
	From     int64  `json:"from"`
	To       int64  `json:"to"`
	Type     string `json:"type"`
	FromFunc string `json:"from_function,omitempty"`
}

// GetXrefsTo returns all references to the given address.
func (d *DB) GetXrefsTo(address int64) ([]Xref, error) {
	rows, err := d.db.Query(`
		SELECT x.from_addr, x.to_addr, x.type, COALESCE(f.name, '')
		FROM xrefs x
		LEFT JOIN functions f ON x.from_addr >= f.address AND x.from_addr < f.address + f.size
		WHERE x.to_addr = ?
		ORDER BY x.from_addr
	`, address)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []Xref
	for rows.Next() {
		var x Xref
		if err := rows.Scan(&x.From, &x.To, &x.Type, &x.FromFunc); err != nil {
			return nil, err
		}
		results = append(results, x)
	}

	return results, rows.Err()
}

// GetXrefsFrom returns all references from the given address.
func (d *DB) GetXrefsFrom(address int64) ([]Xref, error) {
	rows, err := d.db.Query(`
		SELECT from_addr, to_addr, type FROM xrefs WHERE from_addr = ? ORDER BY to_addr
	`, address)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []Xref
	for rows.Next() {
		var x Xref
		if err := rows.Scan(&x.From, &x.To, &x.Type); err != nil {
			return nil, err
		}
		results = append(results, x)
	}

	return results, rows.Err()
}

// InsertIOCs inserts IOCs in bulk.
func (d *DB) InsertIOCs(iocs []model.IOC) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare("INSERT INTO iocs (type, value, offset, section, context) VALUES (?, ?, ?, ?, ?)")
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, ioc := range iocs {
		_, err := stmt.Exec(string(ioc.Type), ioc.Value, ioc.Offset, ioc.Section, ioc.Context)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

// QueryIOCs returns IOCs filtered by type.
func (d *DB) QueryIOCs(iocType string) ([]model.IOC, error) {
	var rows *sql.Rows
	var err error

	if iocType != "" {
		rows, err = d.db.Query(
			"SELECT type, value, offset, section, context FROM iocs WHERE type = ? ORDER BY type, value",
			iocType,
		)
	} else {
		rows, err = d.db.Query("SELECT type, value, offset, section, context FROM iocs ORDER BY type, value")
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []model.IOC
	for rows.Next() {
		var ioc model.IOC
		var typeStr string
		if err := rows.Scan(&typeStr, &ioc.Value, &ioc.Offset, &ioc.Section, &ioc.Context); err != nil {
			return nil, err
		}
		ioc.Type = model.IOCType(typeStr)
		results = append(results, ioc)
	}

	return results, rows.Err()
}

// InsertYARAMatches inserts YARA matches in bulk.
func (d *DB) InsertYARAMatches(matches []YARAMatch) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(
		"INSERT INTO yara_matches (rule, namespace, tags, description, strings) VALUES (?, ?, ?, ?, ?)",
	)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, m := range matches {
		tags, _ := json.Marshal(m.Tags)
		strs, _ := json.Marshal(m.Strings)
		_, err := stmt.Exec(m.Rule, m.Namespace, string(tags), m.Description, string(strs))
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

// YARAMatch represents a YARA rule match for storage.
type YARAMatch struct {
	Rule        string   `json:"rule"`
	Namespace   string   `json:"namespace,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Description string   `json:"description,omitempty"`
	Strings     []string `json:"strings,omitempty"`
}

// QueryYARAMatches returns YARA matches filtered by rule name.
func (d *DB) QueryYARAMatches(ruleName string) ([]YARAMatch, error) {
	var rows *sql.Rows
	var err error

	if ruleName != "" {
		rows, err = d.db.Query(
			"SELECT rule, namespace, tags, description, strings FROM yara_matches WHERE rule LIKE ? ORDER BY rule",
			"%"+ruleName+"%",
		)
	} else {
		rows, err = d.db.Query("SELECT rule, namespace, tags, description, strings FROM yara_matches ORDER BY rule")
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []YARAMatch
	for rows.Next() {
		var m YARAMatch
		var tags, strs string
		if err := rows.Scan(&m.Rule, &m.Namespace, &tags, &m.Description, &strs); err != nil {
			return nil, err
		}
		if tags != "" {
			json.Unmarshal([]byte(tags), &m.Tags)
		}
		if strs != "" {
			json.Unmarshal([]byte(strs), &m.Strings)
		}
		results = append(results, m)
	}

	return results, rows.Err()
}

// InsertEntryPoints inserts entry points in bulk.
func (d *DB) InsertEntryPoints(entryPoints []model.EntryPoint) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare("INSERT INTO entry_points (name, address, type) VALUES (?, ?, ?)")
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, ep := range entryPoints {
		_, err := stmt.Exec(ep.Name, ep.Address, ep.Type)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

// QueryEntryPoints returns all entry points.
func (d *DB) QueryEntryPoints() ([]model.EntryPoint, error) {
	rows, err := d.db.Query("SELECT name, address, type FROM entry_points ORDER BY address")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []model.EntryPoint
	for rows.Next() {
		var ep model.EntryPoint
		if err := rows.Scan(&ep.Name, &ep.Address, &ep.Type); err != nil {
			return nil, err
		}
		results = append(results, ep)
	}

	return results, rows.Err()
}

// GetCallGraph returns the full call graph.
func (d *DB) GetCallGraph() (*model.CallGraph, error) {
	// Get nodes (functions)
	funcs, err := d.QueryFunctions("", 0, 0)
	if err != nil {
		return nil, err
	}

	nodes := make([]model.CallGraphNode, 0, len(funcs))
	for _, f := range funcs {
		nodes = append(nodes, model.CallGraphNode{
			Address: f.Address,
			Name:    f.Name,
		})
	}

	// Get edges (calls)
	rows, err := d.db.Query("SELECT caller, callee FROM calls ORDER BY caller, callee")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var edges []model.CallGraphEdge
	for rows.Next() {
		var e model.CallGraphEdge
		if err := rows.Scan(&e.From, &e.To); err != nil {
			return nil, err
		}
		edges = append(edges, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return &model.CallGraph{
		Nodes: nodes,
		Edges: edges,
	}, nil
}

// parseAddress parses a hex or decimal address string.
func parseAddress(s string) int64 {
	var addr int64
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		// Parse hex value after stripping the prefix
		fmt.Sscanf(s[2:], "%x", &addr)
	} else {
		fmt.Sscanf(s, "%d", &addr)
	}
	return addr
}

// isSimplePattern returns true if the pattern is a simple word search.
func isSimplePattern(pattern string) bool {
	// FTS5 doesn't handle special regex characters well
	return regexp.MustCompile(`^[a-zA-Z0-9_\-\.]+$`).MatchString(pattern)
}

// escapeForFTS escapes special FTS5 characters.
func escapeForFTS(s string) string {
	// FTS5 uses * and " as special characters
	s = strings.ReplaceAll(s, "\"", "\"\"")
	return "\"" + s + "\""
}
