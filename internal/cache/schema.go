// Package cache provides SQLite-based caching for binary analysis results.
package cache

// Schema contains the SQLite schema for the analysis cache.
const Schema = `
-- Metadata table for quick access
CREATE TABLE IF NOT EXISTS metadata (
    key TEXT PRIMARY KEY,
    value TEXT
);

-- Strings table
CREATE TABLE IF NOT EXISTS strings (
    id INTEGER PRIMARY KEY,
    value TEXT NOT NULL,
    offset INTEGER NOT NULL,
    section TEXT,
    encoding TEXT DEFAULT 'ascii'
);
CREATE INDEX IF NOT EXISTS idx_strings_offset ON strings(offset);
CREATE INDEX IF NOT EXISTS idx_strings_section ON strings(section);

-- Full-text search for strings
CREATE VIRTUAL TABLE IF NOT EXISTS strings_fts USING fts5(
    value,
    content='strings',
    content_rowid='id'
);

-- Triggers to keep FTS in sync
CREATE TRIGGER IF NOT EXISTS strings_ai AFTER INSERT ON strings BEGIN
    INSERT INTO strings_fts(rowid, value) VALUES (new.id, new.value);
END;
CREATE TRIGGER IF NOT EXISTS strings_ad AFTER DELETE ON strings BEGIN
    INSERT INTO strings_fts(strings_fts, rowid, value) VALUES('delete', old.id, old.value);
END;
CREATE TRIGGER IF NOT EXISTS strings_au AFTER UPDATE ON strings BEGIN
    INSERT INTO strings_fts(strings_fts, rowid, value) VALUES('delete', old.id, old.value);
    INSERT INTO strings_fts(rowid, value) VALUES (new.id, new.value);
END;

-- Sections table
CREATE TABLE IF NOT EXISTS sections (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    virtual_addr INTEGER,
    virtual_size INTEGER,
    raw_size INTEGER,
    entropy REAL,
    permissions TEXT,
    characteristics INTEGER
);
CREATE INDEX IF NOT EXISTS idx_sections_name ON sections(name);

-- Imports table
CREATE TABLE IF NOT EXISTS imports (
    id INTEGER PRIMARY KEY,
    library TEXT NOT NULL,
    function TEXT NOT NULL,
    ordinal INTEGER,
    address INTEGER
);
CREATE INDEX IF NOT EXISTS idx_imports_library ON imports(library);
CREATE INDEX IF NOT EXISTS idx_imports_function ON imports(function);

-- Exports table
CREATE TABLE IF NOT EXISTS exports (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    ordinal INTEGER,
    address INTEGER
);
CREATE INDEX IF NOT EXISTS idx_exports_name ON exports(name);

-- Functions table
CREATE TABLE IF NOT EXISTS functions (
    address INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    size INTEGER,
    signature TEXT,
    is_external BOOLEAN DEFAULT 0,
    is_thunk BOOLEAN DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_functions_name ON functions(name);

-- Cross-references table
CREATE TABLE IF NOT EXISTS xrefs (
    id INTEGER PRIMARY KEY,
    from_addr INTEGER NOT NULL,
    to_addr INTEGER NOT NULL,
    type TEXT
);
CREATE INDEX IF NOT EXISTS idx_xrefs_from ON xrefs(from_addr);
CREATE INDEX IF NOT EXISTS idx_xrefs_to ON xrefs(to_addr);
CREATE UNIQUE INDEX IF NOT EXISTS idx_xrefs_pair ON xrefs(from_addr, to_addr);

-- Call graph (caller/callee relationships)
CREATE TABLE IF NOT EXISTS calls (
    id INTEGER PRIMARY KEY,
    caller INTEGER NOT NULL,
    callee INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_calls_caller ON calls(caller);
CREATE INDEX IF NOT EXISTS idx_calls_callee ON calls(callee);
CREATE UNIQUE INDEX IF NOT EXISTS idx_calls_pair ON calls(caller, callee);

-- IOCs table
CREATE TABLE IF NOT EXISTS iocs (
    id INTEGER PRIMARY KEY,
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    offset INTEGER,
    section TEXT,
    context TEXT
);
CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(type);
CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(value);

-- YARA matches
CREATE TABLE IF NOT EXISTS yara_matches (
    id INTEGER PRIMARY KEY,
    rule TEXT NOT NULL,
    namespace TEXT,
    tags TEXT,
    description TEXT,
    strings TEXT
);
CREATE INDEX IF NOT EXISTS idx_yara_rule ON yara_matches(rule);

-- Entry points
CREATE TABLE IF NOT EXISTS entry_points (
    id INTEGER PRIMARY KEY,
    name TEXT,
    address INTEGER NOT NULL,
    type TEXT
);
CREATE INDEX IF NOT EXISTS idx_entry_points_address ON entry_points(address);

-- Enrichments from external tools (raw JSON storage)
CREATE TABLE IF NOT EXISTS enrichments (
    id INTEGER PRIMARY KEY,
    tool TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    raw_output TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_enrichments_tool ON enrichments(tool);

-- Capabilities (from capa or similar tools)
CREATE TABLE IF NOT EXISTS capabilities (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    namespace TEXT,
    author TEXT,
    scope TEXT,
    attack_ids TEXT,
    mbc_ids TEXT
);
CREATE INDEX IF NOT EXISTS idx_capabilities_name ON capabilities(name);
CREATE INDEX IF NOT EXISTS idx_capabilities_namespace ON capabilities(namespace);

-- Packer/compiler detections (from diec or similar tools)
CREATE TABLE IF NOT EXISTS packer_detections (
    id INTEGER PRIMARY KEY,
    type TEXT NOT NULL,
    name TEXT NOT NULL,
    version TEXT,
    string TEXT
);
CREATE INDEX IF NOT EXISTS idx_packer_type ON packer_detections(type);
`
