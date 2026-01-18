package model

// BinaryFormat represents the detected binary format
type BinaryFormat string

const (
	FormatPE     BinaryFormat = "PE"
	FormatELF    BinaryFormat = "ELF"
	FormatMachO  BinaryFormat = "Mach-O"
	FormatUnknown BinaryFormat = "unknown"
)

// BinaryMetadata contains basic information about the analyzed binary
type BinaryMetadata struct {
	Path       string       `json:"path"`
	Name       string       `json:"name"`
	Size       int64        `json:"size"`
	MD5        string       `json:"md5"`
	SHA1       string       `json:"sha1"`
	SHA256     string       `json:"sha256"`
	Format     BinaryFormat `json:"format"`
	Arch       string       `json:"arch"`
	Bits       int          `json:"bits"`
	Endian     string       `json:"endian"`
	Compiler   string       `json:"compiler,omitempty"`
	Timestamp  int64        `json:"timestamp,omitempty"`
	IsSigned   bool         `json:"is_signed,omitempty"`
	ImpHash    string       `json:"imphash,omitempty"`
}

// PEInfo contains PE-specific metadata for anomaly detection
type PEInfo struct {
	Checksum           uint32 `json:"checksum"`
	CalculatedChecksum uint32 `json:"calculated_checksum"`
	ImageBase          uint64 `json:"image_base"`
	SectionAlignment   uint32 `json:"section_alignment"`
	FileAlignment      uint32 `json:"file_alignment"`
	SizeOfHeaders      uint32 `json:"size_of_headers"`
	Subsystem          uint16 `json:"subsystem"`
	DllCharacteristics uint16 `json:"dll_characteristics"`
	NumberOfSections   int    `json:"number_of_sections"`
	EntryPointSection  string `json:"entry_point_section,omitempty"`
}

// Section represents a binary section/segment
type Section struct {
	Name         string  `json:"name"`
	VirtualAddr  uint64  `json:"virtual_addr"`
	VirtualSize  uint64  `json:"virtual_size"`
	RawSize      uint64  `json:"raw_size"`
	Entropy      float64 `json:"entropy"`
	Permissions  string  `json:"permissions"`
	Characteristics uint32 `json:"characteristics,omitempty"`
}

// Import represents an imported function
type Import struct {
	Library  string `json:"library"`
	Function string `json:"function"`
	Ordinal  int    `json:"ordinal,omitempty"`
	Address  uint64 `json:"address,omitempty"`
}

// Export represents an exported function
type Export struct {
	Name    string `json:"name"`
	Ordinal int    `json:"ordinal,omitempty"`
	Address uint64 `json:"address"`
}

// ExtractedString represents a string found in the binary
type ExtractedString struct {
	Value     string   `json:"value"`
	Offset    uint64   `json:"offset"`
	Section   string   `json:"section,omitempty"`
	Encoding  string   `json:"encoding"`
	XRefs     []uint64 `json:"xrefs,omitempty"`
}

// Function represents a function (typically from Ghidra analysis)
type Function struct {
	Name       string   `json:"name"`
	Address    uint64   `json:"address"`
	Size       uint64   `json:"size"`
	Signature  string   `json:"signature,omitempty"`
	Callers    []uint64 `json:"callers,omitempty"`
	Callees    []uint64 `json:"callees,omitempty"`
	IsExternal bool     `json:"is_external"`
	IsThunk    bool     `json:"is_thunk"`
}

// CallGraph represents the function call graph
type CallGraph struct {
	Nodes []CallGraphNode `json:"nodes"`
	Edges []CallGraphEdge `json:"edges"`
}

// CallGraphNode represents a node in the call graph
type CallGraphNode struct {
	Address uint64 `json:"address"`
	Name    string `json:"name"`
}

// CallGraphEdge represents an edge in the call graph
type CallGraphEdge struct {
	From uint64 `json:"from"`
	To   uint64 `json:"to"`
}

// EntryPoint represents a program entry point
type EntryPoint struct {
	Name    string `json:"name"`
	Address uint64 `json:"address"`
	Type    string `json:"type"`
}
