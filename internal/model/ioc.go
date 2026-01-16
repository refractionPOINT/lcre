package model

// IOCType represents the type of indicator of compromise
type IOCType string

const (
	IOCURL     IOCType = "url"
	IOCDomain  IOCType = "domain"
	IOCIP      IOCType = "ip"
	IOCEmail   IOCType = "email"
	IOCPath    IOCType = "path"
	IOCRegistry IOCType = "registry"
	IOCHash    IOCType = "hash"
)

// IOC represents an indicator of compromise found in the binary
type IOC struct {
	Type    IOCType  `json:"type"`
	Value   string   `json:"value"`
	Offset  uint64   `json:"offset,omitempty"`
	Section string   `json:"section,omitempty"`
	Context string   `json:"context,omitempty"`
	XRefs   []uint64 `json:"xrefs,omitempty"`
}

// IOCResult contains all extracted IOCs
type IOCResult struct {
	URLs      []IOC `json:"urls,omitempty"`
	Domains   []IOC `json:"domains,omitempty"`
	IPs       []IOC `json:"ips,omitempty"`
	Emails    []IOC `json:"emails,omitempty"`
	Paths     []IOC `json:"paths,omitempty"`
	Registry  []IOC `json:"registry,omitempty"`
	Hashes    []IOC `json:"hashes,omitempty"`
	Count     int   `json:"total_count"`
}

// AddIOC adds an IOC to the appropriate category
func (r *IOCResult) AddIOC(ioc IOC) {
	switch ioc.Type {
	case IOCURL:
		r.URLs = append(r.URLs, ioc)
	case IOCDomain:
		r.Domains = append(r.Domains, ioc)
	case IOCIP:
		r.IPs = append(r.IPs, ioc)
	case IOCEmail:
		r.Emails = append(r.Emails, ioc)
	case IOCPath:
		r.Paths = append(r.Paths, ioc)
	case IOCRegistry:
		r.Registry = append(r.Registry, ioc)
	case IOCHash:
		r.Hashes = append(r.Hashes, ioc)
	}
	r.Count++
}

// IsEmpty returns true if no IOCs were found
func (r *IOCResult) IsEmpty() bool {
	return r.Count == 0
}
