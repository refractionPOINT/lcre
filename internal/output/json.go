package output

import (
	"encoding/json"
	"io"
	"os"
)

// JSONWriter writes analysis results as JSON
type JSONWriter struct {
	indent bool
}

// NewJSONWriter creates a new JSON writer
func NewJSONWriter(indent bool) *JSONWriter {
	return &JSONWriter{indent: indent}
}

// Write writes data as JSON to the given writer
func (w *JSONWriter) Write(writer io.Writer, data interface{}) error {
	encoder := json.NewEncoder(writer)
	if w.indent {
		encoder.SetIndent("", "  ")
	}
	return encoder.Encode(data)
}

// WriteToFile writes data as JSON to a file
func (w *JSONWriter) WriteToFile(path string, data interface{}) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return w.Write(f, data)
}

// Marshal returns data as a JSON byte slice
func (w *JSONWriter) Marshal(data interface{}) ([]byte, error) {
	if w.indent {
		return json.MarshalIndent(data, "", "  ")
	}
	return json.Marshal(data)
}
