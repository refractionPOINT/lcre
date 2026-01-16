package util

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
)

// FileHashes contains all hash values for a file
type FileHashes struct {
	MD5    string
	SHA1   string
	SHA256 string
}

// HashFile computes MD5, SHA1, and SHA256 hashes for a file
func HashFile(path string) (*FileHashes, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	md5Hash := md5.New()
	sha1Hash := sha1.New()
	sha256Hash := sha256.New()

	// Create a multi-writer to compute all hashes in one pass
	writer := io.MultiWriter(md5Hash, sha1Hash, sha256Hash)

	if _, err := io.Copy(writer, f); err != nil {
		return nil, err
	}

	return &FileHashes{
		MD5:    hex.EncodeToString(md5Hash.Sum(nil)),
		SHA1:   hex.EncodeToString(sha1Hash.Sum(nil)),
		SHA256: hex.EncodeToString(sha256Hash.Sum(nil)),
	}, nil
}

// HashBytes computes MD5, SHA1, and SHA256 hashes for a byte slice
func HashBytes(data []byte) *FileHashes {
	return &FileHashes{
		MD5:    hex.EncodeToString(md5Sum(data)),
		SHA1:   hex.EncodeToString(sha1Sum(data)),
		SHA256: hex.EncodeToString(sha256Sum(data)),
	}
}

func md5Sum(data []byte) []byte {
	h := md5.Sum(data)
	return h[:]
}

func sha1Sum(data []byte) []byte {
	h := sha1.Sum(data)
	return h[:]
}

func sha256Sum(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}
