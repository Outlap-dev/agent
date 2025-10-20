package update

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// ParseChecksumManifest extracts the SHA256 checksum value from a manifest line.
// Expected format is "<hex>  <filename>" as produced by sha256sum.
func ParseChecksumManifest(manifest string) (string, error) {
	fields := strings.Fields(strings.TrimSpace(manifest))
	if len(fields) == 0 {
		return "", fmt.Errorf("checksum manifest does not contain a hash value")
	}

	checksum := fields[0]
	if len(checksum) != 64 {
		return "", fmt.Errorf("checksum must be 64 hex characters, got %d", len(checksum))
	}

	if _, err := hex.DecodeString(checksum); err != nil {
		return "", fmt.Errorf("checksum value is not valid hex: %w", err)
	}

	return checksum, nil
}
