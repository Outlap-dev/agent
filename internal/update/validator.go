package update

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"os"
)

// Default embedded public key for verifying update signatures
var EmbeddedPublicKey = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAw5rJ14PFubDpz7fx67APlspgH5S3GRTVUohhq2zTqc0=
-----END PUBLIC KEY-----`

type Validator struct {
	publicKey crypto.PublicKey
}

func NewValidator() (*Validator, error) {
	publicKey, err := parsePublicKey([]byte(EmbeddedPublicKey))
	if err != nil {
		return nil, fmt.Errorf("failed to load embedded public key: %w", err)
	}

	return &Validator{
		publicKey: publicKey,
	}, nil
}

func parsePublicKey(keyData []byte) (crypto.PublicKey, error) {
	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block")
	}

	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	switch key := parsed.(type) {
	case *rsa.PublicKey:
		return key, nil
	case ed25519.PublicKey:
		return key, nil
	default:
		return nil, fmt.Errorf("unsupported public key type: %T", parsed)
	}
}

// VerifySignature verifies the signature of the update metadata
func (v *Validator) VerifySignature(payload []byte, signatureB64 string) error {
	signature, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	switch key := v.publicKey.(type) {
	case *rsa.PublicKey:
		hash := sha256.Sum256(payload)
		err = rsa.VerifyPKCS1v15(key, crypto.SHA256, hash[:], signature)
		if err != nil {
			return fmt.Errorf("RSA signature verification failed: %w", err)
		}
	case ed25519.PublicKey:
		if !ed25519.Verify(key, payload, signature) {
			return fmt.Errorf("Ed25519 signature verification failed")
		}
	default:
		return fmt.Errorf("unsupported public key type: %T", v.publicKey)
	}

	return nil
}

// VerifyFileHash verifies the SHA256 hash of a file
func VerifyFileHash(filePath string, expectedHash string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return fmt.Errorf("failed to calculate hash: %w", err)
	}

	calculatedHash := hex.EncodeToString(hasher.Sum(nil))
	if calculatedHash != expectedHash {
		return fmt.Errorf("hash mismatch: expected %s, got %s", expectedHash, calculatedHash)
	}

	return nil
}

// CalculateFileHash calculates the SHA256 hash of a file
func CalculateFileHash(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", fmt.Errorf("failed to calculate hash: %w", err)
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}
