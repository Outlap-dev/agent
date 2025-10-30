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
	publicKeyPath string
	publicKey     crypto.PublicKey
}

func NewValidator(publicKeyPath string) (*Validator, error) {
	v := &Validator{
		publicKeyPath: publicKeyPath,
	}

	// Try to load public key from file first
	if publicKeyPath != "" {
		if err := v.loadPublicKeyFromFile(); err != nil {
			// If file doesn't exist, use embedded key
			if !os.IsNotExist(err) {
				return nil, fmt.Errorf("failed to load public key from file: %w", err)
			}
		}
	}

	// If no key loaded from file, use embedded key
	if v.publicKey == nil {
		if err := v.loadEmbeddedPublicKey(); err != nil {
			return nil, fmt.Errorf("failed to load embedded public key: %w", err)
		}
	}

	return v, nil
}

func (v *Validator) loadPublicKeyFromFile() error {
	keyData, err := os.ReadFile(v.publicKeyPath)
	if err != nil {
		return err
	}

	return v.parsePublicKey(keyData)
}

func (v *Validator) loadEmbeddedPublicKey() error {
	return v.parsePublicKey([]byte(EmbeddedPublicKey))
}

func (v *Validator) parsePublicKey(keyData []byte) error {
	block, _ := pem.Decode(keyData)
	if block == nil {
		return fmt.Errorf("failed to parse PEM block")
	}

	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	switch key := parsed.(type) {
	case *rsa.PublicKey:
		v.publicKey = key
	case ed25519.PublicKey:
		v.publicKey = key
	default:
		return fmt.Errorf("unsupported public key type: %T", parsed)
	}

	return nil
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
