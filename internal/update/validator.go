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

// PublicKey is the embedded public key for verifying updates
// This should be replaced with the actual PulseUp public key
var EmbeddedPublicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Z3VS5JJcds3xfn/ygWyF0qV
BPr2iCsJKKjTbX2hLJqnPLcqrceaz2NJJBbORpMkNuJFdpCCFMKQbkUi6WJKEKiGQqU8
5nNPmwwz4woyuiFjljMZqma0Fc6qPgvU0nm76L4XUbfej9GSN6kFDmuQfYYouSs3WRgO
sV0bLu5s3BqAFkpOgFGkkWFmhWYdANM0xHDTXq6rvQnAzFEQHMNDzFekr2E2aFO5mPIx
uFxqC3JQYUvVotwcGt2KN5hOmWWNyvZQJdCCdkXBq5hfXFLNpvXP9XJq0hBNSF9F8JIE
h9AvmIjEnlsJ8npjLQW7KXPW6QvDlNDr0wIDAQAB
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
	
	// Try parsing as RSA key first
	if rsaKey, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		v.publicKey = rsaKey
		return nil
	}
	
	// Try parsing as Ed25519 key
	if ed25519Key, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		v.publicKey = ed25519Key
		return nil
	}
	
	return fmt.Errorf("unsupported public key type")
}

// VerifySignature verifies the signature of the update metadata
func (v *Validator) VerifySignature(payload []byte, signatureB64 string) error {
	signature, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}
	
	// Calculate hash of payload
	hash := sha256.Sum256(payload)
	
	switch key := v.publicKey.(type) {
	case *rsa.PublicKey:
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