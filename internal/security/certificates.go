// Package security provides certificate management for mTLS authentication.
package security

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"pulseup-agent-go/pkg/logger"
)

// CertificateManager handles certificate storage, loading, and renewal.
type CertificateManager struct {
	certDir    string
	certPath   string
	keyPath    string
	caPath     string
	logger     *logger.Logger
}

// CertPaths contains the file paths for certificates.
type CertPaths struct {
	CertFile string
	KeyFile  string
	CAFile   string
}

// NewCertificateManager creates a new certificate manager.
func NewCertificateManager(certDir string, logger *logger.Logger) *CertificateManager {
	if certDir == "" {
		certDir = "/var/lib/pulseup/certs"
	}

	return &CertificateManager{
		certDir:  certDir,
		certPath: filepath.Join(certDir, "agent.crt"),
		keyPath:  filepath.Join(certDir, "agent.key"),
		caPath:   filepath.Join(certDir, "ca.crt"),
		logger:   logger.With("component", "certificate_manager"),
	}
}

// EnsureCertDir creates the certificate directory if it doesn't exist.
func (cm *CertificateManager) EnsureCertDir() error {
	if err := os.MkdirAll(cm.certDir, 0700); err != nil {
		return fmt.Errorf("failed to create certificate directory: %w", err)
	}
	return nil
}

// GetPaths returns the certificate file paths.
func (cm *CertificateManager) GetPaths() CertPaths {
	return CertPaths{
		CertFile: cm.certPath,
		KeyFile:  cm.keyPath,
		CAFile:   cm.caPath,
	}
}

// HasCertificate checks if a valid certificate exists.
func (cm *CertificateManager) HasCertificate() bool {
	// Check if all certificate files exist
	if !cm.fileExists(cm.certPath) || !cm.fileExists(cm.keyPath) || !cm.fileExists(cm.caPath) {
		return false
	}

	// Try to load the certificate
	_, err := cm.LoadCertificate()
	return err == nil
}

// LoadCertificate loads the client certificate for mTLS.
func (cm *CertificateManager) LoadCertificate() (tls.Certificate, error) {
	if !cm.fileExists(cm.certPath) || !cm.fileExists(cm.keyPath) {
		return tls.Certificate{}, fmt.Errorf("certificate or key file not found")
	}

	cert, err := tls.LoadX509KeyPair(cm.certPath, cm.keyPath)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to load certificate: %w", err)
	}

	// Parse the certificate to check validity
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Check if certificate is expired
	now := time.Now()
	if now.Before(x509Cert.NotBefore) || now.After(x509Cert.NotAfter) {
		return tls.Certificate{}, fmt.Errorf("certificate is expired or not yet valid")
	}

	cm.logger.Debug("Successfully loaded certificate", 
		"not_before", x509Cert.NotBefore, 
		"not_after", x509Cert.NotAfter,
		"subject", x509Cert.Subject.String())

	return cert, nil
}

// LoadCACertificate loads the CA certificate for server verification.
func (cm *CertificateManager) LoadCACertificate() (*x509.CertPool, error) {
	if !cm.fileExists(cm.caPath) {
		return nil, fmt.Errorf("CA certificate file not found")
	}

	caCertPEM, err := os.ReadFile(cm.caPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %w", err)
	}

	// Start with system cert pool to trust public CAs (e.g., Let's Encrypt, Google Trust Services)
	caCertPool, err := x509.SystemCertPool()
	if err != nil {
		cm.logger.Warn("Failed to load system cert pool, using empty pool", "error", err)
		caCertPool = x509.NewCertPool()
	}
	
	// Add enrollment CA on top
	if !caCertPool.AppendCertsFromPEM(caCertPEM) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	cm.logger.Debug("Successfully loaded CA certificate (system + enrollment CA)")
	return caCertPool, nil
}

// ShouldRenew checks if the certificate should be renewed.
// Returns true if the certificate expires within the renewal threshold (70% of lifetime).
func (cm *CertificateManager) ShouldRenew() (bool, error) {
	if !cm.HasCertificate() {
		return false, fmt.Errorf("no certificate found")
	}

	certPEM, err := os.ReadFile(cm.certPath)
	if err != nil {
		return false, fmt.Errorf("failed to read certificate: %w", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return false, fmt.Errorf("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, fmt.Errorf("failed to parse certificate: %w", err)
	}

	now := time.Now()
	lifetime := cert.NotAfter.Sub(cert.NotBefore)
	renewalThreshold := cert.NotBefore.Add(time.Duration(float64(lifetime) * 0.7))

	shouldRenew := now.After(renewalThreshold)
	
	cm.logger.Debug("Certificate renewal check",
		"not_before", cert.NotBefore,
		"not_after", cert.NotAfter,
		"renewal_threshold", renewalThreshold,
		"should_renew", shouldRenew)

	return shouldRenew, nil
}

// GenerateKeyPair generates an Ed25519 key pair for the agent.
func (cm *CertificateManager) GenerateKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	cm.logger.Info("Generated new Ed25519 key pair")
	return pub, priv, nil
}

// CreateCSR creates a Certificate Signing Request for the given key pair.
func (cm *CertificateManager) CreateCSR(privateKey ed25519.PrivateKey, serverUID string) ([]byte, error) {
	template := x509.CertificateRequest{
		Subject: pkix.Name{
			Country:            []string{"US"},
			Organization:       []string{"PulseUp"},
			OrganizationalUnit: []string{"PulseUp Agent"},
			CommonName:         fmt.Sprintf("agent-%s", serverUID),
		},
		DNSNames: []string{
			fmt.Sprintf("agent-%s.pulseup.local", serverUID),
			serverUID,
		},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create CSR: %w", err)
	}

	// Encode to PEM format
	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	cm.logger.Info("Created certificate signing request", "subject", template.Subject.String())
	return csrPEM, nil
}

// StoreCertificate stores the certificate, private key, and CA certificate.
func (cm *CertificateManager) StoreCertificate(certPEM, caCertPEM []byte, privateKey ed25519.PrivateKey) error {
	if err := cm.EnsureCertDir(); err != nil {
		return err
	}

	// Store the certificate
	if err := cm.writeFileSecure(cm.certPath, certPEM, 0644); err != nil {
		return fmt.Errorf("failed to store certificate: %w", err)
	}

	// Store the CA certificate
	if err := cm.writeFileSecure(cm.caPath, caCertPEM, 0644); err != nil {
		return fmt.Errorf("failed to store CA certificate: %w", err)
	}

	// Store the private key in PKCS#8 PEM format
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	if err := cm.writeFileSecure(cm.keyPath, privateKeyPEM, 0600); err != nil {
		return fmt.Errorf("failed to store private key: %w", err)
	}

	cm.logger.Info("Successfully stored certificate, key, and CA certificate")
	return nil
}

// Sign signs the provided data using the stored private key and returns a base64-encoded signature
func (cm *CertificateManager) Sign(data []byte) (string, error) {
    // Load private key from file
    keyPEM, err := os.ReadFile(cm.keyPath)
    if err != nil {
        return "", fmt.Errorf("failed to read private key: %w", err)
    }
    block, _ := pem.Decode(keyPEM)
    if block == nil {
        return "", fmt.Errorf("failed to decode private key PEM")
    }
    privAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
    if err != nil {
        return "", fmt.Errorf("failed to parse private key: %w", err)
    }
    priv, ok := privAny.(ed25519.PrivateKey)
    if !ok {
        return "", fmt.Errorf("private key is not ed25519")
    }
    sig := ed25519.Sign(priv, data)
    return base64.StdEncoding.EncodeToString(sig), nil
}

// RemoveCertificate removes all certificate files.
func (cm *CertificateManager) RemoveCertificate() error {
	files := []string{cm.certPath, cm.keyPath, cm.caPath}
	
	for _, file := range files {
		if cm.fileExists(file) {
			if err := os.Remove(file); err != nil {
				cm.logger.Error("Failed to remove certificate file", "file", file, "error", err)
				return fmt.Errorf("failed to remove certificate file %s: %w", file, err)
			}
		}
	}

	cm.logger.Info("Removed all certificate files")
	return nil
}

// GetCertificateInfo returns information about the current certificate.
func (cm *CertificateManager) GetCertificateInfo() (*CertificateInfo, error) {
	if !cm.HasCertificate() {
		return nil, fmt.Errorf("no certificate found")
	}

	certPEM, err := os.ReadFile(cm.certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate: %w", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	info := &CertificateInfo{
		Subject:     cert.Subject.String(),
		Issuer:      cert.Issuer.String(),
		SerialNumber: cert.SerialNumber.String(),
		NotBefore:   cert.NotBefore,
		NotAfter:    cert.NotAfter,
		DNSNames:    cert.DNSNames,
	}

	return info, nil
}

// CertificateInfo holds information about a certificate.
type CertificateInfo struct {
	Subject      string
	Issuer       string
	SerialNumber string
	NotBefore    time.Time
	NotAfter     time.Time
	DNSNames     []string
}

// fileExists checks if a file exists.
func (cm *CertificateManager) fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

// writeFileSecure writes data to a file with specific permissions.
func (cm *CertificateManager) writeFileSecure(filename string, data []byte, perm os.FileMode) error {
	// Write to a temporary file first, then move to prevent partial writes
	tempFile := filename + ".tmp"
	
	if err := os.WriteFile(tempFile, data, perm); err != nil {
		return err
	}
	
	return os.Rename(tempFile, filename)
}

// TestCertificateData contains test certificate data for testing
type TestCertificateData struct {
	CertPEM string
	KeyPEM  string
	CAPEM   string
}

// GenerateTestCertificates generates test certificates for mTLS testing
func GenerateTestCertificates() (*TestCertificateData, error) {
	// Generate CA private key
	caPubKey, caPrivKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA private key: %w", err)
	}
	_ = caPubKey // unused

	// Create CA certificate template
	caTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"Test CA"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"Test"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour), // Valid for 24 hours
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// Create CA certificate
	caCertDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, caPrivKey.Public(), caPrivKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create CA certificate: %w", err)
	}

	// Generate client private key
	clientPubKey, clientPrivKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate client private key: %w", err)
	}
	_ = clientPubKey // unused

	// Create client certificate template
	clientTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization:  []string{"Test Client"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"Test"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour), // Valid for 24 hours
		SubjectKeyId: []byte{1, 2, 3, 4, 5},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	// Create client certificate
	clientCertDER, err := x509.CreateCertificate(rand.Reader, &clientTemplate, &caTemplate, clientPrivKey.Public(), caPrivKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create client certificate: %w", err)
	}

	// Encode CA certificate to PEM
	caCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCertDER,
	})

	// Encode client certificate to PEM
	clientCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: clientCertDER,
	})

	// Encode client private key to PEM
	clientKeyDER, err := x509.MarshalPKCS8PrivateKey(clientPrivKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal client private key: %w", err)
	}

	clientKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: clientKeyDER,
	})

	return &TestCertificateData{
		CertPEM: string(clientCertPEM),
		KeyPEM:  string(clientKeyPEM),
		CAPEM:   string(caCertPEM),
	}, nil
}

// NewTestCertificateManager creates a certificate manager with test certificates
func NewTestCertificateManager(certDir string, logger *logger.Logger) (*CertificateManager, error) {
	cm := NewCertificateManager(certDir, logger)

	// Generate test certificates
	testCerts, err := GenerateTestCertificates()
	if err != nil {
		return nil, fmt.Errorf("failed to generate test certificates: %w", err)
	}

	// Create certificate directory
	if err := os.MkdirAll(certDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create cert directory: %w", err)
	}

	// Write test certificates to files
	if err := cm.writeFileSecure(cm.certPath, []byte(testCerts.CertPEM), 0644); err != nil {
		return nil, fmt.Errorf("failed to write test certificate: %w", err)
	}

	if err := cm.writeFileSecure(cm.keyPath, []byte(testCerts.KeyPEM), 0600); err != nil {
		return nil, fmt.Errorf("failed to write test private key: %w", err)
	}

	if err := cm.writeFileSecure(cm.caPath, []byte(testCerts.CAPEM), 0644); err != nil {
		return nil, fmt.Errorf("failed to write test CA certificate: %w", err)
	}

	return cm, nil
}
