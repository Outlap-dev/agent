// Package security provides certificate renewal functionality.
package security

import (
    "bytes"
    "crypto/tls"
    "crypto/x509"
    "encoding/pem"
    "encoding/json"
    "fmt"
    "io"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"

	"pulseup-agent-go/pkg/logger"
)

// CertificateRenewer handles certificate renewal operations.
type CertificateRenewer struct {
	apiURL      string
	certManager *CertificateManager
	logger      *logger.Logger
	httpClient  *http.Client
}

// RenewalRequest represents a certificate renewal request.
type RenewalRequest struct {
	CSRPEM        string `json:"csr_pem"`
	CurrentSerial string `json:"current_serial"`
}

// RenewalResponse represents a certificate renewal response.
type RenewalResponse struct {
	Success             bool   `json:"success"`
	CertificatePEM      string `json:"certificate_pem"`
	CertificateMetadata struct {
		SerialNumber string `json:"serial_number"`
		NotBefore    string `json:"not_before"`
		NotAfter     string `json:"not_after"`
		Fingerprint  string `json:"fingerprint"`
	} `json:"certificate_metadata"`
	Error string `json:"error,omitempty"`
}

// NewCertificateRenewer creates a new certificate renewer.
func NewCertificateRenewer(apiURL string, certManager *CertificateManager, logger *logger.Logger) *CertificateRenewer {
	return &CertificateRenewer{
		apiURL:      apiURL,
		certManager: certManager,
		logger:      logger.With("component", "cert_renewer"),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// StartRenewalLoop starts the certificate renewal loop.
func (r *CertificateRenewer) StartRenewalLoop(stopChan <-chan struct{}) {
	r.logger.Info("Starting certificate renewal loop")

	ticker := time.NewTicker(time.Hour) // Check every hour
	defer ticker.Stop()

	// Check immediately on start
	r.checkAndRenew()

	for {
		select {
		case <-ticker.C:
			r.checkAndRenew()
		case <-stopChan:
			r.logger.Info("Certificate renewal loop stopped")
			return
		}
	}
}

// checkAndRenew checks if renewal is needed and performs it.
func (r *CertificateRenewer) checkAndRenew() {
	shouldRenew, err := r.certManager.ShouldRenew()
	if err != nil {
		r.logger.Error("Failed to check if certificate should be renewed", "error", err)
		return
	}

	if !shouldRenew {
		r.logger.Debug("Certificate renewal not needed yet")
		return
	}

	// Add jitter to avoid thundering herd
	jitter := time.Duration(rand.Intn(3600)) * time.Second // 0-1 hour jitter
	r.logger.Info("Certificate renewal needed, waiting for jitter", "jitter", jitter)
	time.Sleep(jitter)

	if err := r.RenewCertificate(); err != nil {
		r.logger.Error("Failed to renew certificate", "error", err)
	}
}

// RenewCertificate performs certificate renewal.
func (r *CertificateRenewer) RenewCertificate() error {
	r.logger.Info("Starting certificate renewal")

	// Get current certificate info
	certInfo, err := r.certManager.GetCertificateInfo()
	if err != nil {
		return fmt.Errorf("failed to get current certificate info: %w", err)
	}

	// Load current certificate to extract server UID
	cert, err := r.certManager.LoadCertificate()
	if err != nil {
		return fmt.Errorf("failed to load current certificate: %w", err)
	}

	// Parse certificate to get server UID from subject or SAN
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	serverUID := r.extractServerUIDFromCertificate(x509Cert)
	if serverUID == "" {
		return fmt.Errorf("failed to extract server UID from certificate")
	}

	// Generate new key pair (rotate the key)
	_, privateKey, err := r.certManager.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate new key pair: %w", err)
	}

	// Create CSR with new key
	csrPEM, err := r.certManager.CreateCSR(privateKey, serverUID)
	if err != nil {
		return fmt.Errorf("failed to create CSR: %w", err)
	}

	// Send renewal request
	response, err := r.sendRenewalRequest(csrPEM, certInfo.SerialNumber)
	if err != nil {
		return fmt.Errorf("renewal request failed: %w", err)
	}

	if !response.Success {
		return fmt.Errorf("renewal failed: %s", response.Error)
	}

	// Get CA certificate in PEM format
	caCertPEM, err := r.getCACertificatePEM()
	if err != nil {
		return fmt.Errorf("failed to get CA certificate PEM: %w", err)
	}

	err = r.certManager.StoreCertificate(
		[]byte(response.CertificatePEM),
		caCertPEM,
		privateKey,
	)
	if err != nil {
		return fmt.Errorf("failed to store renewed certificate: %w", err)
	}

	r.logger.Info("Certificate renewed successfully",
		"old_serial", certInfo.SerialNumber,
		"new_serial", response.CertificateMetadata.SerialNumber,
		"not_before", response.CertificateMetadata.NotBefore,
		"not_after", response.CertificateMetadata.NotAfter)

	return nil
}

// sendRenewalRequest sends the renewal request to the server using mTLS.
func (r *CertificateRenewer) sendRenewalRequest(csrPEM []byte, currentSerial string) (*RenewalResponse, error) {
	request := RenewalRequest{
		CSRPEM:        string(csrPEM),
		CurrentSerial: currentSerial,
	}

	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create HTTPS client with mTLS
	client, err := r.createMTLSClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create mTLS client: %w", err)
	}

    url := r.apiURL + "/api/agent/renew"
    req, err := http.NewRequest("POST", url, bytes.NewBuffer(requestBody))
    if err != nil {
        return nil, fmt.Errorf("failed to create request: %w", err)
    }

    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("User-Agent", "PulseUp-Agent/1.0")

    // Include client certificate PEM in header for proxies that terminate TLS
    // so the backend can still verify the caller at application layer
    if cert, err := r.certManager.LoadCertificate(); err == nil && len(cert.Certificate) > 0 {
        pemBlock := &pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}
        pemBytes := pem.EncodeToMemory(pemBlock)
        req.Header.Set("X-Client-Certificate", string(pemBytes))
    }

	r.logger.Debug("Sending renewal request via mTLS", "url", url)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("renewal request failed with status %d: %s", resp.StatusCode, string(responseBody))
	}

	var response RenewalResponse
	if err := json.Unmarshal(responseBody, &response); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &response, nil
}

// createMTLSClient creates an HTTP client configured for mTLS.
func (r *CertificateRenewer) createMTLSClient() (*http.Client, error) {
	// Load client certificate
	cert, err := r.certManager.LoadCertificate()
	if err != nil {
		return nil, fmt.Errorf("failed to load client certificate: %w", err)
	}

	// Load CA certificate
	caCertPool, err := r.certManager.LoadCACertificate()
	if err != nil {
		return nil, fmt.Errorf("failed to load CA certificate: %w", err)
	}

	// Create TLS configuration
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
		MinVersion:   tls.VersionTLS13,
	}

	// Create HTTP client with custom transport
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}, nil
}

// getCACertificatePEM returns the CA certificate in PEM format.
func (r *CertificateRenewer) getCACertificatePEM() ([]byte, error) {
	// Read the CA certificate file
	return r.certManager.LoadCACertificateRaw()
}

// extractServerUIDFromCertificate extracts the server UID from a certificate.
func (r *CertificateRenewer) extractServerUIDFromCertificate(cert *x509.Certificate) string {
	// Try to extract from DNS names first
	for _, dnsName := range cert.DNSNames {
		if len(dnsName) > 6 && dnsName[:6] == "agent-" {
			// Extract UID from "agent-{uid}.pulseup.local" format
			if idx := strings.Index(dnsName, "."); idx > 6 {
				return dnsName[6:idx]
			}
			// Or from "agent-{uid}" format
			return dnsName[6:]
		}
		// Check if it's just the UID
		if !strings.Contains(dnsName, ".") {
			return dnsName
		}
	}

	// Try to extract from Common Name
	cn := cert.Subject.CommonName
	if len(cn) > 6 && cn[:6] == "agent-" {
		return cn[6:]
	}

	return ""
}

// LoadCACertificateRaw loads the CA certificate as raw bytes.
func (cm *CertificateManager) LoadCACertificateRaw() ([]byte, error) {
	if !cm.fileExists(cm.caPath) {
		return nil, fmt.Errorf("CA certificate file not found")
	}

	return os.ReadFile(cm.caPath)
}
