// Package enrollment handles agent enrollment with join tokens.
package enrollment

import (
    "context"
    "bytes"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "time"

    "pulseup-agent-go/internal/security"
    "pulseup-agent-go/pkg/logger"
    "pulseup-agent-go/pkg/types"
)

// Enroller handles the agent enrollment process.
type Enroller struct {
    apiURL      string
    joinToken   string
    certManager *security.CertificateManager
    logger      *logger.Logger
    httpClient  *http.Client
    sysProvider SystemInfoProvider
}

// Config holds the enrollment configuration.
type Config struct {
    APIURL      string
    JoinToken   string
    CertDir     string
    Timeout     time.Duration
}

// SystemInfoProvider provides hardware info collection without importing services
type SystemInfoProvider interface {
    GetHardwareInfo(ctx context.Context) (*types.HardwareInfo, error)
}

// EnrollmentRequest represents the enrollment request payload.
type EnrollmentRequest struct {
	JoinToken    string                 `json:"join_token"`
	CSRPEM       string                 `json:"csr_pem"`
	HardwareInfo map[string]interface{} `json:"hardware_info"`
}

// EnrollmentResponse represents the enrollment response.
type EnrollmentResponse struct {
	Success           bool   `json:"success"`
	ServerUID         string `json:"server_uid"`
	CertificatePEM    string `json:"certificate_pem"`
	CACertificatePEM  string `json:"ca_certificate_pem"`
	RenewalEndpoint   string `json:"renewal_endpoint"`
	RenewalThreshold  float64 `json:"renewal_threshold"`
	CertificateMetadata struct {
		SerialNumber string `json:"serial_number"`
		NotBefore    string `json:"not_before"`
		NotAfter     string `json:"not_after"`
		Fingerprint  string `json:"fingerprint"`
	} `json:"certificate_metadata"`
	Error string `json:"error,omitempty"`
}

// NewEnroller creates a new enroller instance.
func NewEnroller(config Config, logger *logger.Logger, provider SystemInfoProvider) *Enroller {
	timeout := config.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	certManager := security.NewCertificateManager(config.CertDir, logger)

    return &Enroller{
        apiURL:      config.APIURL,
        joinToken:   config.JoinToken,
        certManager: certManager,
        logger:      logger.With("component", "enroller"),
        httpClient: &http.Client{
            Timeout: timeout,
        },
        sysProvider: provider,
    }
}

// Enroll performs the complete enrollment process.
func (e *Enroller) Enroll() (*EnrollmentResult, error) {
	e.logger.Info("Starting agent enrollment process")

	// Check if we already have valid certificates
	if e.certManager.HasCertificate() {
		shouldRenew, err := e.certManager.ShouldRenew()
		if err == nil && !shouldRenew {
			e.logger.Info("Valid certificate already exists, skipping enrollment")
			info, _ := e.certManager.GetCertificateInfo()
			return &EnrollmentResult{
				ServerUID: e.extractServerUIDFromCert(info),
				Enrolled:  false,
				Message:   "Already enrolled with valid certificate",
			}, nil
		}
		e.logger.Info("Existing certificate needs renewal, proceeding with enrollment")
	}

	// Step 1: Generate key pair
	e.logger.Info("Generating Ed25519 key pair")
	_, privateKey, err := e.certManager.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	// Step 2: Get hardware information
	e.logger.Info("Collecting hardware information")
	hardwareInfo, err := e.collectHardwareInfo()
	if err != nil {
		return nil, fmt.Errorf("failed to collect hardware info: %w", err)
	}

	// Step 3: Create CSR
	e.logger.Info("Creating certificate signing request")
	// We don't have a server UID yet, so use a temporary identifier
	tempUID := fmt.Sprintf("temp-%d", time.Now().Unix())
	csrPEM, err := e.certManager.CreateCSR(privateKey, tempUID)
	if err != nil {
		return nil, fmt.Errorf("failed to create CSR: %w", err)
	}

	// Step 4: Send enrollment request
	e.logger.Info("Sending enrollment request to server")
	response, err := e.sendEnrollmentRequest(csrPEM, hardwareInfo)
	if err != nil {
		return nil, fmt.Errorf("enrollment request failed: %w", err)
	}

	if !response.Success {
		return nil, fmt.Errorf("enrollment failed: %s", response.Error)
	}

	// Step 5: Store certificates
	e.logger.Info("Storing certificates", "server_uid", response.ServerUID)
	err = e.certManager.StoreCertificate(
		[]byte(response.CertificatePEM),
		[]byte(response.CACertificatePEM),
		privateKey,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to store certificates: %w", err)
	}

	e.logger.Info("Agent enrollment completed successfully", 
		"server_uid", response.ServerUID,
		"serial_number", response.CertificateMetadata.SerialNumber)

	return &EnrollmentResult{
		ServerUID:        response.ServerUID,
		SerialNumber:     response.CertificateMetadata.SerialNumber,
		NotBefore:        response.CertificateMetadata.NotBefore,
		NotAfter:         response.CertificateMetadata.NotAfter,
		RenewalEndpoint:  response.RenewalEndpoint,
		RenewalThreshold: response.RenewalThreshold,
		Enrolled:         true,
		Message:          "Successfully enrolled and received certificate",
	}, nil
}

// sendEnrollmentRequest sends the enrollment request to the server.
func (e *Enroller) sendEnrollmentRequest(csrPEM []byte, hardwareInfo map[string]interface{}) (*EnrollmentResponse, error) {
	request := EnrollmentRequest{
		JoinToken:    e.joinToken,
		CSRPEM:       string(csrPEM),
		HardwareInfo: hardwareInfo,
	}

	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	url := e.apiURL + "/api/agent/enroll"
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "PulseUp-Agent/1.0")

	e.logger.Debug("Sending enrollment request", "url", url)

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	e.logger.Debug("Received enrollment response", "status", resp.Status, "body_len", len(responseBody))

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("enrollment request failed with status %d: %s", resp.StatusCode, string(responseBody))
	}

	var response EnrollmentResponse
	if err := json.Unmarshal(responseBody, &response); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &response, nil
}

// collectHardwareInfo gathers system hardware information.
func (e *Enroller) collectHardwareInfo() (map[string]interface{}, error) {
    // Use provided system info provider to gather hardware info
    if e.sysProvider == nil {
        return nil, fmt.Errorf("system info provider is not configured")
    }
    info, err := e.sysProvider.GetHardwareInfo(context.Background())
    if err != nil {
        return nil, fmt.Errorf("failed to get hardware info: %w", err)
    }

    // Convert structured hardware info to a generic map for the enrollment payload
    var hwMap map[string]interface{}
    b, err := json.Marshal(info)
    if err != nil {
        return nil, fmt.Errorf("failed to marshal hardware info: %w", err)
    }
    if err := json.Unmarshal(b, &hwMap); err != nil {
        return nil, fmt.Errorf("failed to convert hardware info to map: %w", err)
    }
    return hwMap, nil
}

// EnrollmentResult contains the result of an enrollment attempt.
type EnrollmentResult struct {
	ServerUID        string
	SerialNumber     string
	NotBefore        string
	NotAfter         string
	RenewalEndpoint  string
	RenewalThreshold float64
	Enrolled         bool
	Message          string
}

// Helper methods removed in favor of SystemService collectors

func (e *Enroller) extractServerUIDFromCert(info *security.CertificateInfo) string {
	// Extract server UID from certificate subject or DNS names
	// This is a placeholder - implement based on certificate format
	return "existing-server-uid"
}
