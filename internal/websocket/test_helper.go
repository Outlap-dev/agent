package websocket

import (
	"context"
	"encoding/pem"
	"fmt"
	"os"
	"testing"
	"time"

	"pulseup-agent-go/internal/config"
	"pulseup-agent-go/internal/security"
	"pulseup-agent-go/internal/testws"
	"pulseup-agent-go/pkg/logger"
)

// TestHelper provides utilities for setting up mTLS-based WebSocket tests
type TestHelper struct {
	tempDir     string
	certManager *security.CertificateManager
	server      *testws.TestWebSocketServer
	config      *config.Config
	logger      *logger.Logger
}

// NewTestHelper creates a new test helper with certificates and test server
func NewTestHelper(t *testing.T) *TestHelper {
	// Create temporary directory for test certificates
	tempDir, err := os.MkdirTemp("", "pulseup-test-certs-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	logger := logger.New()

	// Create certificate manager with test certificates
	certManager, err := security.NewTestCertificateManager(tempDir, logger)
	if err != nil {
		os.RemoveAll(tempDir)
		t.Fatalf("Failed to create test certificate manager: %v", err)
	}

	// Create test WebSocket server
	server := testws.NewTestWebSocketServer("localhost:0", logger)

	// Create test configuration
	config := &config.Config{
		WebSocketURL:                 "", // Will be set after server starts
		ReconnectEnabled:             false, // Disable for simpler testing
		AuthWaitForConfirmation:      true,
		AuthPermanentFailureCooldown: 60,
		CertDir:                      tempDir,
	}

	return &TestHelper{
		tempDir:     tempDir,
		certManager: certManager,
		server:      server,
		config:      config,
		logger:      logger,
	}
}

// StartServer starts the test WebSocket server
func (h *TestHelper) StartServer(ctx context.Context) error {
	if err := h.server.Start(ctx); err != nil {
		return fmt.Errorf("failed to start test server: %w", err)
	}

	// Update config with server URL
	h.config.WebSocketURL = h.server.GetURL()

	// Give server time to start
	time.Sleep(50 * time.Millisecond)

	return nil
}

// CreateMTLSClient creates an MTLSClient configured for testing
func (h *TestHelper) CreateMTLSClient() interface{} {
	// Return a generic interface since MTLSClient might not be available in this package
	// This should be implemented when the client is properly imported
	return nil
}

// CreateManager creates a WebSocket manager configured for testing
func (h *TestHelper) CreateManager() *Manager {
	manager := NewManager(h.config, h.logger)

	// Configure the manager with certificate capabilities
	manager.SetCertificateProvider(func() (string, error) {
		cert, err := h.certManager.LoadCertificate()
		if err != nil {
			return "", err
		}
		if len(cert.Certificate) == 0 {
			return "", fmt.Errorf("no certificate loaded")
		}
		block := &pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}
		return string(pem.EncodeToMemory(block)), nil
	})

	manager.SetSigner(func(data []byte) (string, error) {
		return h.certManager.Sign(data)
	})

	return manager
}

// GetServer returns the test server
func (h *TestHelper) GetServer() *testws.TestWebSocketServer {
	return h.server
}

// GetConfig returns the test configuration
func (h *TestHelper) GetConfig() *config.Config {
	return h.config
}

// GetCertManager returns the certificate manager
func (h *TestHelper) GetCertManager() *security.CertificateManager {
	return h.certManager
}

// Cleanup cleans up test resources
func (h *TestHelper) Cleanup() {
	if h.server != nil {
		h.server.Stop()
	}
	if h.tempDir != "" {
		os.RemoveAll(h.tempDir)
	}
}

// WaitForConnection waits for a connection to be established
func (h *TestHelper) WaitForConnection(client interface{}, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		var connected bool

		switch c := client.(type) {
		case *Manager:
			connected = c.IsConnected()
		default:
			return fmt.Errorf("unsupported client type")
		}

		if connected {
			return nil
		}

		time.Sleep(10 * time.Millisecond)
	}

	return fmt.Errorf("connection timeout after %v", timeout)
}

// SetupTestWithCertificates sets up a complete test environment with certificates
func SetupTestWithCertificates(t *testing.T) (*TestHelper, context.Context, context.CancelFunc) {
	helper := NewTestHelper(t)

	ctx, cancel := context.WithCancel(context.Background())

	// Clean up on test completion
	t.Cleanup(func() {
		cancel()
		helper.Cleanup()
	})

	// Start server
	if err := helper.StartServer(ctx); err != nil {
		t.Fatalf("Failed to start test server: %v", err)
	}

	return helper, ctx, cancel
}