package services

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"outlap-agent-go/internal/config"
	"outlap-agent-go/internal/update"
	"outlap-agent-go/pkg/logger"
	"outlap-agent-go/pkg/types"
)

type updateService struct {
	config           *config.Config
	logger           *logger.Logger
	commandService   CommandService
	httpClient       *http.Client
	validator        *update.Validator
	rand             *rand.Rand
	loopMu           sync.Mutex
	stopChan         chan struct{}
	updateInProgress bool
	lastETag         string // ETag from backend manifest for caching
}

func NewUpdateService(cfg *config.Config, logger *logger.Logger, commandService CommandService) UpdateService {
	validator, err := update.NewValidator()
	if err != nil {
		logger.Error("Failed to initialize update validator", "error", err)
	}

	if err := update.SetCurrentVersionFromString(config.GetVersionString()); err != nil {
		logger.Warn("Failed to parse embedded version metadata", "version", config.GetVersionString(), "error", err)
	}

	return &updateService{
		config:         cfg,
		logger:         logger,
		commandService: commandService,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		validator: validator,
		rand:      rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func (s *updateService) CheckForUpdate(ctx context.Context) (*types.UpdateMetadata, error) {
	// Construct manifest URL from APIBaseURL (same URL used for registration)
	if s.config.APIBaseURL == "" {
		return nil, fmt.Errorf("API base URL not configured")
	}

	manifestURL := s.config.APIBaseURL + "/api/agent/updates/manifest"
	return s.checkForUpdateFromBackend(ctx, manifestURL)
}

// checkForUpdateFromBackend checks for updates using the backend manifest endpoint
func (s *updateService) checkForUpdateFromBackend(ctx context.Context, manifestURL string) (*types.UpdateMetadata, error) {
	currentVersion := update.GetCurrentVersion()
	s.logger.Info("Checking for updates from backend", "current", currentVersion.String(), "url", manifestURL)

	metadata, err := s.fetchBackendManifest(ctx, manifestURL)
	if err != nil {
		s.logger.Error("Failed to fetch update manifest from backend", "error", err)
		return nil, err
	}

	// Parse latest version
	latestVersion, err := update.ParseVersion(metadata.Version)
	if err != nil {
		return nil, fmt.Errorf("failed to parse latest version '%s': %w", metadata.Version, err)
	}

	if !currentVersion.LessThan(latestVersion) {
		s.logger.Info("Agent is up to date", "current", currentVersion.String(), "latest", latestVersion.String())
		return nil, nil
	}

	s.logger.Info("Update available", "current", currentVersion.String(), "latest", latestVersion.String())
	return metadata, nil
}

// artifactName returns the platform-specific artifact name for GitHub downloads
func (s *updateService) artifactName() string {
	return fmt.Sprintf("outlap-agent_%s_%s", runtime.GOOS, runtime.GOARCH)
}

func (s *updateService) ensureValidator() (*update.Validator, error) {
	if s.validator != nil {
		return s.validator, nil
	}

	validator, err := update.NewValidator()
	if err != nil {
		return nil, err
	}

	s.validator = validator
	return validator, nil
}

func (s *updateService) decorateRequest(req *http.Request, accept string) {
	if accept == "" {
		accept = "application/vnd.github+json"
	}
	req.Header.Set("Accept", accept)
	req.Header.Set("User-Agent", fmt.Sprintf("Outlap-Agent-Go/%s", config.GetVersionString()))
}

func (s *updateService) DownloadUpdate(ctx context.Context, metadata *types.UpdateMetadata) (string, error) {
	if metadata == nil {
		return "", fmt.Errorf("update metadata is required")
	}
	if metadata.DownloadURL == "" {
		return "", fmt.Errorf("update metadata missing download url")
	}

	s.logger.Info("Downloading update", "version", metadata.Version, "url", metadata.DownloadURL)

	// Create temp directory for update
	tempDir, err := os.MkdirTemp("", "outlap-update-*")
	if err != nil {
		return "", fmt.Errorf("failed to create temp directory: %w", err)
	}

	// Download update file
	updateFile := filepath.Join(tempDir, fmt.Sprintf("outlap-agent_%s_%s_%s",
		metadata.Version, runtime.GOOS, runtime.GOARCH))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metadata.DownloadURL, nil)
	if err != nil {
		os.RemoveAll(tempDir)
		return "", fmt.Errorf("failed to create download request: %w", err)
	}

	s.decorateRequest(req, "application/octet-stream")

	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		os.RemoveAll(tempDir)
		return "", fmt.Errorf("failed to download update: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		os.RemoveAll(tempDir)
		return "", fmt.Errorf("download failed with status: %d", resp.StatusCode)
	}

	// Create update file
	out, err := os.Create(updateFile)
	if err != nil {
		os.RemoveAll(tempDir)
		return "", fmt.Errorf("failed to create update file: %w", err)
	}
	defer out.Close()

	// Copy download to file
	if _, err := io.Copy(out, resp.Body); err != nil {
		os.RemoveAll(tempDir)
		return "", fmt.Errorf("failed to save update file: %w", err)
	}

	s.logger.Info("Update downloaded successfully", "path", updateFile)
	return updateFile, nil
}

func (s *updateService) ValidateUpdate(ctx context.Context, filePath string, metadata *types.UpdateMetadata) error {
	if metadata == nil {
		return fmt.Errorf("update metadata is required")
	}

	if metadata.ChecksumManifest == "" || metadata.Signature == "" {
		return fmt.Errorf("update metadata missing checksum signature information")
	}

	validator, err := s.ensureValidator()
	if err != nil {
		return fmt.Errorf("failed to initialize validator: %w", err)
	}

	if err := validator.VerifySignature([]byte(metadata.ChecksumManifest), metadata.Signature); err != nil {
		return fmt.Errorf("checksum signature verification failed: %w", err)
	}
	s.logger.Info("Validating update", "file", filePath)

	if err := update.VerifyFileHash(filePath, metadata.SHA256); err != nil {
		return err
	}

	s.logger.Info("Update validation successful")
	return nil
}

func (s *updateService) ApplyUpdate(ctx context.Context, metadata *types.UpdateMetadata, opts *types.UpdateApplyOptions) error {
	if metadata == nil {
		return fmt.Errorf("update metadata is required")
	}

	if s.updateInProgress {
		return fmt.Errorf("update already in progress")
	}

	s.updateInProgress = true
	defer func() { s.updateInProgress = false }()

	s.logger.Info("Applying update", "version", metadata.Version)

	// Download the update first
	updateFile, err := s.DownloadUpdate(ctx, metadata)
	if err != nil {
		return fmt.Errorf("failed to download update: %w", err)
	}
	defer os.RemoveAll(filepath.Dir(updateFile))

	// Validate the update
	if err := s.ValidateUpdate(ctx, updateFile, metadata); err != nil {
		return fmt.Errorf("update validation failed: %w", err)
	}

	// Write update request for systemd path-triggered updater
	return s.triggerSystemdUpdate(ctx, metadata, updateFile)
}

// triggerSystemdUpdate prepares update files and triggers systemd path-based updater
func (s *updateService) triggerSystemdUpdate(ctx context.Context, metadata *types.UpdateMetadata, filePath string) error {
	// Extract the update archive to staging directory
	stagingDir := "/var/lib/outlap"
	if err := os.MkdirAll(stagingDir, 0755); err != nil {
		return fmt.Errorf("failed to create staging directory: %w", err)
	}

	// Extract archive
	if err := s.extractArchive(filePath, stagingDir); err != nil {
		return fmt.Errorf("failed to extract update: %w", err)
	}

	newBinary := filepath.Join(stagingDir, "outlap-agent")
	if _, err := os.Stat(newBinary); err != nil {
		return fmt.Errorf("new binary not found in archive: %w", err)
	}

	// Move binary to staging location expected by updater
	stagingBinary := filepath.Join(stagingDir, "outlap-agent.new")
	if err := os.Rename(newBinary, stagingBinary); err != nil {
		return fmt.Errorf("failed to move binary to staging: %w", err)
	}

	if err := os.Chmod(stagingBinary, 0755); err != nil {
		return fmt.Errorf("failed to set executable permissions: %w", err)
	}

	// Write checksum file
	checksumFile := stagingBinary + ".sha256"
	if err := os.WriteFile(checksumFile, []byte(metadata.SHA256+"  outlap-agent.new\n"), 0644); err != nil {
		return fmt.Errorf("failed to write checksum file: %w", err)
	}

	// Write signature file
	signatureFile := checksumFile + ".sig"
	if err := os.WriteFile(signatureFile, []byte(metadata.Signature), 0644); err != nil {
		return fmt.Errorf("failed to write signature file: %w", err)
	}

	// Trigger systemd path watcher by writing update request
	updateRequestPath := "/run/outlap/update.request"
	if err := os.MkdirAll(filepath.Dir(updateRequestPath), 0755); err != nil {
		return fmt.Errorf("failed to create run directory: %w", err)
	}

	// Write download URL to request file (in case updater needs to re-fetch)
	updateRequest := fmt.Sprintf("version=%s\nurl=%s\nchecksum=%s\n",
		metadata.Version, metadata.DownloadURL, metadata.SHA256)
	if err := os.WriteFile(updateRequestPath, []byte(updateRequest), 0644); err != nil {
		return fmt.Errorf("failed to write update request: %w", err)
	}

	s.logger.Info("Systemd updater triggered", "version", metadata.Version, "staging", stagingBinary)
	return nil
}

func (s *updateService) StartAutoUpdateLoop(ctx context.Context) error {
	if !s.config.UpdateEnabled {
		s.logger.Info("Auto-update is disabled")
		return nil
	}

	s.loopMu.Lock()
	defer s.loopMu.Unlock()

	if s.stopChan != nil {
		s.logger.Debug("Auto-update loop already running")
		return nil
	}

	stopChan := make(chan struct{})
	s.stopChan = stopChan

	go s.runAutoUpdateLoop(ctx, stopChan)

	return nil
}

func (s *updateService) StopAutoUpdateLoop() error {
	s.loopMu.Lock()
	defer s.loopMu.Unlock()

	if s.stopChan == nil {
		return nil
	}

	close(s.stopChan)
	s.stopChan = nil
	return nil
}

func (s *updateService) runAutoUpdateLoop(ctx context.Context, stop <-chan struct{}) {
	s.performUpdateCheck(ctx)

	for {
		interval := s.computeNextInterval()
		timer := time.NewTimer(interval)
		s.logger.Debug("Scheduled next update check", "interval", interval)

		select {
		case <-timer.C:
			timer.Stop()
			s.performUpdateCheck(ctx)
		case <-stop:
			timer.Stop()
			return
		case <-ctx.Done():
			timer.Stop()
			return
		}
	}
}

func (s *updateService) computeNextInterval() time.Duration {
	intervalHours := s.config.UpdateIntervalHours
	if intervalHours <= 0 {
		// Backend polling: 3-5 minutes with jitter
		base := 4 * time.Minute         // 4 minutes base
		jitterWindow := 1 * time.Minute // ±1 minute jitter (3-5 minute range)

		var jitter time.Duration
		if s.rand != nil {
			rangeN := int64(jitterWindow * 2)
			if rangeN > 0 {
				jitter = time.Duration(s.rand.Int63n(rangeN)) - jitterWindow
			}
		}

		return base + jitter
	}

	base := time.Duration(intervalHours) * time.Hour
	if base < time.Hour {
		base = time.Hour
	}

	jitterWindow := base / 5
	if jitterWindow < 5*time.Minute {
		jitterWindow = 5 * time.Minute
	}

	var jitter time.Duration
	if s.rand != nil && jitterWindow > 0 {
		rangeN := int64(jitterWindow * 2)
		if rangeN > 0 {
			jitter = time.Duration(s.rand.Int63n(rangeN)) - jitterWindow
		}
	}

	next := base + jitter
	if next < time.Hour {
		next = time.Hour
	}

	return next
}

// Helper methods
func (s *updateService) performUpdateCheck(ctx context.Context) {
	metadata, err := s.CheckForUpdate(ctx)
	if err != nil {
		s.logger.Error("Update check failed", "error", err)
		return
	}

	if metadata == nil {
		// No update available
		return
	}

	if !s.config.UpdateAutoApply {
		s.logger.Info("Update available but auto-apply is disabled", "version", metadata.Version)
		// TODO: Send notification to server about available update
		return
	}

	// Apply update (downloads and validates internally)
	if err := s.ApplyUpdate(ctx, metadata, nil); err != nil {
		s.logger.Error("Failed to apply update", "error", err)
		return
	}
}

func (s *updateService) extractArchive(archivePath, destDir string) error {
	file, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer file.Close()

	gzr, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		target := filepath.Join(destDir, header.Name)

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0755); err != nil {
				return err
			}
		case tar.TypeReg:
			file, err := os.OpenFile(target, os.O_CREATE|os.O_RDWR, os.FileMode(header.Mode))
			if err != nil {
				return err
			}

			if _, err := io.Copy(file, tr); err != nil {
				file.Close()
				return err
			}

			file.Close()
		}
	}

	return nil
}

// fetchBackendManifest fetches the update manifest from the backend endpoint
func (s *updateService) fetchBackendManifest(ctx context.Context, manifestURL string) (*types.UpdateMetadata, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, manifestURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create backend manifest request: %w", err)
	}

	// Add caching headers
	if s.lastETag != "" {
		req.Header.Set("If-None-Match", s.lastETag)
	}
	req.Header.Set("User-Agent", fmt.Sprintf("Outlap-Agent-Go/%s", config.GetVersionString()))

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch backend manifest: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotModified:
		// No changes, cached data is still valid
		s.logger.Debug("Backend manifest unchanged")
		return nil, nil
	case http.StatusOK:
		// New data available
		break
	default:
		return nil, fmt.Errorf("backend manifest returned status %d", resp.StatusCode)
	}

	// Store ETag for future requests
	s.lastETag = resp.Header.Get("ETag")

	// Parse response
	var backendManifest struct {
		Version string `json:"version"`
		BaseURL string `json:"base_url"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&backendManifest); err != nil {
		return nil, fmt.Errorf("failed to decode backend manifest: %w", err)
	}

	// Validate required fields
	if backendManifest.Version == "" || backendManifest.BaseURL == "" {
		return nil, fmt.Errorf("backend manifest missing required fields")
	}

	// Construct platform-specific URLs
	// Example: {base_url}/outlap-agent_linux_amd64
	platform := fmt.Sprintf("%s_%s", runtime.GOOS, runtime.GOARCH)
	binaryURL := fmt.Sprintf("%s/outlap-agent_%s", backendManifest.BaseURL, platform)
	checksumURL := fmt.Sprintf("%s/outlap-agent_%s.sha256", backendManifest.BaseURL, platform)
	signatureURL := fmt.Sprintf("%s/outlap-agent_%s.sha256.sig", backendManifest.BaseURL, platform)

	s.logger.Info("Fetching update assets from backend-provided URLs",
		"version", backendManifest.Version,
		"binary_url", binaryURL)

	// Download and parse checksum and signature files
	manifestContent, checksum, signature, err := s.fetchChecksumAndSignature(ctx, checksumURL, signatureURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch checksum/signature: %w", err)
	}

	// Convert to internal metadata format
	metadata := &types.UpdateMetadata{
		Version:          backendManifest.Version,
		DownloadURL:      binaryURL,
		SHA256:           checksum,
		Signature:        signature,
		ChecksumManifest: manifestContent, // Use full manifest content as signed by release pipeline
		Changelog:        "",              // Not provided by backend manifest
	}

	return metadata, nil
}

// fetchChecksumAndSignature downloads and parses the platform-specific checksum and signature files
// Returns the full checksum manifest content, parsed checksum value, and signature
func (s *updateService) fetchChecksumAndSignature(ctx context.Context, checksumURL, signatureURL string) (string, string, string, error) {
	// Fetch checksum file
	checksumReq, err := http.NewRequestWithContext(ctx, http.MethodGet, checksumURL, nil)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to create checksum request: %w", err)
	}
	s.decorateRequest(checksumReq, "")

	checksumResp, err := s.httpClient.Do(checksumReq)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to fetch checksum: %w", err)
	}
	defer checksumResp.Body.Close()

	if checksumResp.StatusCode != http.StatusOK {
		return "", "", "", fmt.Errorf("checksum download returned status %d", checksumResp.StatusCode)
	}

	// Read checksum file (small file, ~91 bytes)
	checksumBytes, err := io.ReadAll(checksumResp.Body)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to read checksum: %w", err)
	}

	// Parse checksum (format: "hash  filename" or just "hash")
	checksumStr := strings.TrimSpace(string(checksumBytes))
	checksumFields := strings.Fields(checksumStr)
	if len(checksumFields) == 0 {
		return "", "", "", fmt.Errorf("invalid checksum format")
	}
	checksum := checksumFields[0]

	// Fetch signature file
	sigReq, err := http.NewRequestWithContext(ctx, http.MethodGet, signatureURL, nil)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to create signature request: %w", err)
	}
	s.decorateRequest(sigReq, "")

	sigResp, err := s.httpClient.Do(sigReq)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to fetch signature: %w", err)
	}
	defer sigResp.Body.Close()

	if sigResp.StatusCode != http.StatusOK {
		return "", "", "", fmt.Errorf("signature download returned status %d", sigResp.StatusCode)
	}

	// Read signature file (small file, ~88 bytes)
	signatureBytes, err := io.ReadAll(sigResp.Body)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to read signature: %w", err)
	}

	signature := strings.TrimSpace(string(signatureBytes))

	return string(checksumBytes), checksum, signature, nil
}
