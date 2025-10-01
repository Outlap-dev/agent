package services

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"pulseup-agent-go/internal/config"
	"pulseup-agent-go/pkg/logger"
	"pulseup-agent-go/pkg/types"
)

const (
	// UpdateFlagFile is the path to the update flag file
	UpdateFlagFile = "/var/run/pulseup-agent/update-needed"
	// GitHubAPIURL is the base URL for GitHub API
	GitHubAPIURL = "https://api.github.com/repos"
)

// GitHubTag represents a GitHub tag from the API
type GitHubTag struct {
	Name string `json:"name"`
}

// versionCheckService implements VersionCheckService
type versionCheckService struct {
	config     *config.Config
	logger     *logger.Logger
	httpClient *http.Client
	stopChan   chan struct{}
	running    bool
}

// NewVersionCheckService creates a new version check service instance
func NewVersionCheckService(cfg *config.Config, logger *logger.Logger) VersionCheckService {
	return &versionCheckService{
		config: cfg,
		logger: logger.With("service", "version_check"),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		stopChan: make(chan struct{}),
	}
}

// Start begins the background version checking process exactly like Python
func (v *versionCheckService) Start(ctx context.Context) error {
	if !v.config.VersionCheckEnabled {
		v.logger.Info("Version checking is disabled")
		return nil
	}

	if v.running {
		v.logger.Debug("Version check service already running")
		return nil
	}

	v.running = true
	v.logger.Info("Starting version check service",
		"interval", v.config.VersionCheckInterval,
		"repo", v.config.VersionCheckRepo)

	// Start background goroutine for periodic checks
	go v.checkTask(ctx)

	return nil
}

// Stop stops the background version checking process
func (v *versionCheckService) Stop(ctx context.Context) error {
	if !v.running {
		return nil
	}

	v.logger.Info("Stopping version check service")
	v.running = false
	close(v.stopChan)
	return nil
}

// CheckVersion performs a single version check exactly like Python
func (v *versionCheckService) CheckVersion(ctx context.Context) (*types.VersionCheckResult, error) {
	currentVersion := config.GetVersionString()

	v.logger.Info("Checking for new version", "current", currentVersion)

	// Get latest version from GitHub
	latestVersion, err := v.getLatestVersion(ctx)
	if err != nil {
		v.logger.Error("Failed to get latest version", "error", err)
		return &types.VersionCheckResult{
			CurrentVersion: currentVersion,
			Error:          err.Error(),
		}, err
	}

	// Compare versions
	updateNeeded := config.IsNewerVersion(currentVersion, latestVersion)

	result := &types.VersionCheckResult{
		CurrentVersion: currentVersion,
		LatestVersion:  latestVersion,
		UpdateNeeded:   updateNeeded,
	}

	if updateNeeded {
		v.logger.Info("New version available",
			"current", currentVersion,
			"latest", latestVersion)
	} else {
		v.logger.Debug("Agent is up to date", "version", currentVersion)
	}

	return result, nil
}

// checkTask runs the background version checking loop exactly like Python
func (v *versionCheckService) checkTask(ctx context.Context) {
	ticker := time.NewTicker(time.Duration(v.config.VersionCheckInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			v.logger.Info("Version check task stopped due to context cancellation")
			return
		case <-v.stopChan:
			v.logger.Info("Version check task stopped")
			return
		case <-ticker.C:
			if err := v.performVersionCheck(ctx); err != nil {
				v.logger.Error("Version check failed", "error", err)
			}
		}
	}
}

// performVersionCheck performs a version check and handles updates exactly like Python
func (v *versionCheckService) performVersionCheck(ctx context.Context) error {
	result, err := v.CheckVersion(ctx)
	if err != nil {
		return err
	}

	if result.UpdateNeeded {
		v.logger.Info("Requesting agent update via flag file")
		if err := v.requestUpdate(); err != nil {
			v.logger.Error("Failed to request update", "error", err)
			return err
		}

		// Stop the service after requesting update (like Python)
		v.Stop(ctx)
	}

	return nil
}

// getLatestVersion fetches the latest version from GitHub API exactly like Python
func (v *versionCheckService) getLatestVersion(ctx context.Context) (string, error) {
	url := fmt.Sprintf("%s/%s/tags", GitHubAPIURL, v.config.VersionCheckRepo)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	// Add User-Agent header to avoid rate limiting
	req.Header.Set("User-Agent", "PulseUp-Agent-Go/"+config.GetVersionString())

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch GitHub tags: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	var tags []GitHubTag
	if err := json.Unmarshal(body, &tags); err != nil {
		return "", fmt.Errorf("failed to parse GitHub response: %w", err)
	}

	if len(tags) == 0 {
		return "", fmt.Errorf("no tags found in GitHub repository")
	}

	// Get the latest tag (first in the list)
	latestTag := tags[0].Name

	// Remove 'v' prefix if present
	if len(latestTag) > 0 && latestTag[0] == 'v' {
		latestTag = latestTag[1:]
	}

	return latestTag, nil
}

// requestUpdate creates the update flag file exactly like Python
func (v *versionCheckService) requestUpdate() error {
	// Ensure the directory exists
	flagDir := filepath.Dir(UpdateFlagFile)
	if err := os.MkdirAll(flagDir, 0755); err != nil {
		return fmt.Errorf("failed to create flag file directory: %w", err)
	}

	// Create the update flag file (empty file is sufficient as a flag)
	if err := os.WriteFile(UpdateFlagFile, []byte(""), 0644); err != nil {
		return fmt.Errorf("failed to create update flag file: %w", err)
	}

	v.logger.Info("Update flag file created", "file", UpdateFlagFile)
	return nil
}
