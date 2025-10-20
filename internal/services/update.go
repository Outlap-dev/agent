package services

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
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

	"pulseup-agent-go/internal/config"
	"pulseup-agent-go/internal/ipc"
	"pulseup-agent-go/internal/update"
	"pulseup-agent-go/pkg/logger"
	"pulseup-agent-go/pkg/types"
)

type updateService struct {
	config           *config.Config
	logger           *logger.Logger
	commandService   CommandService
	httpClient       *http.Client
	validator        *update.Validator
	ipcClient        IPCClient
	repoOwner        string
	repoName         string
	apiBaseURL       string
	rand             *rand.Rand
	loopMu           sync.Mutex
	stopChan         chan struct{}
	updateInProgress bool
}

const githubAPIBase = "https://api.github.com"

var (
	errGitHubRateLimited = errors.New("github api rate limit exceeded")
	errNoMatchingAsset   = errors.New("no matching release asset found for current platform")
)

type githubTag struct {
	Name string `json:"name"`
}

type githubRelease struct {
	TagName     string               `json:"tag_name"`
	Body        string               `json:"body"`
	HTMLURL     string               `json:"html_url"`
	PublishedAt *time.Time           `json:"published_at"`
	Assets      []githubReleaseAsset `json:"assets"`
}

type githubReleaseAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

func NewUpdateService(cfg *config.Config, logger *logger.Logger, commandService CommandService, ipcClient IPCClient) UpdateService {
	validator, err := update.NewValidator(cfg.UpdatePublicKeyPath)
	if err != nil {
		logger.Error("Failed to initialize update validator", "error", err)
	}

	owner, repo, repoErr := parseRepositoryIdentifier(cfg.UpdateRepository)
	if repoErr != nil {
		logger.Error("Invalid update repository", "repository", cfg.UpdateRepository, "error", repoErr)
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
		validator:  validator,
		ipcClient:  ipcClient,
		repoOwner:  owner,
		repoName:   repo,
		apiBaseURL: githubAPIBase,
		rand:       rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func (s *updateService) CheckForUpdate(ctx context.Context) (*types.UpdateMetadata, error) {
	if s.repoOwner == "" || s.repoName == "" {
		return nil, fmt.Errorf("update repository not configured")
	}

	currentVersion := update.GetCurrentVersion()
	s.logger.Info("Checking for updates", "current", currentVersion.String())

	latestTag, err := s.fetchLatestTag(ctx)
	if err != nil {
		if errors.Is(err, errGitHubRateLimited) {
			s.logger.Warn("GitHub rate limit reached while checking for updates")
			return nil, nil
		}
		return nil, err
	}

	latestVersion, err := update.ParseVersion(latestTag)
	if err != nil {
		return nil, fmt.Errorf("failed to parse latest version '%s': %w", latestTag, err)
	}

	if !currentVersion.LessThan(latestVersion) {
		s.logger.Info("Agent is up to date", "current", currentVersion.String(), "latest", latestVersion.String())
		return nil, nil
	}

	metadata, err := s.prepareUpdateMetadata(ctx, latestTag, latestVersion)
	if err != nil {
		return nil, err
	}

	s.logger.Info("Update available", "current", currentVersion.String(), "latest", latestVersion.String())
	return metadata, nil
}

func (s *updateService) fetchLatestTag(ctx context.Context) (string, error) {
	base := s.apiBaseURL
	if base == "" {
		base = githubAPIBase
	}
	url := fmt.Sprintf("%s/repos/%s/%s/tags?per_page=1", base, s.repoOwner, s.repoName)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create GitHub tag request: %w", err)
	}

	s.decorateRequest(req, "")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch tags from GitHub: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", s.githubAPIError(resp)
	}

	var tags []githubTag
	if err := json.NewDecoder(resp.Body).Decode(&tags); err != nil {
		return "", fmt.Errorf("failed to decode GitHub tags response: %w", err)
	}

	if len(tags) == 0 {
		return "", fmt.Errorf("no tags found in repository %s/%s", s.repoOwner, s.repoName)
	}

	return tags[0].Name, nil
}

func (s *updateService) fetchReleaseByTag(ctx context.Context, tag string) (*githubRelease, error) {
	base := s.apiBaseURL
	if base == "" {
		base = githubAPIBase
	}
	url := fmt.Sprintf("%s/repos/%s/%s/releases/tags/%s", base, s.repoOwner, s.repoName, tag)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create GitHub release request: %w", err)
	}

	s.decorateRequest(req, "")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch release from GitHub: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, s.githubAPIError(resp)
	}

	var release githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, fmt.Errorf("failed to decode GitHub release response: %w", err)
	}

	return &release, nil
}

func (s *updateService) prepareUpdateMetadata(ctx context.Context, tag string, latestVersion update.Version) (*types.UpdateMetadata, error) {
	release, err := s.fetchReleaseByTag(ctx, tag)
	if err != nil {
		return nil, err
	}

	artifactName := s.artifactName()
	binaryAsset, checksumAsset, signatureAsset := findReleaseAssets(artifactName, release.Assets)
	if binaryAsset == nil || checksumAsset == nil || signatureAsset == nil {
		return nil, fmt.Errorf("%w (%s)", errNoMatchingAsset, artifactName)
	}

	manifest, err := s.downloadTextAsset(ctx, *checksumAsset)
	if err != nil {
		return nil, fmt.Errorf("failed to download checksum manifest: %w", err)
	}
	manifest = strings.TrimSpace(manifest)
	if manifest == "" {
		return nil, fmt.Errorf("checksum manifest is empty")
	}

	signature, err := s.downloadTextAsset(ctx, *signatureAsset)
	if err != nil {
		return nil, fmt.Errorf("failed to download checksum signature: %w", err)
	}
	signature = strings.TrimSpace(signature)
	if signature == "" {
		return nil, fmt.Errorf("checksum signature is empty")
	}

	validator, err := s.ensureValidator()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize validator: %w", err)
	}

	if err := validator.VerifySignature([]byte(manifest), signature); err != nil {
		return nil, fmt.Errorf("checksum signature verification failed: %w", err)
	}

	checksum, err := update.ParseChecksumManifest(manifest)
	if err != nil {
		return nil, err
	}

	metadata := &types.UpdateMetadata{
		Version:          latestVersion.String(),
		DownloadURL:      binaryAsset.BrowserDownloadURL,
		SHA256:           checksum,
		Signature:        signature,
		ChecksumManifest: manifest,
		Changelog:        release.Body,
	}

	if release.HTMLURL != "" {
		metadata.ReleaseURL = release.HTMLURL
	}
	if release.PublishedAt != nil {
		metadata.SignedAt = *release.PublishedAt
	}

	return metadata, nil
}

func (s *updateService) downloadTextAsset(ctx context.Context, asset githubReleaseAsset) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, asset.BrowserDownloadURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create asset request for %s: %w", asset.Name, err)
	}

	s.decorateRequest(req, "application/octet-stream")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to download asset %s: %w", asset.Name, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", s.githubAPIError(resp)
	}

	content, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return "", fmt.Errorf("failed to read asset %s: %w", asset.Name, err)
	}

	return string(content), nil
}

func (s *updateService) githubAPIError(resp *http.Response) error {
	if resp.StatusCode == http.StatusForbidden && resp.Header.Get("X-RateLimit-Remaining") == "0" {
		return errGitHubRateLimited
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	message := strings.TrimSpace(string(body))
	if message == "" {
		return fmt.Errorf("github api returned status %d", resp.StatusCode)
	}
	return fmt.Errorf("github api returned status %d: %s", resp.StatusCode, message)
}

func (s *updateService) artifactName() string {
	return fmt.Sprintf("pulseup-agent_%s_%s.tar.gz", runtime.GOOS, runtime.GOARCH)
}

func findReleaseAssets(baseName string, assets []githubReleaseAsset) (binary, checksum, signature *githubReleaseAsset) {
	checksumName := baseName + ".sha256"
	signatureName := checksumName + ".sig"
	for idx := range assets {
		asset := &assets[idx]
		switch asset.Name {
		case baseName:
			binary = asset
		case checksumName:
			checksum = asset
		case signatureName:
			signature = asset
		}
	}
	return
}

func (s *updateService) ensureValidator() (*update.Validator, error) {
	if s.validator != nil {
		return s.validator, nil
	}

	validator, err := update.NewValidator(s.config.UpdatePublicKeyPath)
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
	req.Header.Set("User-Agent", fmt.Sprintf("PulseUp-Agent-Go/%s", config.GetVersionString()))
}

func parseRepositoryIdentifier(repo string) (string, string, error) {
	repo = strings.TrimSpace(repo)
	if repo == "" {
		return "", "", fmt.Errorf("repository string is empty")
	}

	parts := strings.Split(repo, "/")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid repository identifier: %s", repo)
	}

	owner := strings.TrimSpace(parts[0])
	name := strings.TrimSpace(parts[1])
	if owner == "" || name == "" {
		return "", "", fmt.Errorf("invalid repository identifier: %s", repo)
	}

	return owner, name, nil
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
	tempDir, err := os.MkdirTemp("", "pulseup-update-*")
	if err != nil {
		return "", fmt.Errorf("failed to create temp directory: %w", err)
	}

	// Download update file
	updateFile := filepath.Join(tempDir, fmt.Sprintf("pulseup-agent_%s_%s_%s.tar.gz",
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

func (s *updateService) ApplyUpdate(ctx context.Context, metadata *types.UpdateMetadata, filePath string) error {
	if metadata == nil {
		return fmt.Errorf("update metadata is required")
	}

	if s.updateInProgress {
		return fmt.Errorf("update already in progress")
	}

	s.updateInProgress = true
	defer func() { s.updateInProgress = false }()

	s.logger.Info("Applying update", "version", metadata.Version, "file", filePath)

	if err := s.applyViaSupervisor(ctx, metadata, filePath); err == nil {
		return nil
	} else if err != nil {
		s.logger.Warn("Supervisor update attempt failed, falling back to local installation", "error", err)
	}

	return s.applyLocally(ctx, metadata, filePath)
}

func (s *updateService) applyViaSupervisor(ctx context.Context, metadata *types.UpdateMetadata, filePath string) error {
	if s.ipcClient == nil {
		return fmt.Errorf("supervisor connection unavailable")
	}
	if !s.ipcClient.IsConnected() {
		return fmt.Errorf("supervisor not connected")
	}

	args := map[string]interface{}{
		"update_file_path":  filePath,
		"checksum_manifest": metadata.ChecksumManifest,
		"signature":         metadata.Signature,
		"version":           metadata.Version,
	}

	resp, err := s.ipcClient.SendPrivilegedRequest(ctx, ipc.OpAgentUpdate, args)
	if err != nil {
		return err
	}
	if resp == nil {
		return fmt.Errorf("received empty response from supervisor")
	}
	if !resp.Success {
		if resp.Error != "" {
			return fmt.Errorf(resp.Error)
		}
		return fmt.Errorf("supervisor rejected update request")
	}

	s.logger.Info("Supervisor installed update", "version", metadata.Version)
	return nil
}

func (s *updateService) applyLocally(ctx context.Context, metadata *types.UpdateMetadata, filePath string) error {
	// Local installation is a fallback path for environments without the supervisor IPC.
	currentExe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get current executable: %w", err)
	}

	currentExe, err = filepath.EvalSymlinks(currentExe)
	if err != nil {
		return fmt.Errorf("failed to resolve executable path: %w", err)
	}

	tempDir := filepath.Dir(filePath)
	if err := s.extractArchive(filePath, tempDir); err != nil {
		return fmt.Errorf("failed to extract update: %w", err)
	}

	newBinary := filepath.Join(tempDir, "pulseup-agent")
	if _, err := os.Stat(newBinary); err != nil {
		return fmt.Errorf("new binary not found in archive: %w", err)
	}

	backupPath := currentExe + ".bak"
	if err := s.copyFile(currentExe, backupPath); err != nil {
		return fmt.Errorf("failed to backup current binary: %w", err)
	}

	if err := os.Chmod(newBinary, 0755); err != nil {
		return fmt.Errorf("failed to set executable permissions: %w", err)
	}

	if err := s.replaceFile(newBinary, currentExe); err != nil {
		s.copyFile(backupPath, currentExe)
		return fmt.Errorf("failed to replace binary: %w", err)
	}

	s.logger.Info("Local update applied, restarting agent", "version", metadata.Version)

	if _, err := s.commandService.ExecuteWhitelistedCommand(ctx, "agent.restart", nil); err != nil {
		s.logger.Error("Failed to restart agent after local update", "error", err)
		s.copyFile(backupPath, currentExe)
		return fmt.Errorf("failed to restart agent: %w", err)
	}

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
		intervalHours = 6
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

	// Download update
	updateFile, err := s.DownloadUpdate(ctx, metadata)
	if err != nil {
		s.logger.Error("Failed to download update", "error", err)
		return
	}
	defer os.RemoveAll(filepath.Dir(updateFile))

	// Validate update
	if err := s.ValidateUpdate(ctx, updateFile, metadata); err != nil {
		s.logger.Error("Update validation failed", "error", err)
		return
	}

	// Apply update
	if err := s.ApplyUpdate(ctx, metadata, updateFile); err != nil {
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

func (s *updateService) copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	if _, err := io.Copy(destFile, sourceFile); err != nil {
		return err
	}

	// Copy file permissions
	sourceInfo, err := os.Stat(src)
	if err != nil {
		return err
	}

	return os.Chmod(dst, sourceInfo.Mode())
}

func (s *updateService) replaceFile(src, dst string) error {
	// On Unix systems, we can use rename which is atomic
	if runtime.GOOS != "windows" {
		return os.Rename(src, dst)
	}

	// On Windows, we need to remove the destination first
	if err := os.Remove(dst); err != nil && !os.IsNotExist(err) {
		return err
	}

	return os.Rename(src, dst)
}
