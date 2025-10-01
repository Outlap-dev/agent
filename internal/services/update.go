package services

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"pulseup-agent-go/internal/config"
	"pulseup-agent-go/internal/update"
	"pulseup-agent-go/pkg/logger"
	"pulseup-agent-go/pkg/types"
)

type updateService struct {
	config            *config.Config
	logger            *logger.Logger
	stopChan          chan struct{}
	updateInProgress  bool
	commandService    CommandService
}

func NewUpdateService(cfg *config.Config, logger *logger.Logger, commandService CommandService) UpdateService {
	return &updateService{
		config:         cfg,
		logger:         logger,
		commandService: commandService,
	}
}

func (s *updateService) CheckForUpdate(ctx context.Context) (*types.UpdateMetadata, error) {
	s.logger.Info("Checking for updates", "url", s.config.UpdateURL)
	
	req, err := http.NewRequestWithContext(ctx, "GET", s.config.UpdateURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch update metadata: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("update check failed with status: %d", resp.StatusCode)
	}
	
	var metadata types.UpdateMetadata
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return nil, fmt.Errorf("failed to decode update metadata: %w", err)
	}
	
	// Check if update is needed
	latestVersion, err := update.ParseVersion(metadata.Version)
	if err != nil {
		return nil, fmt.Errorf("failed to parse latest version: %w", err)
	}
	
	if !update.CurrentVersion.LessThan(latestVersion) {
		s.logger.Info("Agent is up to date", 
			"current", update.CurrentVersion.String(), 
			"latest", latestVersion.String())
		return nil, nil
	}
	
	s.logger.Info("Update available", 
		"current", update.CurrentVersion.String(), 
		"latest", latestVersion.String())
	
	return &metadata, nil
}

func (s *updateService) DownloadUpdate(ctx context.Context, metadata *types.UpdateMetadata) (string, error) {
	s.logger.Info("Downloading update", "version", metadata.Version, "url", metadata.URL)
	
	// Create temp directory for update
	tempDir, err := os.MkdirTemp("", "pulseup-update-*")
	if err != nil {
		return "", fmt.Errorf("failed to create temp directory: %w", err)
	}
	
	// Download update file
	updateFile := filepath.Join(tempDir, fmt.Sprintf("pulseup-agent_%s_%s_%s.tar.gz", 
		metadata.Version, runtime.GOOS, runtime.GOARCH))
	
	req, err := http.NewRequestWithContext(ctx, "GET", metadata.URL, nil)
	if err != nil {
		os.RemoveAll(tempDir)
		return "", fmt.Errorf("failed to create download request: %w", err)
	}
	
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
	s.logger.Info("Validating update", "file", filePath)
	
	// Verify SHA256 hash
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open update file: %w", err)
	}
	defer file.Close()
	
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return fmt.Errorf("failed to calculate hash: %w", err)
	}
	
	calculatedHash := hex.EncodeToString(hasher.Sum(nil))
	if calculatedHash != metadata.SHA256 {
		return fmt.Errorf("hash mismatch: expected %s, got %s", metadata.SHA256, calculatedHash)
	}
	
	// TODO: Verify signature once we have the public key implementation
	// For now, we'll just verify the hash
	
	s.logger.Info("Update validation successful")
	return nil
}

func (s *updateService) ApplyUpdate(ctx context.Context, filePath string) error {
	if s.updateInProgress {
		return fmt.Errorf("update already in progress")
	}
	
	s.updateInProgress = true
	defer func() { s.updateInProgress = false }()
	
	s.logger.Info("Applying update", "file", filePath)
	
	// Get current executable path
	currentExe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get current executable: %w", err)
	}
	
	// Resolve any symlinks
	currentExe, err = filepath.EvalSymlinks(currentExe)
	if err != nil {
		return fmt.Errorf("failed to resolve executable path: %w", err)
	}
	
	// Extract update archive
	tempDir := filepath.Dir(filePath)
	if err := s.extractArchive(filePath, tempDir); err != nil {
		return fmt.Errorf("failed to extract update: %w", err)
	}
	
	// Find the new binary
	newBinary := filepath.Join(tempDir, "pulseup-agent")
	if _, err := os.Stat(newBinary); err != nil {
		return fmt.Errorf("new binary not found in archive: %w", err)
	}
	
	// Backup current binary
	backupPath := currentExe + ".bak"
	if err := s.copyFile(currentExe, backupPath); err != nil {
		return fmt.Errorf("failed to backup current binary: %w", err)
	}
	
	// Make new binary executable
	if err := os.Chmod(newBinary, 0755); err != nil {
		return fmt.Errorf("failed to set executable permissions: %w", err)
	}
	
	// Replace current binary with new one
	if err := s.replaceFile(newBinary, currentExe); err != nil {
		// Try to restore backup
		s.copyFile(backupPath, currentExe)
		return fmt.Errorf("failed to replace binary: %w", err)
	}
	
	s.logger.Info("Update applied successfully, restarting agent...")
	
	// Restart the agent
	if _, err := s.commandService.ExecuteWhitelistedCommand(ctx, "agent.restart", nil); err != nil {
		s.logger.Error("Failed to restart agent after update", "error", err)
		// Try to restore backup
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
	
	s.stopChan = make(chan struct{})
	
	go func() {
		ticker := time.NewTicker(time.Duration(s.config.UpdateIntervalHours) * time.Hour)
		defer ticker.Stop()
		
		// Check immediately on start
		s.performUpdateCheck(ctx)
		
		for {
			select {
			case <-ticker.C:
				s.performUpdateCheck(ctx)
			case <-s.stopChan:
				return
			case <-ctx.Done():
				return
			}
		}
	}()
	
	return nil
}

func (s *updateService) StopAutoUpdateLoop() error {
	if s.stopChan != nil {
		close(s.stopChan)
	}
	return nil
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
	if err := s.ApplyUpdate(ctx, updateFile); err != nil {
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