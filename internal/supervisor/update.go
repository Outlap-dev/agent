// Package supervisor provides privileged agent update operations
package supervisor

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"pulseup-agent-go/internal/config"
	"pulseup-agent-go/internal/ipc"
	"pulseup-agent-go/pkg/logger"
)

// UpdateManager handles privileged agent update operations
type UpdateManager struct {
	logger *logger.Logger
	config *config.Config
}

// NewUpdateManager creates a new update manager
func NewUpdateManager(logger *logger.Logger, config *config.Config) *UpdateManager {
	return &UpdateManager{
		logger: logger.With("service", "update_manager"),
		config: config,
	}
}

// UpdateAgent performs an agent update
func (um *UpdateManager) UpdateAgent(ctx context.Context, args map[string]interface{}) (*ipc.PrivilegedResponse, error) {
	updateFilePath, ok := args["update_file_path"].(string)
	if !ok || updateFilePath == "" {
		return &ipc.PrivilegedResponse{
			Success: false,
			Error:   "update_file_path is required",
		}, nil
	}

	um.logger.Info("Starting agent update", "update_file", updateFilePath)

	// Validate update file path
	if err := um.validateUpdateFile(updateFilePath); err != nil {
		return &ipc.PrivilegedResponse{
			Success: false,
			Error:   fmt.Sprintf("invalid update file: %v", err),
		}, nil
	}

	// Verify signature if provided
	if signature, ok := args["signature"].(string); ok && signature != "" {
		if err := um.verifySignature(updateFilePath, signature); err != nil {
			um.logger.Error("Update signature verification failed", "error", err)
			return &ipc.PrivilegedResponse{
				Success: false,
				Error:   fmt.Sprintf("signature verification failed: %v", err),
			}, nil
		}
		um.logger.Info("Update signature verified successfully")
	}

	// Create backup of current binaries
	backupDir, err := um.createBackup()
	if err != nil {
		um.logger.Error("Failed to create backup", "error", err)
		return &ipc.PrivilegedResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to create backup: %v", err),
		}, nil
	}

	// Install new binaries
	if err := um.installUpdate(updateFilePath); err != nil {
		um.logger.Error("Failed to install update", "error", err)
		
		// Attempt to restore from backup
		if restoreErr := um.restoreFromBackup(backupDir); restoreErr != nil {
			um.logger.Error("Failed to restore from backup", "restore_error", restoreErr)
		}
		
		return &ipc.PrivilegedResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to install update: %v", err),
		}, nil
	}

	// Clean up backup after successful update
	um.cleanupBackup(backupDir)

	um.logger.Info("Agent update completed successfully")
	return &ipc.PrivilegedResponse{
		Success: true,
		Data: map[string]interface{}{
			"message":     "Agent update completed successfully",
			"update_file": updateFilePath,
			"backup_dir":  backupDir,
		},
	}, nil
}

// RestartAgent restarts the agent processes
func (um *UpdateManager) RestartAgent(ctx context.Context, args map[string]interface{}) (*ipc.PrivilegedResponse, error) {
	um.logger.Info("Restarting agent processes")

	var errors []string

	// Try systemctl first
	if um.commandExists("systemctl") {
		// Restart supervisor service
		if err := um.restartSystemdService("pulseup-supervisor"); err != nil {
			um.logger.Warn("Failed to restart supervisor via systemctl", "error", err)
			errors = append(errors, fmt.Sprintf("supervisor systemctl: %v", err))
		} else {
			um.logger.Info("Supervisor restarted via systemctl")
		}

		// Restart worker service
		if err := um.restartSystemdService("pulseup-worker"); err != nil {
			um.logger.Warn("Failed to restart worker via systemctl", "error", err)
			errors = append(errors, fmt.Sprintf("worker systemctl: %v", err))
		} else {
			um.logger.Info("Worker restarted via systemctl")
		}

		// If systemctl worked, we're done
		if len(errors) == 0 {
			return &ipc.PrivilegedResponse{
				Success: true,
				Data: map[string]interface{}{
					"message": "Agent processes restarted via systemctl",
					"method":  "systemctl",
				},
			}, nil
		}
	}

	// Try Docker container restart
	if err := um.restartDockerContainer("pulseup-agent-go"); err != nil {
		um.logger.Warn("Failed to restart agent container", "error", err)
		errors = append(errors, fmt.Sprintf("docker: %v", err))
	} else {
		um.logger.Info("Agent container restarted")
		return &ipc.PrivilegedResponse{
			Success: true,
			Data: map[string]interface{}{
				"message": "Agent container restarted",
				"method":  "docker",
			},
		}, nil
	}

	// If all restart methods failed
	if len(errors) > 0 {
		return &ipc.PrivilegedResponse{
			Success: false,
			Error:   fmt.Sprintf("all restart methods failed: %s", strings.Join(errors, "; ")),
		}, nil
	}

	return &ipc.PrivilegedResponse{
		Success: true,
		Data: map[string]interface{}{
			"message": "Agent restart initiated",
		},
	}, nil
}

// validateUpdateFile validates an update file
func (um *UpdateManager) validateUpdateFile(filePath string) error {
	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return fmt.Errorf("update file does not exist: %s", filePath)
	}

	// Check file extension (should be .tar.gz or .zip)
	ext := strings.ToLower(filepath.Ext(filePath))
	if ext != ".gz" && ext != ".zip" {
		// Check for .tar.gz
		if !strings.HasSuffix(strings.ToLower(filePath), ".tar.gz") {
			return fmt.Errorf("invalid update file format, expected .tar.gz or .zip")
		}
	}

	// Check file size (should be reasonable, < 100MB)
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("failed to stat update file: %v", err)
	}

	const maxSize = 100 * 1024 * 1024 // 100MB
	if fileInfo.Size() > maxSize {
		return fmt.Errorf("update file too large: %d bytes (max: %d)", fileInfo.Size(), maxSize)
	}

	return nil
}

// verifySignature verifies the signature of an update file
func (um *UpdateManager) verifySignature(filePath, signature string) error {
	// Calculate file hash
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file for hashing: %v", err)
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return fmt.Errorf("failed to calculate file hash: %v", err)
	}

	fileHash := fmt.Sprintf("%x", hasher.Sum(nil))

	// For now, we'll just compare the provided signature with the file hash
	// In a real implementation, you would use proper cryptographic signature verification
	if signature != fileHash {
		return fmt.Errorf("signature verification failed")
	}

	return nil
}

// createBackup creates a backup of current binaries
func (um *UpdateManager) createBackup() (string, error) {
	timestamp := time.Now().Format("20060102-150405")
	backupDir := filepath.Join("/tmp", fmt.Sprintf("pulseup-backup-%s", timestamp))

	if err := os.MkdirAll(backupDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create backup directory: %v", err)
	}

	// Backup binaries
	binaries := []string{
		"/usr/local/bin/pulseup-supervisor",
		"/usr/local/bin/pulseup-worker",
	}

	for _, binary := range binaries {
		if _, err := os.Stat(binary); err == nil {
			backupPath := filepath.Join(backupDir, filepath.Base(binary))
			if err := um.copyFile(binary, backupPath); err != nil {
				return "", fmt.Errorf("failed to backup %s: %v", binary, err)
			}
		}
	}

	um.logger.Info("Backup created successfully", "backup_dir", backupDir)
	return backupDir, nil
}

// installUpdate installs the update from the provided file
func (um *UpdateManager) installUpdate(updateFilePath string) error {
	// Extract update file to temporary directory
	tempDir := "/tmp/pulseup-update-extract"
	if err := os.RemoveAll(tempDir); err != nil {
		return fmt.Errorf("failed to clean temp directory: %v", err)
	}

	if err := os.MkdirAll(tempDir, 0755); err != nil {
		return fmt.Errorf("failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Extract update archive
	if err := um.extractArchive(updateFilePath, tempDir); err != nil {
		return fmt.Errorf("failed to extract update archive: %v", err)
	}

	// Install binaries
	binaries := map[string]string{
		"pulseup-supervisor": "/usr/local/bin/pulseup-supervisor",
		"pulseup-worker":     "/usr/local/bin/pulseup-worker",
	}

	for binaryName, targetPath := range binaries {
		sourcePath := filepath.Join(tempDir, binaryName)
		if _, err := os.Stat(sourcePath); err == nil {
			if err := um.copyFile(sourcePath, targetPath); err != nil {
				return fmt.Errorf("failed to install %s: %v", binaryName, err)
			}

			// Make executable
			if err := os.Chmod(targetPath, 0755); err != nil {
				return fmt.Errorf("failed to make %s executable: %v", targetPath, err)
			}
		}
	}

	return nil
}

// restoreFromBackup restores binaries from backup
func (um *UpdateManager) restoreFromBackup(backupDir string) error {
	binaries := map[string]string{
		"pulseup-supervisor": "/usr/local/bin/pulseup-supervisor",
		"pulseup-worker":     "/usr/local/bin/pulseup-worker",
	}

	for binaryName, targetPath := range binaries {
		sourcePath := filepath.Join(backupDir, binaryName)
		if _, err := os.Stat(sourcePath); err == nil {
			if err := um.copyFile(sourcePath, targetPath); err != nil {
				return fmt.Errorf("failed to restore %s: %v", binaryName, err)
			}

			// Make executable
			if err := os.Chmod(targetPath, 0755); err != nil {
				return fmt.Errorf("failed to make %s executable: %v", targetPath, err)
			}
		}
	}

	um.logger.Info("Restored from backup successfully", "backup_dir", backupDir)
	return nil
}

// cleanupBackup removes the backup directory
func (um *UpdateManager) cleanupBackup(backupDir string) {
	if err := os.RemoveAll(backupDir); err != nil {
		um.logger.Warn("Failed to cleanup backup directory", "backup_dir", backupDir, "error", err)
	} else {
		um.logger.Debug("Backup directory cleaned up", "backup_dir", backupDir)
	}
}

// copyFile copies a file from source to destination
func (um *UpdateManager) copyFile(src, dst string) error {
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

	_, err = io.Copy(destFile, sourceFile)
	return err
}

// extractArchive extracts an archive to the specified directory
func (um *UpdateManager) extractArchive(archivePath, destDir string) error {
	// Determine archive type and extract accordingly
	if strings.HasSuffix(strings.ToLower(archivePath), ".tar.gz") {
		return um.extractTarGz(archivePath, destDir)
	} else if strings.HasSuffix(strings.ToLower(archivePath), ".zip") {
		return um.extractZip(archivePath, destDir)
	}

	return fmt.Errorf("unsupported archive format")
}

// extractTarGz extracts a tar.gz archive
func (um *UpdateManager) extractTarGz(archivePath, destDir string) error {
	cmd := exec.Command("tar", "-xzf", archivePath, "-C", destDir)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to extract tar.gz: %v", err)
	}
	return nil
}

// extractZip extracts a zip archive
func (um *UpdateManager) extractZip(archivePath, destDir string) error {
	cmd := exec.Command("unzip", "-q", archivePath, "-d", destDir)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to extract zip: %v", err)
	}
	return nil
}

// restartSystemdService restarts a systemd service (supervisor already runs as root)
func (um *UpdateManager) restartSystemdService(serviceName string) error {
	cmd := exec.Command("systemctl", "restart", serviceName)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("systemctl restart failed: %v", err)
	}
	return nil
}

// restartDockerContainer restarts a Docker container
func (um *UpdateManager) restartDockerContainer(containerName string) error {
	cmd := exec.Command("docker", "restart", containerName)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker restart failed: %v", err)
	}
	return nil
}

// commandExists checks if a command exists in the system PATH
func (um *UpdateManager) commandExists(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}