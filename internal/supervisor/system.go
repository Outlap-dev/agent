// Package supervisor provides privileged system operations
package supervisor

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"pulseup-agent-go/internal/ipc"
	"pulseup-agent-go/pkg/logger"
)

// SystemService handles privileged system operations
type SystemService struct {
	logger *logger.Logger
}

// NewSystemService creates a new system service
func NewSystemService(logger *logger.Logger) *SystemService {
	return &SystemService{
		logger: logger.With("service", "system"),
	}
}

// Reboot performs a system reboot
func (s *SystemService) Reboot(ctx context.Context, args map[string]interface{}) (*ipc.PrivilegedResponse, error) {
	s.logger.Info("Executing system reboot")

	// Execute reboot command (supervisor already runs as root)
	cmd := exec.CommandContext(ctx, "reboot")
	output, err := cmd.CombinedOutput()

	if err != nil {
		s.logger.Error("Failed to reboot system", "error", err, "output", string(output))
		return &ipc.PrivilegedResponse{
			Success: false,
			Error:   fmt.Sprintf("reboot failed: %v", err),
			Data: map[string]interface{}{
				"output": string(output),
			},
		}, nil
	}

	s.logger.Info("System reboot command executed successfully")
	return &ipc.PrivilegedResponse{
		Success: true,
		Data: map[string]interface{}{
			"message": "System reboot initiated",
			"output":  string(output),
		},
	}, nil
}

// Shutdown performs a system shutdown
func (s *SystemService) Shutdown(ctx context.Context, args map[string]interface{}) (*ipc.PrivilegedResponse, error) {
	s.logger.Info("Executing system shutdown")

	// Execute shutdown command (supervisor already runs as root)
	cmd := exec.CommandContext(ctx, "shutdown", "-h", "now")
	output, err := cmd.CombinedOutput()

	if err != nil {
		s.logger.Error("Failed to shutdown system", "error", err, "output", string(output))
		return &ipc.PrivilegedResponse{
			Success: false,
			Error:   fmt.Sprintf("shutdown failed: %v", err),
			Data: map[string]interface{}{
				"output": string(output),
			},
		}, nil
	}

	s.logger.Info("System shutdown command executed successfully")
	return &ipc.PrivilegedResponse{
		Success: true,
		Data: map[string]interface{}{
			"message": "System shutdown initiated",
			"output":  string(output),
		},
	}, nil
}

// UpdatePackages updates system packages or lists upgradable packages
func (s *SystemService) UpdatePackages(ctx context.Context, args map[string]interface{}) (*ipc.PrivilegedResponse, error) {
	s.logger.Info("Processing package operation", "args", args)

	// Check if this is a list-only request
	if listOnly, ok := args["list_only"]; ok && listOnly == true {
		return s.listUpgradablePackages(ctx)
	}

	// Check if specific packages are requested
	var packages []string
	if packagesArg, ok := args["packages"]; ok {
		if packagesList, ok := packagesArg.([]interface{}); ok {
			for _, pkg := range packagesList {
				if pkgStr, ok := pkg.(string); ok {
					packages = append(packages, pkgStr)
				}
			}
		}
	}

	// Detect package manager and build command (NO SUDO - supervisor runs as root)
	var cmd *exec.Cmd
	if s.commandExists("apt-get") {
		if len(packages) > 0 {
			// Update specific packages
			cmdArgs := append([]string{"install", "-y"}, packages...)
			cmd = exec.CommandContext(ctx, "apt-get", cmdArgs...)
		} else {
			// Update package list only
			cmd = exec.CommandContext(ctx, "apt-get", "update")
		}
	} else if s.commandExists("yum") {
		if len(packages) > 0 {
			// Update specific packages
			cmdArgs := append([]string{"install", "-y"}, packages...)
			cmd = exec.CommandContext(ctx, "yum", cmdArgs...)
		} else {
			// Update package list
			cmd = exec.CommandContext(ctx, "yum", "check-update")
		}
	} else if s.commandExists("dnf") {
		if len(packages) > 0 {
			// Update specific packages
			cmdArgs := append([]string{"install", "-y"}, packages...)
			cmd = exec.CommandContext(ctx, "dnf", cmdArgs...)
		} else {
			// Update package list
			cmd = exec.CommandContext(ctx, "dnf", "check-update")
		}
	} else {
		return &ipc.PrivilegedResponse{
			Success: false,
			Error:   "No supported package manager found (apt-get, yum, dnf)",
		}, nil
	}

	s.logger.Info("Starting package update", "packages", packages)
	startTime := time.Now()

	// Execute package update command
	output, err := cmd.CombinedOutput()
	duration := time.Since(startTime)

	if err != nil {
		s.logger.Error("Package update failed", 
			"error", err, 
			"output", string(output),
			"duration", duration,
		)
		return &ipc.PrivilegedResponse{
			Success: false,
			Error:   fmt.Sprintf("package update failed: %v", err),
			Data: map[string]interface{}{
				"output":   string(output),
				"duration": duration.Seconds(),
				"packages": packages,
			},
		}, nil
	}

	s.logger.Info("Package update completed successfully", 
		"duration", duration,
		"packages", packages,
	)
	return &ipc.PrivilegedResponse{
		Success: true,
		Data: map[string]interface{}{
			"message":  "Package update completed successfully",
			"output":   string(output),
			"duration": duration.Seconds(),
			"packages": packages,
		},
	}, nil
}

// InstallPackage installs a specific system package
func (s *SystemService) InstallPackage(ctx context.Context, args map[string]interface{}) (*ipc.PrivilegedResponse, error) {
	packageName, ok := args["package_name"].(string)
	if !ok || packageName == "" {
		return &ipc.PrivilegedResponse{
			Success: false,
			Error:   "package_name is required",
		}, nil
	}

	s.logger.Info("Installing package", "package", packageName)

	// Detect package manager and build command
	var cmd *exec.Cmd
	if s.commandExists("apt-get") {
		cmd = exec.CommandContext(ctx, "apt-get", "install", "-y", packageName)
	} else if s.commandExists("yum") {
		cmd = exec.CommandContext(ctx, "yum", "install", "-y", packageName)
	} else if s.commandExists("dnf") {
		cmd = exec.CommandContext(ctx, "dnf", "install", "-y", packageName)
	} else if s.commandExists("brew") {
		// For macOS development
		cmd = exec.CommandContext(ctx, "brew", "install", packageName)
	} else {
		return &ipc.PrivilegedResponse{
			Success: false,
			Error:   "No supported package manager found (apt-get, yum, dnf, brew)",
		}, nil
	}

	startTime := time.Now()

	// Execute package install command
	output, err := cmd.CombinedOutput()
	duration := time.Since(startTime)

	if err != nil {
		s.logger.Error("Package installation failed",
			"package", packageName,
			"error", err,
			"output", string(output),
			"duration", duration,
		)
		return &ipc.PrivilegedResponse{
			Success: false,
			Error:   fmt.Sprintf("package installation failed: %v", err),
			Data: map[string]interface{}{
				"package":  packageName,
				"output":   string(output),
				"duration": duration.Seconds(),
			},
		}, nil
	}

	s.logger.Info("Package installed successfully",
		"package", packageName,
		"duration", duration,
	)
	return &ipc.PrivilegedResponse{
		Success: true,
		Data: map[string]interface{}{
			"message":  fmt.Sprintf("Package '%s' installed successfully", packageName),
			"package":  packageName,
			"output":   string(output),
			"duration": duration.Seconds(),
		},
	}, nil
}

// listUpgradablePackages returns a list of packages that can be upgraded
func (s *SystemService) listUpgradablePackages(ctx context.Context) (*ipc.PrivilegedResponse, error) {
	s.logger.Info("Listing upgradable packages")

	var packages []map[string]interface{}
	var totalSize string

	if s.commandExists("apt") {
		// Get upgradable packages using apt
		cmd := exec.CommandContext(ctx, "apt", "list", "--upgradable")
		output, err := cmd.Output()
		if err != nil {
			s.logger.Error("Failed to list upgradable packages", "error", err)
			return &ipc.PrivilegedResponse{
				Success: false,
				Error:   fmt.Sprintf("failed to list upgradable packages: %v", err),
			}, nil
		}

		packages = s.parseAptUpgradablePackages(string(output))

		// Get total download size
		sizeCmd := exec.CommandContext(ctx, "apt-get", "upgrade", "-s")
		sizeOutput, _ := sizeCmd.Output()
		totalSize = s.extractAptTotalSize(string(sizeOutput))
	} else {
		// Fallback for other package managers
		packages = []map[string]interface{}{}
		totalSize = "0 MB"
	}

	return &ipc.PrivilegedResponse{
		Success: true,
		Data: map[string]interface{}{
			"packages":    packages,
			"total_size":  totalSize,
			"last_checked": time.Now().UTC().Format(time.RFC3339),
		},
	}, nil
}

// parseAptUpgradablePackages parses apt list --upgradable output
func (s *SystemService) parseAptUpgradablePackages(output string) []map[string]interface{} {
	var packages []map[string]interface{}

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()

		// Skip header line
		if strings.Contains(line, "Listing...") || line == "" {
			continue
		}

		// Parse format: package/suite version arch [upgradable from: old-version]
		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}

		// Extract package name (before /)
		nameParts := strings.Split(parts[0], "/")
		if len(nameParts) == 0 {
			continue
		}
		packageName := nameParts[0]

		// Extract new version
		newVersion := parts[1]

		// Extract architecture
		arch := parts[2]

		// Extract current version
		currentVersion := ""
		for i, part := range parts {
			if part == "from:" && i+1 < len(parts) {
				currentVersion = strings.TrimSuffix(parts[i+1], "]")
				break
			}
		}

		packages = append(packages, map[string]interface{}{
			"name":            packageName,
			"current_version": currentVersion,
			"new_version":     newVersion,
			"architecture":    arch,
		})
	}

	return packages
}

// extractAptTotalSize extracts the total download size from apt-get upgrade -s output
func (s *SystemService) extractAptTotalSize(output string) string {
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "Need to get") {
			// Format: "Need to get X MB of archives"
			parts := strings.Fields(line)
			if len(parts) >= 4 {
				return fmt.Sprintf("%s %s", parts[3], parts[4])
			}
		}
	}
	return "0 MB"
}

// commandExists checks if a command exists in the system PATH
func (s *SystemService) commandExists(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}

// validatePackageName validates a package name for security
func (s *SystemService) validatePackageName(name string) error {
	// Basic validation to prevent command injection
	if strings.ContainsAny(name, ";|&$`(){}[]<>") {
		return fmt.Errorf("invalid characters in package name: %s", name)
	}

	if len(name) == 0 {
		return fmt.Errorf("empty package name")
	}

	if len(name) > 128 {
		return fmt.Errorf("package name too long: %d characters", len(name))
	}

	return nil
}