package services

import (
	"bufio"
	"context"
	"fmt"
	"strings"
	"time"

	"pulseup-agent-go/pkg/logger"
	"pulseup-agent-go/pkg/runtime"
	"pulseup-agent-go/pkg/types"
)

// PackageServiceImpl implements the PackageService interface
type PackageServiceImpl struct {
	logger   *logger.Logger
	executor *runtime.Executor
	osInfo   *runtime.OSInfo
}

// NewPackageService creates a new package service instance
func NewPackageService(logger *logger.Logger) *PackageServiceImpl {
	return &PackageServiceImpl{
		logger:   logger,
		executor: runtime.NewExecutor(),
		osInfo:   runtime.DetectOS(),
	}
}

// GetUpgradablePackages retrieves all packages that can be upgraded
func (s *PackageServiceImpl) GetUpgradablePackages(ctx context.Context) (*types.UpgradablePackages, error) {
	s.logger.Info("Getting upgradable packages")

	// First, update the package list
	result := s.executor.Execute(ctx, "apt-get", []string{"update"}, nil)
	if result.Error != nil {
		s.logger.Error("Failed to update package list",
			"error", result.Error,
			"output", result.Stderr)
		return nil, fmt.Errorf("failed to update package list: %v", result.Error)
	}

	// Get the list of upgradable packages
	listResult := s.executor.Execute(ctx, "apt", []string{"list", "--upgradable"}, nil)
	if listResult.Error != nil {
		s.logger.Error("Failed to list upgradable packages", "error", listResult.Error)
		return nil, fmt.Errorf("failed to list upgradable packages: %v", listResult.Error)
	}

	packages := s.parseUpgradablePackages(listResult.Stdout)

	// Get total download size
	sizeResult := s.executor.Execute(ctx, "apt-get", []string{"upgrade", "-s"}, nil)
	totalSize := s.extractTotalSize(sizeResult.Stdout)

	pkgResult := &types.UpgradablePackages{
		Packages:    packages,
		TotalCount:  len(packages),
		TotalSize:   totalSize,
		LastChecked: time.Now().UTC().Format(time.RFC3339),
	}

	s.logger.Info("Found upgradable packages", "count", pkgResult.TotalCount)
	return pkgResult, nil
}

// UpdatePackages updates specific packages
func (s *PackageServiceImpl) UpdatePackages(ctx context.Context, packageNames []string) (*types.PackageUpdateResult, error) {
	s.logger.Info("Updating packages", "packages", packageNames)

	if len(packageNames) == 0 {
		return &types.PackageUpdateResult{
			Success: false,
			Message: "No packages specified",
		}, nil
	}

	// Prepare the command
	args := append([]string{"install", "--only-upgrade", "-y"}, packageNames...)
	result := s.executor.Execute(ctx, "apt-get", args, nil)

	if result.Error != nil {
		s.logger.Error("Failed to update packages",
			"error", result.Error,
			"output", result.Stderr)

		return &types.PackageUpdateResult{
			UpdatedPackages: []types.Package{},
			FailedPackages:  packageNames,
			Success:         false,
			Message:         "Failed to update packages",
			Errors:          []string{result.Error.Error(), result.Stderr},
		}, nil
	}

	// Parse the output to determine which packages were updated
	updatedPackages := s.parseUpdatedPackages(result.Stdout, packageNames)

	return &types.PackageUpdateResult{
		UpdatedPackages: updatedPackages,
		FailedPackages:  []string{},
		Success:         true,
		Message:         fmt.Sprintf("Successfully updated %d packages", len(updatedPackages)),
		Errors:          []string{},
	}, nil
}

// UpdateAllPackages updates all upgradable packages
func (s *PackageServiceImpl) UpdateAllPackages(ctx context.Context) (*types.PackageUpdateResult, error) {
	s.logger.Info("Updating all packages")

	// First, get the list of upgradable packages
	upgradable, err := s.GetUpgradablePackages(ctx)
	if err != nil {
		return nil, err
	}

	if len(upgradable.Packages) == 0 {
		return &types.PackageUpdateResult{
			Success: true,
			Message: "No packages to update",
		}, nil
	}

	// Execute the upgrade
	result := s.executor.Execute(ctx, "apt-get", []string{"upgrade", "-y"}, nil)

	if result.Error != nil {
		s.logger.Error("Failed to update all packages",
			"error", result.Error,
			"output", result.Stderr)

		return &types.PackageUpdateResult{
			UpdatedPackages: []types.Package{},
			Success:         false,
			Message:         "Failed to update packages",
			Errors:          []string{result.Error.Error(), result.Stderr},
		}, nil
	}

	return &types.PackageUpdateResult{
		UpdatedPackages: upgradable.Packages,
		FailedPackages:  []string{},
		Success:         true,
		Message:         fmt.Sprintf("Successfully updated %d packages", len(upgradable.Packages)),
		Errors:          []string{},
	}, nil
}

// GetPackageInfo retrieves information about a specific package
func (s *PackageServiceImpl) GetPackageInfo(ctx context.Context, packageName string) (*types.PackageInfo, error) {
	s.logger.Info("Getting package info", "package", packageName)

	// Get package details using apt-cache
	result := s.executor.Execute(ctx, "apt-cache", []string{"show", packageName}, nil)
	if result.Error != nil {
		s.logger.Error("Failed to get package info", "error", result.Error)
		return nil, fmt.Errorf("failed to get package info: %v", result.Error)
	}

	info := s.parsePackageInfo(result.Stdout, packageName)

	// Check if package is installed
	policyResult := s.executor.Execute(ctx, "apt-cache", []string{"policy", packageName}, nil)
	info.Installed = s.isPackageInstalled(policyResult.Stdout)

	return info, nil
}

// parseUpgradablePackages parses the output of apt list --upgradable
func (s *PackageServiceImpl) parseUpgradablePackages(output string) []types.Package {
	var packages []types.Package

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

		packages = append(packages, types.Package{
			Name:           packageName,
			CurrentVersion: currentVersion,
			NewVersion:     newVersion,
			Architecture:   arch,
		})
	}

	return packages
}

// extractTotalSize extracts the total download size from apt-get upgrade -s output
func (s *PackageServiceImpl) extractTotalSize(output string) string {
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

// parseUpdatedPackages parses which packages were actually updated
func (s *PackageServiceImpl) parseUpdatedPackages(output string, requestedPackages []string) []types.Package {
	var updated []types.Package

	// Look for "Setting up package-name (version)" lines
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Setting up") {
			for _, pkg := range requestedPackages {
				if strings.Contains(line, pkg) {
					// Extract version from "Setting up package (version) ..."
					start := strings.Index(line, "(")
					end := strings.Index(line, ")")
					version := ""
					if start != -1 && end != -1 && end > start {
						version = line[start+1 : end]
					}

					updated = append(updated, types.Package{
						Name:       pkg,
						NewVersion: version,
					})
					break
				}
			}
		}
	}

	return updated
}

// parsePackageInfo parses apt-cache show output
func (s *PackageServiceImpl) parsePackageInfo(output string, packageName string) *types.PackageInfo {
	info := &types.PackageInfo{
		Name:         packageName,
		Dependencies: []string{},
	}

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()

		if strings.HasPrefix(line, "Version:") {
			info.Version = strings.TrimSpace(strings.TrimPrefix(line, "Version:"))
		} else if strings.HasPrefix(line, "Description:") {
			info.Description = strings.TrimSpace(strings.TrimPrefix(line, "Description:"))
		} else if strings.HasPrefix(line, "Size:") {
			info.Size = strings.TrimSpace(strings.TrimPrefix(line, "Size:"))
		} else if strings.HasPrefix(line, "Depends:") {
			deps := strings.TrimSpace(strings.TrimPrefix(line, "Depends:"))
			info.Dependencies = strings.Split(deps, ", ")
		}
	}

	return info
}

// isPackageInstalled checks if a package is installed from apt-cache policy output
func (s *PackageServiceImpl) isPackageInstalled(output string) bool {
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "Installed:") {
			installed := strings.TrimSpace(strings.TrimPrefix(line, "Installed:"))
			return installed != "(none)" && installed != ""
		}
	}
	return false
}

// UpdatePackagesStream updates specific packages with real-time output streaming
func (s *PackageServiceImpl) UpdatePackagesStream(ctx context.Context, packageNames []string, outputChan chan<- types.PackageLogMessage) (*types.PackageUpdateResult, error) {
	s.logger.Info("Updating packages with streaming", "packages", packageNames)

	if len(packageNames) == 0 {
		return &types.PackageUpdateResult{
			Success: false,
			Message: "No packages specified",
		}, nil
	}

	// Send initial message
	s.sendLogMessage(outputChan, "Starting package update...", "info")

	// Prepare the command
	args := append([]string{"install", "--only-upgrade", "-y"}, packageNames...)

	opts := &runtime.ExecOptions{
		StreamOutput: true,
		StreamHandler: func(line string, isStderr bool) {
			level := "info"
			if isStderr {
				level = "error"
			}
			s.sendLogMessage(outputChan, line, level)
		},
	}

	result := s.executor.Execute(ctx, "apt-get", args, opts)

	if result.Error != nil {
		s.logger.Error("Failed to update packages", "error", result.Error, "output", result.Stderr)
		s.sendLogMessage(outputChan, fmt.Sprintf("Package update failed: %v", result.Error), "error")

		return &types.PackageUpdateResult{
			UpdatedPackages: []types.Package{},
			FailedPackages:  packageNames,
			Success:         false,
			Message:         "Failed to update packages",
			Errors:          []string{result.Error.Error(), result.Stderr},
		}, nil
	}

	// Parse the output to determine which packages were updated
	updatedPackages := s.parseUpdatedPackages(result.Stdout, packageNames)
	s.sendLogMessage(outputChan, fmt.Sprintf("Successfully updated %d packages", len(updatedPackages)), "info")

	return &types.PackageUpdateResult{
		UpdatedPackages: updatedPackages,
		FailedPackages:  []string{},
		Success:         true,
		Message:         fmt.Sprintf("Successfully updated %d packages", len(updatedPackages)),
		Errors:          []string{},
	}, nil
}

// UpdateAllPackagesStream updates all upgradable packages with real-time output streaming
func (s *PackageServiceImpl) UpdateAllPackagesStream(ctx context.Context, outputChan chan<- types.PackageLogMessage) (*types.PackageUpdateResult, error) {
	s.logger.Info("Updating all packages with streaming")

	// Send initial message
	s.sendLogMessage(outputChan, "Getting list of upgradable packages...", "info")

	// First, get the list of upgradable packages
	upgradable, err := s.GetUpgradablePackages(ctx)
	if err != nil {
		s.sendLogMessage(outputChan, fmt.Sprintf("Failed to get upgradable packages: %v", err), "error")
		return nil, err
	}

	if len(upgradable.Packages) == 0 {
		return &types.PackageUpdateResult{
			Success: true,
			Message: "No packages to update",
		}, nil
	}

	s.sendLogMessage(outputChan, fmt.Sprintf("Found %d packages to update", len(upgradable.Packages)), "info")
	s.sendLogMessage(outputChan, "Starting full package upgrade...", "info")

	// Execute the upgrade with streaming
	opts := &runtime.ExecOptions{
		StreamOutput: true,
		StreamHandler: func(line string, isStderr bool) {
			level := "info"
			if isStderr {
				level = "error"
			}
			s.sendLogMessage(outputChan, line, level)
		},
	}

	result := s.executor.Execute(ctx, "apt-get", []string{"upgrade", "-y"}, opts)

	if result.Error != nil {
		s.logger.Error("Failed to update all packages", "error", result.Error, "output", result.Stderr)
		s.sendLogMessage(outputChan, fmt.Sprintf("Package update failed: %v", result.Error), "error")

		return &types.PackageUpdateResult{
			UpdatedPackages: []types.Package{},
			Success:         false,
			Message:         "Failed to update packages",
			Errors:          []string{result.Error.Error(), result.Stderr},
		}, nil
	}

	s.sendLogMessage(outputChan, fmt.Sprintf("Successfully updated %d packages", len(upgradable.Packages)), "info")

	return &types.PackageUpdateResult{
		UpdatedPackages: upgradable.Packages,
		FailedPackages:  []string{},
		Success:         true,
		Message:         fmt.Sprintf("Successfully updated %d packages", len(upgradable.Packages)),
		Errors:          []string{},
	}, nil
}

// sendLogMessage sends a log message to the output channel
func (s *PackageServiceImpl) sendLogMessage(outputChan chan<- types.PackageLogMessage, message, level string) {
	select {
	case outputChan <- types.PackageLogMessage{
		Message:   message,
		Level:     level,
		Timestamp: time.Now().Unix(),
	}:
	default:
		// Channel is full or closed, log the message instead
		s.logger.Warn("Output channel full, dropping message", "message", message)
	}
}
