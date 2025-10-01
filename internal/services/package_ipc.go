package services

import (
	"context"
	"fmt"
	"time"

	"pulseup-agent-go/internal/ipc"
	"pulseup-agent-go/pkg/logger"
	"pulseup-agent-go/pkg/types"
)

// PackageServiceIPC implements PackageService using IPC delegation to supervisor
type PackageServiceIPC struct {
	logger    *logger.Logger
	ipcClient IPCClient
}

// NewPackageServiceIPC creates a new IPC-aware package service
func NewPackageServiceIPC(logger *logger.Logger, ipcClient IPCClient) *PackageServiceIPC {
	return &PackageServiceIPC{
		logger:    logger,
		ipcClient: ipcClient,
	}
}

// GetUpgradablePackages retrieves all packages that can be upgraded via IPC
func (s *PackageServiceIPC) GetUpgradablePackages(ctx context.Context) (*types.UpgradablePackages, error) {
	s.logger.Info("Getting upgradable packages via IPC")

	// First, update the package list via supervisor
	updateArgs := map[string]interface{}{}
	updateResp, err := s.ipcClient.SendPrivilegedRequest(ctx, ipc.OpSystemUpdatePackages, updateArgs)
	if err != nil {
		s.logger.Error("Failed to update package list via IPC", "error", err)
		return nil, fmt.Errorf("failed to update package list: %v", err)
	}

	if !updateResp.Success {
		s.logger.Error("Package list update failed", "error", updateResp.Error)
		return nil, fmt.Errorf("failed to update package list: %s", updateResp.Error)
	}

	// Get the list of upgradable packages via supervisor
	listArgs := map[string]interface{}{
		"list_only": true,
	}
	listResp, err := s.ipcClient.SendPrivilegedRequest(ctx, ipc.OpSystemUpdatePackages, listArgs)
	if err != nil {
		s.logger.Error("Failed to list upgradable packages via IPC", "error", err)
		return nil, fmt.Errorf("failed to list upgradable packages: %v", err)
	}

	if !listResp.Success {
		s.logger.Error("Package listing failed", "error", listResp.Error)
		return nil, fmt.Errorf("failed to list upgradable packages: %s", listResp.Error)
	}

	// Parse the response data
	packages := []types.Package{}
	totalSize := "0 MB"
	if len(listResp.Data) > 0 {
		// Access the data directly since it's already map[string]interface{}
		if packageData, exists := listResp.Data["packages"]; exists {
			if packageList, isList := packageData.([]interface{}); isList {
				packages = make([]types.Package, len(packageList))
				for i, pkg := range packageList {
					if pkgMap, isMap := pkg.(map[string]interface{}); isMap {
						packages[i] = types.Package{
							Name:           getString(pkgMap, "name"),
							CurrentVersion: getString(pkgMap, "current_version"),
							NewVersion:     getString(pkgMap, "new_version"),
							Architecture:   getString(pkgMap, "architecture"),
						}
					}
				}
			}
		}
		
		if sizeData, exists := listResp.Data["total_size"]; exists {
			if size, isString := sizeData.(string); isString {
				totalSize = size
			}
		}
	}

	result := &types.UpgradablePackages{
		Packages:    packages,
		TotalCount:  len(packages),
		TotalSize:   totalSize,
		LastChecked: time.Now().UTC().Format(time.RFC3339),
	}

	s.logger.Info("Found upgradable packages via IPC", "count", result.TotalCount)
	return result, nil
}

// UpdatePackages updates specific packages via IPC
func (s *PackageServiceIPC) UpdatePackages(ctx context.Context, packageNames []string) (*types.PackageUpdateResult, error) {
	s.logger.Info("Updating packages via IPC", "packages", packageNames)

	if len(packageNames) == 0 {
		return &types.PackageUpdateResult{
			Success: false,
			Message: "No packages specified",
		}, nil
	}

	args := map[string]interface{}{
		"packages": packageNames,
	}

	resp, err := s.ipcClient.SendPrivilegedRequest(ctx, ipc.OpSystemUpdatePackages, args)
	if err != nil {
		s.logger.Error("Failed to update packages via IPC", "error", err)
		return &types.PackageUpdateResult{
			UpdatedPackages: []types.Package{},
			FailedPackages:  packageNames,
			Success:         false,
			Message:         "Failed to update packages",
			Errors:          []string{err.Error()},
		}, nil
	}

	if !resp.Success {
		s.logger.Error("Package update failed", "error", resp.Error)
		return &types.PackageUpdateResult{
			UpdatedPackages: []types.Package{},
			FailedPackages:  packageNames,
			Success:         false,
			Message:         "Failed to update packages",
			Errors:          []string{resp.Error},
		}, nil
	}

	// Parse updated packages from response
	updatedPackages := []types.Package{}
	if len(resp.Data) > 0 {
		if packageData, exists := resp.Data["updated_packages"]; exists {
			if packageList, isList := packageData.([]interface{}); isList {
				updatedPackages = make([]types.Package, len(packageList))
				for i, pkg := range packageList {
					if pkgMap, isMap := pkg.(map[string]interface{}); isMap {
						updatedPackages[i] = types.Package{
							Name:       getString(pkgMap, "name"),
							NewVersion: getString(pkgMap, "new_version"),
						}
					}
				}
			}
		}
	}

	return &types.PackageUpdateResult{
		UpdatedPackages: updatedPackages,
		FailedPackages:  []string{},
		Success:         true,
		Message:         fmt.Sprintf("Successfully updated %d packages", len(updatedPackages)),
		Errors:          []string{},
	}, nil
}

// UpdateAllPackages updates all upgradable packages via IPC
func (s *PackageServiceIPC) UpdateAllPackages(ctx context.Context) (*types.PackageUpdateResult, error) {
	s.logger.Info("Updating all packages via IPC")

	args := map[string]interface{}{
		"upgrade_all": true,
	}

	resp, err := s.ipcClient.SendPrivilegedRequest(ctx, ipc.OpSystemUpdatePackages, args)
	if err != nil {
		s.logger.Error("Failed to update all packages via IPC", "error", err)
		return &types.PackageUpdateResult{
			UpdatedPackages: []types.Package{},
			Success:         false,
			Message:         "Failed to update packages",
			Errors:          []string{err.Error()},
		}, nil
	}

	if !resp.Success {
		s.logger.Error("Package update failed", "error", resp.Error)
		return &types.PackageUpdateResult{
			UpdatedPackages: []types.Package{},
			Success:         false,
			Message:         "Failed to update packages",
			Errors:          []string{resp.Error},
		}, nil
	}

	return &types.PackageUpdateResult{
		UpdatedPackages: []types.Package{}, // TODO: Parse from response
		FailedPackages:  []string{},
		Success:         true,
		Message:         "Successfully updated all packages",
		Errors:          []string{},
	}, nil
}

// GetPackageInfo retrieves information about a specific package via IPC
func (s *PackageServiceIPC) GetPackageInfo(ctx context.Context, packageName string) (*types.PackageInfo, error) {
	s.logger.Info("Getting package info via IPC", "package", packageName)

	args := map[string]interface{}{
		"package_name": packageName,
	}

	resp, err := s.ipcClient.SendPrivilegedRequest(ctx, ipc.OpSystemInstallPackage, args)
	if err != nil {
		s.logger.Error("Failed to get package info via IPC", "error", err)
		return nil, fmt.Errorf("failed to get package info: %v", err)
	}

	if !resp.Success {
		s.logger.Error("Package info request failed", "error", resp.Error)
		return nil, fmt.Errorf("failed to get package info: %s", resp.Error)
	}

	// TODO: Parse package info from response
	return &types.PackageInfo{
		Name:         packageName,
		Version:      "unknown",
		Description:  "Package info via IPC",
		Size:         "unknown",
		Dependencies: []string{},
		Installed:    false,
	}, nil
}

// UpdatePackagesStream updates packages with streaming via IPC
func (s *PackageServiceIPC) UpdatePackagesStream(ctx context.Context, packageNames []string, outputChan chan<- types.PackageLogMessage) (*types.PackageUpdateResult, error) {
	s.logger.Info("Updating packages with streaming via IPC", "packages", packageNames)

	// Send initial message
	s.sendLogMessage(outputChan, "Starting package update via supervisor...", "info")

	// Delegate to regular update for now (streaming support can be added later)
	result, err := s.UpdatePackages(ctx, packageNames)
	if err != nil {
		s.sendLogMessage(outputChan, fmt.Sprintf("Package update failed: %v", err), "error")
		return result, err
	}

	if result.Success {
		s.sendLogMessage(outputChan, result.Message, "info")
	} else {
		s.sendLogMessage(outputChan, result.Message, "error")
	}

	return result, nil
}

// UpdateAllPackagesStream updates all packages with streaming via IPC
func (s *PackageServiceIPC) UpdateAllPackagesStream(ctx context.Context, outputChan chan<- types.PackageLogMessage) (*types.PackageUpdateResult, error) {
	s.logger.Info("Updating all packages with streaming via IPC")

	// Send initial message
	s.sendLogMessage(outputChan, "Starting full package upgrade via supervisor...", "info")

	// Delegate to regular update for now (streaming support can be added later)
	result, err := s.UpdateAllPackages(ctx)
	if err != nil {
		s.sendLogMessage(outputChan, fmt.Sprintf("Package update failed: %v", err), "error")
		return result, err
	}

	if result.Success {
		s.sendLogMessage(outputChan, result.Message, "info")
	} else {
		s.sendLogMessage(outputChan, result.Message, "error")
	}

	return result, nil
}

// sendLogMessage sends a log message to the output channel
func (s *PackageServiceIPC) sendLogMessage(outputChan chan<- types.PackageLogMessage, message, level string) {
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

// getString safely extracts a string from a map[string]interface{}
func getString(data map[string]interface{}, key string) string {
	if value, exists := data[key]; exists {
		if str, isString := value.(string); isString {
			return str
		}
	}
	return ""
}