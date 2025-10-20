package services

import (
	"context"

	"pulseup-agent-go/pkg/logger"
	"pulseup-agent-go/pkg/types"
)

// PackageServiceIPC implements PackageService using the local package service now that supervisor duties are removed
type PackageServiceIPC struct {
	logger   *logger.Logger
	delegate PackageService
}

// NewPackageServiceIPC creates a new IPC-aware package service
func NewPackageServiceIPC(logger *logger.Logger, ipcClient IPCClient) *PackageServiceIPC {
	_ = ipcClient // retained for compatibility; supervisor no longer handles package operations
	return &PackageServiceIPC{
		logger:   logger,
		delegate: NewPackageService(logger),
	}
}

// GetUpgradablePackages retrieves all packages that can be upgraded via IPC
func (s *PackageServiceIPC) GetUpgradablePackages(ctx context.Context) (*types.UpgradablePackages, error) {
	return s.delegate.GetUpgradablePackages(ctx)
}

// UpdatePackages updates specific packages via IPC
func (s *PackageServiceIPC) UpdatePackages(ctx context.Context, packageNames []string) (*types.PackageUpdateResult, error) {
	return s.delegate.UpdatePackages(ctx, packageNames)
}

// UpdateAllPackages updates all upgradable packages via IPC
func (s *PackageServiceIPC) UpdateAllPackages(ctx context.Context) (*types.PackageUpdateResult, error) {
	return s.delegate.UpdateAllPackages(ctx)
}

// GetPackageInfo retrieves information about a specific package via IPC
func (s *PackageServiceIPC) GetPackageInfo(ctx context.Context, packageName string) (*types.PackageInfo, error) {
	return s.delegate.GetPackageInfo(ctx, packageName)
}

// UpdatePackagesStream updates packages with streaming via IPC
func (s *PackageServiceIPC) UpdatePackagesStream(ctx context.Context, packageNames []string, outputChan chan<- types.PackageLogMessage) (*types.PackageUpdateResult, error) {
	return s.delegate.UpdatePackagesStream(ctx, packageNames, outputChan)
}

// UpdateAllPackagesStream updates all packages with streaming via local execution
func (s *PackageServiceIPC) UpdateAllPackagesStream(ctx context.Context, outputChan chan<- types.PackageLogMessage) (*types.PackageUpdateResult, error) {
	s.logger.Info("Updating all packages with streaming locally (supervisor package operations disabled)")
	return s.delegate.UpdateAllPackagesStream(ctx, outputChan)
}
