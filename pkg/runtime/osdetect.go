package runtime

import (
	"context"
	"os/exec"
	"strings"
	"sync"
)

// PackageManager represents a system package manager
type PackageManager string

const (
	PackageManagerAPT     PackageManager = "apt"
	PackageManagerYUM     PackageManager = "yum"
	PackageManagerDNF     PackageManager = "dnf"
	PackageManagerPacman  PackageManager = "pacman"
	PackageManagerUnknown PackageManager = "unknown"
)

// OSInfo holds detected operating system information
type OSInfo struct {
	PackageManager PackageManager
	HasSudo        bool
	Distribution   string
}

var (
	osInfoOnce  sync.Once
	osInfoCache *OSInfo
)

// DetectOS detects the operating system and package manager
func DetectOS() *OSInfo {
	osInfoOnce.Do(func() {
		osInfoCache = &OSInfo{
			PackageManager: detectPackageManager(),
			HasSudo:        hasSudo(),
			Distribution:   detectDistribution(),
		}
	})
	return osInfoCache
}

// detectPackageManager identifies the available package manager
func detectPackageManager() PackageManager {
	managers := []struct {
		name PackageManager
		cmd  string
	}{
		{PackageManagerAPT, "apt-get"},
		{PackageManagerDNF, "dnf"},
		{PackageManagerYUM, "yum"},
		{PackageManagerPacman, "pacman"},
	}

	for _, mgr := range managers {
		if _, err := exec.LookPath(mgr.cmd); err == nil {
			return mgr.name
		}
	}

	return PackageManagerUnknown
}

// hasSudo checks if sudo is available
func hasSudo() bool {
	_, err := exec.LookPath("sudo")
	return err == nil
}

// detectDistribution tries to detect the Linux distribution
func detectDistribution() string {
	result := QuickExec(context.Background(), "cat", "/etc/os-release")
	if result.Error != nil {
		return "unknown"
	}

	lines := strings.Split(result.Stdout, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "ID=") {
			return strings.Trim(strings.TrimPrefix(line, "ID="), `"`)
		}
	}

	return "unknown"
}

// GetPackageManagerCommand returns the appropriate package manager command
func (o *OSInfo) GetPackageManagerCommand() string {
	switch o.PackageManager {
	case PackageManagerAPT:
		return "apt-get"
	case PackageManagerYUM:
		return "yum"
	case PackageManagerDNF:
		return "dnf"
	case PackageManagerPacman:
		return "pacman"
	default:
		return ""
	}
}

// GetUpdateCommand returns the command to update package lists
func (o *OSInfo) GetUpdateCommand() []string {
	switch o.PackageManager {
	case PackageManagerAPT:
		return []string{"apt-get", "update"}
	case PackageManagerYUM:
		return []string{"yum", "check-update"}
	case PackageManagerDNF:
		return []string{"dnf", "check-update"}
	case PackageManagerPacman:
		return []string{"pacman", "-Sy"}
	default:
		return nil
	}
}

// GetUpgradeCommand returns the command to upgrade all packages
func (o *OSInfo) GetUpgradeCommand() []string {
	switch o.PackageManager {
	case PackageManagerAPT:
		return []string{"apt-get", "upgrade", "-y"}
	case PackageManagerYUM:
		return []string{"yum", "update", "-y"}
	case PackageManagerDNF:
		return []string{"dnf", "upgrade", "-y"}
	case PackageManagerPacman:
		return []string{"pacman", "-Syu", "--noconfirm"}
	default:
		return nil
	}
}

// PrefixSudo adds sudo to a command if available and needed
func (o *OSInfo) PrefixSudo(cmd []string) []string {
	if o.HasSudo && len(cmd) > 0 {
		return append([]string{"sudo"}, cmd...)
	}
	return cmd
}
