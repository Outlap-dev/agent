package types

// Package represents information about a system package
type Package struct {
	Name            string `json:"name"`
	CurrentVersion  string `json:"current_version"`
	NewVersion      string `json:"new_version"`
	Architecture    string `json:"architecture"`
	Size            string `json:"size"`
	Description     string `json:"description"`
}

// UpgradablePackages represents the list of packages that can be upgraded
type UpgradablePackages struct {
	Packages     []Package `json:"packages"`
	TotalCount   int       `json:"total_count"`
	TotalSize    string    `json:"total_size"`
	LastChecked  string    `json:"last_checked"`
}

// PackageUpdateResult represents the result of a package update operation
type PackageUpdateResult struct {
	UpdatedPackages []Package `json:"updated_packages"`
	FailedPackages  []string  `json:"failed_packages"`
	Success         bool      `json:"success"`
	Message         string    `json:"message"`
	Errors          []string  `json:"errors"`
}

// PackageInfo represents detailed information about a specific package
type PackageInfo struct {
	Name         string   `json:"name"`
	Version      string   `json:"version"`
	Description  string   `json:"description"`
	Installed    bool     `json:"installed"`
	Upgradable   bool     `json:"upgradable"`
	NewVersion   string   `json:"new_version,omitempty"`
	Dependencies []string `json:"dependencies"`
	Size         string   `json:"size"`
}

// PackageLogMessage represents a log message from package operations
type PackageLogMessage struct {
	Message   string `json:"message"`
	Level     string `json:"level"` // "info", "error", "warning", "debug"
	Timestamp int64  `json:"timestamp"`
}