package config

import (
	"fmt"
	"os"
	"strings"
)

// Build-time variables set by ldflags
var (
	Version   = ""
	BuildDate = ""
	GitCommit = ""
)

const versionEnvKey = "OUTLAP_AGENT_VERSION"

// Config holds the application configuration
type Config struct {
	WebSocketURL         string
	APIBaseURL           string
	ServerPort           int
	Debug                bool
	DockerHost           string
	LogLevel             string
	ReconnectDelay       int
	MaxReconnects        int
	EnableCaddy          bool
	CaddyConfigDir       string
	CaddyDataDir         string
	ReconnectEnabled     bool
	ReconnectMaxAttempts int
	ReconnectInterval    int
	ReconnectBackoffMax  int
	// Authentication configuration
	AuthWaitForConfirmation      bool
	AuthPermanentFailureCooldown int // in seconds

	// Update configuration
	UpdateEnabled       bool
	UpdateAutoApply     bool
	UpdateIntervalHours int
	UpdatePublicKeyPath string
	UpdateRepository    string
	UpdateRequestPath   string
	UpdateManifestURL   string

	// mTLS and enrollment configuration
	CertDir     string
	JoinToken   string
	SocketGroup string
}

// Load loads configuration from environment variables
func Load() (*Config, error) {
	config := &Config{
		WebSocketURL:                 getEnv("WEBSOCKET_URL", "ws://host.docker.internal:8000/ws"),
		APIBaseURL:                   getEnv("API_BASE_URL", "http://host.docker.internal:8000"),
		ServerPort:                   getEnvInt("SERVER_PORT", 8080),
		Debug:                        getEnvBool("DEBUG", false),
		DockerHost:                   getEnv("DOCKER_HOST", ""),
		LogLevel:                     getEnv("LOG_LEVEL", "info"),
		ReconnectDelay:               getEnvInt("RECONNECT_DELAY", 5),
		MaxReconnects:                getEnvInt("MAX_RECONNECTS", 10),
		EnableCaddy:                  getEnvBool("ENABLE_CADDY", true),
		CaddyConfigDir:               getEnv("CADDY_CONFIG_DIR", "/etc/outlap-agent/caddy"),
		CaddyDataDir:                 getEnv("CADDY_DATA_DIR", "/etc/outlap-agent/caddy/data"),
		ReconnectEnabled:             getEnvBool("RECONNECT_ENABLED", true),
		ReconnectMaxAttempts:         getEnvInt("RECONNECT_MAX_ATTEMPTS", 10),
		ReconnectInterval:            getEnvInt("RECONNECT_INTERVAL", 5),
		ReconnectBackoffMax:          getEnvInt("RECONNECT_BACKOFF_MAX", 60),
		AuthWaitForConfirmation:      getEnvBool("AUTH_WAIT_FOR_CONFIRMATION", true),
		AuthPermanentFailureCooldown: getEnvInt("AUTH_PERMANENT_FAILURE_COOLDOWN", 3600), // 1 hour
		UpdateEnabled:                getEnvBool("UPDATE_ENABLED", false),                // Disabled by default for safety
		UpdateAutoApply:              getEnvBool("UPDATE_AUTO_APPLY", false),
		UpdateIntervalHours:          getEnvInt("UPDATE_INTERVAL_HOURS", 0),
		UpdatePublicKeyPath:          getEnv("UPDATE_PUBLIC_KEY_PATH", "/etc/outlap-agent/update_public.pem"),
		UpdateRepository:             resolveUpdateRepository(),
		UpdateRequestPath:            getEnv("UPDATE_REQUEST_PATH", "/run/outlap/update.request"),
		UpdateManifestURL:            getEnv("UPDATE_MANIFEST_URL", ""),

		// mTLS and enrollment configuration
		CertDir:     getEnv("CERT_DIR", "/var/lib/outlap/certs"),
		JoinToken:   getEnv("JOIN_TOKEN", ""),
		SocketGroup: getEnv("OUTLAP_AGENT_GROUP", "outlap"),
	}

	// Validate required fields
	if config.WebSocketURL == "" {
		return nil, fmt.Errorf("WEBSOCKET_URL is required")
	}

	return config, nil
}

// ParseVersion parses a version string into a slice of integers
func ParseVersion(versionStr string) []int {
	if versionStr == "" {
		return []int{0, 0, 0}
	}

	// Remove 'v' prefix if present
	if versionStr[0] == 'v' {
		versionStr = versionStr[1:]
	}

	// Split by dots and convert to integers
	parts := strings.Split(versionStr, ".")
	result := make([]int, len(parts))

	for i, part := range parts {
		// Remove any non-numeric suffixes (like "-beta", "-alpha", etc.)
		numericPart := ""
		for _, char := range part {
			if char >= '0' && char <= '9' {
				numericPart += string(char)
			} else {
				break
			}
		}

		if numericPart == "" {
			result[i] = 0
		} else {
			result[i] = parseInt(numericPart)
		}
	}

	// Ensure at least 3 parts (major.minor.patch)
	for len(result) < 3 {
		result = append(result, 0)
	}

	return result
}

// IsNewerVersion checks if the latest version is newer than the current version
func IsNewerVersion(current, latest string) bool {
	currentParts := ParseVersion(current)
	latestParts := ParseVersion(latest)

	// Compare versions part by part
	maxLen := len(currentParts)
	if len(latestParts) > maxLen {
		maxLen = len(latestParts)
	}

	// Pad shorter version with zeros
	for len(currentParts) < maxLen {
		currentParts = append(currentParts, 0)
	}
	for len(latestParts) < maxLen {
		latestParts = append(latestParts, 0)
	}

	for i := 0; i < maxLen; i++ {
		if latestParts[i] > currentParts[i] {
			return true
		} else if latestParts[i] < currentParts[i] {
			return false
		}
	}

	return false // Versions are equal
}

// GetVersionString returns the current version string
func GetVersionString() string {
	if v := strings.TrimSpace(Version); v != "" {
		return v
	}

	if envVersion := strings.TrimSpace(os.Getenv(versionEnvKey)); envVersion != "" {
		return envVersion
	}

	if commit := strings.TrimSpace(GitCommit); commit != "" {
		if len(commit) > 7 {
			commit = commit[:7]
		}
		return fmt.Sprintf("git-%s", commit)
	}

	return "development"
}

// Helper functions

func resolveUpdateRepository() string {
	if value := os.Getenv("UPDATE_REPOSITORY"); value != "" {
		return value
	}
	if legacy := os.Getenv("VERSION_CHECK_REPO"); legacy != "" {
		return legacy
	}
	return "Outlap-dev/agent"
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intVal := parseInt(value); intVal != 0 {
			return intVal
		}
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		return value == "true" || value == "1" || value == "yes"
	}
	return defaultValue
}

func parseInt(s string) int {
	var result int
	fmt.Sscanf(s, "%d", &result)
	return result
}
