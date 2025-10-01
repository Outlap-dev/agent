// Package retry provides configurable retry mechanisms for WebSocket connections
package retry

import (
	"time"
)

// Config holds retry configuration
type Config struct {
	// Initial delay before first retry
	InitialDelay time.Duration `json:"initial_delay" yaml:"initial_delay"`
	
	// Maximum delay between retries
	MaxDelay time.Duration `json:"max_delay" yaml:"max_delay"`
	
	// Factor to multiply delay by for each retry (exponential backoff)
	BackoffFactor float64 `json:"backoff_factor" yaml:"backoff_factor"`
	
	// Maximum number of retry attempts (0 = unlimited)
	MaxAttempts int `json:"max_attempts" yaml:"max_attempts"`
	
	// Maximum total time to spend retrying (0 = unlimited)
	MaxTotalTime time.Duration `json:"max_total_time" yaml:"max_total_time"`
	
	// Amount of jitter to add (as percentage of delay, 0.0-1.0)
	JitterFactor float64 `json:"jitter_factor" yaml:"jitter_factor"`
	
	// Whether retry is enabled at all
	Enabled bool `json:"enabled" yaml:"enabled"`
}

// DefaultConfig returns a retry configuration with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		InitialDelay:  1 * time.Second,
		MaxDelay:      60 * time.Second,
		BackoffFactor: 2.0,
		MaxAttempts:   0, // unlimited
		MaxTotalTime:  0, // unlimited
		JitterFactor:  0.1,
		Enabled:       true,
	}
}

// AggressiveConfig returns a configuration for aggressive retrying
func AggressiveConfig() *Config {
	return &Config{
		InitialDelay:  500 * time.Millisecond,
		MaxDelay:      10 * time.Second,
		BackoffFactor: 1.5,
		MaxAttempts:   0, // unlimited
		MaxTotalTime:  0, // unlimited
		JitterFactor:  0.2,
		Enabled:       true,
	}
}

// ConservativeConfig returns a configuration for conservative retrying
func ConservativeConfig() *Config {
	return &Config{
		InitialDelay:  5 * time.Second,
		MaxDelay:      5 * time.Minute,
		BackoffFactor: 2.5,
		MaxAttempts:   10,
		MaxTotalTime:  30 * time.Minute,
		JitterFactor:  0.05,
		Enabled:       true,
	}
}

// DisabledConfig returns a configuration with retries disabled
func DisabledConfig() *Config {
	return &Config{
		Enabled: false,
	}
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if !c.Enabled {
		return nil
	}
	
	if c.InitialDelay <= 0 {
		c.InitialDelay = 1 * time.Second
	}
	
	if c.MaxDelay <= 0 {
		c.MaxDelay = 60 * time.Second
	}
	
	if c.BackoffFactor <= 1.0 {
		c.BackoffFactor = 2.0
	}
	
	if c.JitterFactor < 0 {
		c.JitterFactor = 0
	} else if c.JitterFactor > 1.0 {
		c.JitterFactor = 1.0
	}
	
	if c.MaxAttempts < 0 {
		c.MaxAttempts = 0
	}
	
	return nil
}

// AuthRetryConfig holds retry configuration specifically for authentication
type AuthRetryConfig struct {
	// Maximum number of consecutive auth failures before giving up
	MaxConsecutiveFailures int `json:"max_consecutive_failures"`
	
	// Time to wait after max failures before allowing retries again
	CooldownPeriod time.Duration `json:"cooldown_period"`
	
	// Time to wait after a permanent failure (e.g., invalid token) before allowing retries
	PermanentFailureCooldown time.Duration `json:"permanent_failure_cooldown"`
	
	// Whether to use exponential backoff for auth retries
	UseExponentialBackoff bool `json:"use_exponential_backoff"`
	
	// Base configuration for retries
	*Config
}

// DefaultAuthRetryConfig returns auth retry configuration with sensible defaults
func DefaultAuthRetryConfig() *AuthRetryConfig {
	return &AuthRetryConfig{
		MaxConsecutiveFailures:   5,
		CooldownPeriod:          5 * time.Minute,
		PermanentFailureCooldown: 1 * time.Hour,
		UseExponentialBackoff:    true,
		Config:                   DefaultConfig(),
	}
}

// ConnectionRetryConfig holds retry configuration for connection attempts
type ConnectionRetryConfig struct {
	// Whether to enable automatic reconnection
	EnableAutoReconnect bool `json:"enable_auto_reconnect"`
	
	// Base configuration for retries
	*Config
}

// DefaultConnectionRetryConfig returns connection retry configuration with sensible defaults
func DefaultConnectionRetryConfig() *ConnectionRetryConfig {
	return &ConnectionRetryConfig{
		EnableAutoReconnect: true,
		Config:              DefaultConfig(),
	}
}