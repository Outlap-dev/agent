// Package retry provides backoff implementations for retry logic
package retry

import (
	"math/rand"
	"time"
)

// Backoff represents a backoff strategy for retries
type Backoff interface {
	// Next returns the next delay duration
	Next() time.Duration
	
	// Reset resets the backoff to its initial state
	Reset()
	
	// Attempts returns the number of attempts made so far
	Attempts() int
}

// ExponentialBackoff implements exponential backoff with jitter
type ExponentialBackoff struct {
	config   *Config
	current  time.Duration
	attempts int
	rand     *rand.Rand
}

// NewExponentialBackoff creates a new exponential backoff instance
func NewExponentialBackoff(config *Config) *ExponentialBackoff {
	if err := config.Validate(); err != nil {
		config = DefaultConfig()
	}
	
	return &ExponentialBackoff{
		config:  config,
		current: config.InitialDelay,
		rand:    rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// Next returns the next delay duration with exponential backoff and jitter
func (b *ExponentialBackoff) Next() time.Duration {
	if !b.config.Enabled {
		return 0
	}
	
	delay := b.current
	
	// Apply exponential backoff
	b.current = time.Duration(float64(b.current) * b.config.BackoffFactor)
	if b.current > b.config.MaxDelay {
		b.current = b.config.MaxDelay
	}
	
	// Apply jitter if configured
	if b.config.JitterFactor > 0 {
		jitterAmount := float64(delay) * b.config.JitterFactor
		jitter := time.Duration(jitterAmount * (2*b.rand.Float64() - 1))
		delay += jitter
		
		// Ensure delay is not negative
		if delay < 0 {
			delay = b.config.InitialDelay
		}
	}
	
	b.attempts++
	return delay
}

// Reset resets the backoff to its initial state
func (b *ExponentialBackoff) Reset() {
	b.current = b.config.InitialDelay
	b.attempts = 0
}

// Attempts returns the number of attempts made so far
func (b *ExponentialBackoff) Attempts() int {
	return b.attempts
}

// ConstantBackoff implements constant delay backoff
type ConstantBackoff struct {
	config   *Config
	attempts int
}

// NewConstantBackoff creates a new constant backoff instance
func NewConstantBackoff(config *Config) *ConstantBackoff {
	if err := config.Validate(); err != nil {
		config = DefaultConfig()
	}
	
	return &ConstantBackoff{
		config: config,
	}
}

// Next returns a constant delay duration
func (b *ConstantBackoff) Next() time.Duration {
	if !b.config.Enabled {
		return 0
	}
	
	b.attempts++
	return b.config.InitialDelay
}

// Reset resets the backoff to its initial state
func (b *ConstantBackoff) Reset() {
	b.attempts = 0
}

// Attempts returns the number of attempts made so far
func (b *ConstantBackoff) Attempts() int {
	return b.attempts
}

// LinearBackoff implements linear backoff
type LinearBackoff struct {
	config   *Config
	attempts int
}

// NewLinearBackoff creates a new linear backoff instance
func NewLinearBackoff(config *Config) *LinearBackoff {
	if err := config.Validate(); err != nil {
		config = DefaultConfig()
	}
	
	return &LinearBackoff{
		config: config,
	}
}

// Next returns the next delay duration with linear increase
func (b *LinearBackoff) Next() time.Duration {
	if !b.config.Enabled {
		return 0
	}
	
	b.attempts++
	delay := time.Duration(int64(b.config.InitialDelay) * int64(b.attempts))
	
	if delay > b.config.MaxDelay {
		delay = b.config.MaxDelay
	}
	
	return delay
}

// Reset resets the backoff to its initial state
func (b *LinearBackoff) Reset() {
	b.attempts = 0
}

// Attempts returns the number of attempts made so far
func (b *LinearBackoff) Attempts() int {
	return b.attempts
}

// RetryManager manages retry attempts with configurable backoff strategies
type RetryManager struct {
	config    *Config
	backoff   Backoff
	startTime time.Time
}

// NewRetryManager creates a new retry manager with the given configuration
func NewRetryManager(config *Config) *RetryManager {
	if config == nil {
		config = DefaultConfig()
	}
	
	return &RetryManager{
		config:  config,
		backoff: NewExponentialBackoff(config),
	}
}

// NewRetryManagerWithBackoff creates a new retry manager with a custom backoff strategy
func NewRetryManagerWithBackoff(config *Config, backoff Backoff) *RetryManager {
	if config == nil {
		config = DefaultConfig()
	}
	
	return &RetryManager{
		config:  config,
		backoff: backoff,
	}
}

// ShouldRetry determines if a retry should be attempted based on the configuration
func (r *RetryManager) ShouldRetry() bool {
	if !r.config.Enabled {
		return false
	}
	
	// Check max attempts
	if r.config.MaxAttempts > 0 && r.backoff.Attempts() >= r.config.MaxAttempts {
		return false
	}
	
	// Check max total time
	if r.config.MaxTotalTime > 0 && !r.startTime.IsZero() {
		if time.Since(r.startTime) >= r.config.MaxTotalTime {
			return false
		}
	}
	
	return true
}

// NextDelay returns the next delay duration for retry
func (r *RetryManager) NextDelay() time.Duration {
	if r.startTime.IsZero() {
		r.startTime = time.Now()
	}
	
	return r.backoff.Next()
}

// Reset resets the retry manager to its initial state
func (r *RetryManager) Reset() {
	r.backoff.Reset()
	r.startTime = time.Time{}
}

// Attempts returns the number of attempts made so far
func (r *RetryManager) Attempts() int {
	return r.backoff.Attempts()
}

// AuthFailureTracker tracks authentication failures for retry logic
type AuthFailureTracker struct {
	config              *AuthRetryConfig
	consecutiveFailures int
	lastFailureTime     time.Time
	backoff             Backoff
	permanentFailure    bool
}

// NewAuthFailureTracker creates a new auth failure tracker
func NewAuthFailureTracker(config *AuthRetryConfig) *AuthFailureTracker {
	if config == nil {
		config = DefaultAuthRetryConfig()
	}
	
	var backoff Backoff
	if config.UseExponentialBackoff {
		backoff = NewExponentialBackoff(config.Config)
	} else {
		backoff = NewConstantBackoff(config.Config)
	}
	
	return &AuthFailureTracker{
		config:  config,
		backoff: backoff,
	}
}

// RecordFailure records an authentication failure
func (t *AuthFailureTracker) RecordFailure() {
	t.consecutiveFailures++
	t.lastFailureTime = time.Now()
}

// RecordSuccess records an authentication success (resets failure count)
func (t *AuthFailureTracker) RecordSuccess() {
	t.consecutiveFailures = 0
	t.permanentFailure = false
	t.backoff.Reset()
}

// RecordPermanentFailure records a permanent authentication failure (e.g., invalid token)
func (t *AuthFailureTracker) RecordPermanentFailure() {
	t.permanentFailure = true
	t.lastFailureTime = time.Now()
}

// ShouldRetryAuth determines if authentication should be retried
func (t *AuthFailureTracker) ShouldRetryAuth() bool {
	if !t.config.Enabled {
		return false
	}
	
	// If we have a permanent failure (like invalid token), check if we're in extended cooldown
	if t.permanentFailure {
		// Use a much longer cooldown for permanent failures
		extendedCooldown := t.config.PermanentFailureCooldown
		if extendedCooldown == 0 {
			// Default to 1 hour if not configured
			extendedCooldown = 1 * time.Hour
		}
		
		if time.Since(t.lastFailureTime) < extendedCooldown {
			return false
		}
		// Reset permanent failure flag after extended cooldown
		t.permanentFailure = false
	}
	
	// Check if we've exceeded max consecutive failures
	if t.consecutiveFailures >= t.config.MaxConsecutiveFailures {
		// Check if cooldown period has passed
		if time.Since(t.lastFailureTime) < t.config.CooldownPeriod {
			return false
		}
		// Reset failure count after cooldown
		t.consecutiveFailures = 0
		t.backoff.Reset()
	}
	
	return true
}

// NextAuthDelay returns the next delay for authentication retry
func (t *AuthFailureTracker) NextAuthDelay() time.Duration {
	return t.backoff.Next()
}

// GetFailureInfo returns current failure information
func (t *AuthFailureTracker) GetFailureInfo() (count int, lastFailure time.Time) {
	return t.consecutiveFailures, t.lastFailureTime
}

// IsPermanentFailure returns true if we're in permanent failure mode
func (t *AuthFailureTracker) IsPermanentFailure() bool {
	return t.permanentFailure
}

// GetNextRetryTime returns when the next retry will be allowed
func (t *AuthFailureTracker) GetNextRetryTime() time.Time {
	if t.permanentFailure {
		cooldown := t.config.PermanentFailureCooldown
		if cooldown == 0 {
			cooldown = 1 * time.Hour
		}
		return t.lastFailureTime.Add(cooldown)
	}
	return t.lastFailureTime.Add(t.config.CooldownPeriod)
}