// Package ipc provides Inter-Process Communication between supervisor and worker processes
package ipc

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// PrivilegedRequest represents a request from worker to supervisor for a privileged operation
type PrivilegedRequest struct {
	ID        string                 `json:"id"`
	Operation string                 `json:"operation"`
	Args      map[string]interface{} `json:"args"`
	Timestamp time.Time              `json:"timestamp"`
	WorkerPID int                    `json:"worker_pid"`
}

// PrivilegedResponse represents the supervisor's response to a privileged request
type PrivilegedResponse struct {
	ID      string                 `json:"id"`
	Success bool                   `json:"success"`
	Data    map[string]interface{} `json:"data,omitempty"`
	Error   string                 `json:"error,omitempty"`
	Took    time.Duration          `json:"took,omitempty"`
}

// OperationType represents the type of privileged operation
type OperationType string

const (
	// Agent management operations
	OpAgentUpdate OperationType = "agent.update"
)

// OperationConfig defines configuration for a privileged operation
type OperationConfig struct {
	// Whether this operation requires explicit user confirmation
	RequiresConfirmation bool `json:"requires_confirmation"`

	// Whether this operation is rate limited
	RateLimited bool `json:"rate_limited"`

	// Maximum calls per minute (if rate limited)
	MaxCallsPerMinute int `json:"max_calls_per_minute"`

	// Required arguments for this operation
	RequiredArgs []string `json:"required_args"`

	// Optional arguments for this operation
	OptionalArgs []string `json:"optional_args"`

	// Whether this operation can be performed while other operations are running
	AllowConcurrent bool `json:"allow_concurrent"`

	// Maximum timeout for this operation
	MaxTimeout time.Duration `json:"max_timeout"`

	// Description of what this operation does (for audit logs)
	Description string `json:"description"`
}

// RequestValidationError represents a validation error for a privileged request
type RequestValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

func (e RequestValidationError) Error() string {
	return fmt.Sprintf("validation error for field '%s': %s", e.Field, e.Message)
}

// Message represents a raw IPC message
type Message struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

// MessageType represents the type of IPC message
type MessageType string

const (
	MessageTypeRequest   MessageType = "request"
	MessageTypeResponse  MessageType = "response"
	MessageTypeHeartbeat MessageType = "heartbeat"
	MessageTypeShutdown  MessageType = "shutdown"
)

// HeartbeatMessage represents a heartbeat message between processes
type HeartbeatMessage struct {
	ProcessType string    `json:"process_type"` // "supervisor" or "worker"
	PID         int       `json:"pid"`
	Timestamp   time.Time `json:"timestamp"`
	Status      string    `json:"status"`
}

// SocketConfig represents configuration for the IPC socket
type SocketConfig struct {
	// Path to the Unix domain socket
	SocketPath string `json:"socket_path"`

	// Socket file permissions
	SocketMode uint32 `json:"socket_mode"`

	// Socket owner user ID
	SocketUID int `json:"socket_uid"`

	// Socket owner group ID
	SocketGID int `json:"socket_gid"`

	// Timeout for socket operations
	Timeout time.Duration `json:"timeout"`

	// Buffer size for socket communication
	BufferSize int `json:"buffer_size"`
}

// DefaultSocketConfig returns default socket configuration
func DefaultSocketConfig() *SocketConfig {
	return DefaultSocketConfigWithGroup("")
}

// DefaultSocketConfigWithGroup returns the default socket configuration with the provided group name.
func DefaultSocketConfigWithGroup(groupName string) *SocketConfig {
	return buildSocketConfig(groupName)
}

func buildSocketConfig(groupName string) *SocketConfig {
	gid := os.Getegid()
	candidate := strings.TrimSpace(groupName)
	if candidate == "" {
		candidate = strings.TrimSpace(os.Getenv("PULSEUP_AGENT_GROUP"))
	}

	if candidate != "" {
		if resolved, err := lookupGroupID(candidate); err == nil {
			gid = resolved
		}
	}

	return &SocketConfig{
		SocketPath: "/var/run/pulseup/supervisor.sock",
		SocketMode: 0660, // rw-rw----
		SocketUID:  0,    // root
		SocketGID:  gid,
		Timeout:    30 * time.Second,
		BufferSize: 4096,
	}
}

func lookupGroupID(groupName string) (int, error) {
	file, err := os.Open("/etc/group")
	if err != nil {
		return 0, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Split(line, ":")
		if len(parts) < 3 {
			continue
		}
		if parts[0] != groupName {
			continue
		}

		gid, err := strconv.Atoi(parts[2])
		if err != nil {
			return 0, err
		}
		return gid, nil
	}

	if err := scanner.Err(); err != nil {
		return 0, err
	}

	return 0, fmt.Errorf("group %q not found", groupName)
}

// ValidateRequest performs basic validation on a privileged request
func (r *PrivilegedRequest) Validate() error {
	if r.ID == "" {
		return RequestValidationError{Field: "id", Message: "request ID is required"}
	}

	if r.Operation == "" {
		return RequestValidationError{Field: "operation", Message: "operation is required"}
	}

	if r.Timestamp.IsZero() {
		return RequestValidationError{Field: "timestamp", Message: "timestamp is required"}
	}

	// Check if timestamp is too old (prevent replay attacks)
	if time.Since(r.Timestamp) > 5*time.Minute {
		return RequestValidationError{Field: "timestamp", Message: "request timestamp is too old"}
	}

	// Check if timestamp is in the future (clock skew protection)
	if r.Timestamp.After(time.Now().Add(1 * time.Minute)) {
		return RequestValidationError{Field: "timestamp", Message: "request timestamp is in the future"}
	}

	if r.WorkerPID <= 0 {
		return RequestValidationError{Field: "worker_pid", Message: "valid worker PID is required"}
	}

	return nil
}

// GetOperationConfig returns the configuration for a specific operation type
func GetOperationConfig(op OperationType) (*OperationConfig, error) {
	configs := map[OperationType]*OperationConfig{
		OpAgentUpdate: {
			RequiresConfirmation: true,
			RateLimited:          true,
			MaxCallsPerMinute:    1,
			RequiredArgs:         []string{"update_file_path"},
			OptionalArgs:         []string{"signature"},
			AllowConcurrent:      false,
			MaxTimeout:           5 * time.Minute,
			Description:          "Update the agent binary",
		},
	}

	config, exists := configs[op]
	if !exists {
		return nil, fmt.Errorf("unknown operation type: %s", op)
	}

	return config, nil
}

// IsValidOperation checks if an operation type is valid
func IsValidOperation(op OperationType) bool {
	_, err := GetOperationConfig(op)
	return err == nil
}
