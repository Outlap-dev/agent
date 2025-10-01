// Package ipc provides Inter-Process Communication between supervisor and worker processes
package ipc

import (
	"encoding/json"
	"fmt"
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
	// System operations
	OpSystemReboot         OperationType = "system.reboot"
	OpSystemShutdown       OperationType = "system.shutdown"
	OpSystemUpdatePackages OperationType = "system.update_packages"
	OpSystemInstallPackage OperationType = "system.install_package"

	// Service management operations
	OpServiceRestart OperationType = "service.restart"
	OpServiceStart   OperationType = "service.start"
	OpServiceStop    OperationType = "service.stop"
	OpServiceStatus  OperationType = "service.status"

	// Docker operations
	OpDockerStart          OperationType = "docker.start"
	OpDockerStop           OperationType = "docker.stop"
	OpDockerRestart        OperationType = "docker.restart"
	OpDockerRemove         OperationType = "docker.remove"
	OpDockerCreate         OperationType = "docker.create"
	OpDockerBuild          OperationType = "docker.build"
	OpDockerPull           OperationType = "docker.pull"
	OpDockerExec           OperationType = "docker.exec"
	OpDockerLogs           OperationType = "docker.logs"
	OpDockerListContainers OperationType = "docker.list_containers"
	OpDockerPrune          OperationType = "docker.prune"

	// File system operations
	OpFileWritePrivileged  OperationType = "file.write_privileged"
	OpFileReadPrivileged   OperationType = "file.read_privileged"
	OpFileDeletePrivileged OperationType = "file.delete_privileged"
	OpFileChmodPrivileged  OperationType = "file.chmod_privileged"
	OpFileChownPrivileged  OperationType = "file.chown_privileged"

	// Agent management operations
	OpAgentUpdate  OperationType = "agent.update"
	OpAgentRestart OperationType = "agent.restart"

	// Caddy operations
	OpCaddyInstall      OperationType = "caddy.install"
	OpCaddyRestart      OperationType = "caddy.restart"
	OpCaddyReload       OperationType = "caddy.reload"
	OpCaddyAddSite      OperationType = "caddy.add_site"
	OpCaddyRemoveSite   OperationType = "caddy.remove_site"
	OpCaddyUpdateConfig OperationType = "caddy.update_config"
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
	return &SocketConfig{
		SocketPath: "/var/run/pulseup/supervisor.sock",
		SocketMode: 0660, // rw-rw----
		SocketUID:  0,    // root
		SocketGID:  1000, // pulseup group (to be determined)
		Timeout:    30 * time.Second,
		BufferSize: 4096,
	}
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
		OpSystemReboot: {
			RequiresConfirmation: true,
			RateLimited:          true,
			MaxCallsPerMinute:    3,
			RequiredArgs:         []string{},
			AllowConcurrent:      false,
			MaxTimeout:           30 * time.Second,
			Description:          "Reboot the server",
		},
		OpSystemShutdown: {
			RequiresConfirmation: true,
			RateLimited:          true,
			MaxCallsPerMinute:    3,
			RequiredArgs:         []string{},
			AllowConcurrent:      false,
			MaxTimeout:           30 * time.Second,
			Description:          "Shutdown the server",
		},
		OpSystemUpdatePackages: {
			RequiresConfirmation: true,
			RateLimited:          true,
			MaxCallsPerMinute:    30,
			RequiredArgs:         []string{},
			OptionalArgs:         []string{"packages"},
			AllowConcurrent:      false,
			MaxTimeout:           30 * time.Minute,
			Description:          "Update system packages",
		},
		OpSystemInstallPackage: {
			RequiresConfirmation: false,
			RateLimited:          true,
			MaxCallsPerMinute:    30,
			RequiredArgs:         []string{"package_name"},
			AllowConcurrent:      true,
			MaxTimeout:           10 * time.Minute,
			Description:          "Install a system package",
		},
		OpServiceRestart: {
			RequiresConfirmation: false,
			RateLimited:          true,
			MaxCallsPerMinute:    30,
			RequiredArgs:         []string{"service_name"},
			AllowConcurrent:      true,
			MaxTimeout:           2 * time.Minute,
			Description:          "Restart a system service",
		},
		OpDockerStart: {
			RequiresConfirmation: false,
			RateLimited:          false,
			RequiredArgs:         []string{"container_id"},
			AllowConcurrent:      true,
			MaxTimeout:           2 * time.Minute,
			Description:          "Start a Docker container",
		},
		OpDockerStop: {
			RequiresConfirmation: false,
			RateLimited:          false,
			RequiredArgs:         []string{"container_id"},
			AllowConcurrent:      true,
			MaxTimeout:           2 * time.Minute,
			Description:          "Stop a Docker container",
		},
		OpDockerRestart: {
			RequiresConfirmation: false,
			RateLimited:          false,
			RequiredArgs:         []string{"container_id"},
			AllowConcurrent:      true,
			MaxTimeout:           2 * time.Minute,
			Description:          "Restart a Docker container",
		},
		OpDockerRemove: {
			RequiresConfirmation: false,
			RateLimited:          true,
			MaxCallsPerMinute:    20,
			RequiredArgs:         []string{"container_id"},
			AllowConcurrent:      true,
			MaxTimeout:           2 * time.Minute,
			Description:          "Remove a Docker container",
		},
		OpDockerCreate: {
			RequiresConfirmation: false,
			RateLimited:          false,
			RequiredArgs:         []string{"image", "container_name"},
			OptionalArgs:         []string{"env_vars", "ports", "volumes", "networks"},
			AllowConcurrent:      true,
			MaxTimeout:           10 * time.Minute,
			Description:          "Create a Docker container",
		},
		OpDockerBuild: {
			RequiresConfirmation: false,
			RateLimited:          true,
			MaxCallsPerMinute:    5,
			RequiredArgs:         []string{"build_context", "tags"},
			AllowConcurrent:      true,
			MaxTimeout:           30 * time.Minute,
			Description:          "Build a Docker image",
		},
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
		OpAgentRestart: {
			RequiresConfirmation: false,
			RateLimited:          true,
			MaxCallsPerMinute:    5,
			RequiredArgs:         []string{},
			AllowConcurrent:      false,
			MaxTimeout:           1 * time.Minute,
			Description:          "Restart the agent",
		},
		OpFileWritePrivileged: {
			RequiresConfirmation: false,
			RateLimited:          true,
			MaxCallsPerMinute:    50,
			RequiredArgs:         []string{"file_path", "content"},
			OptionalArgs:         []string{"mode", "owner", "group"},
			AllowConcurrent:      true,
			MaxTimeout:           1 * time.Minute,
			Description:          "Write to a privileged file location",
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
