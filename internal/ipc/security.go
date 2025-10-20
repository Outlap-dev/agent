// Package ipc provides security validation for inter-process communication
package ipc

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// RequestValidator provides comprehensive validation for privileged requests
type RequestValidator struct {
	mu           sync.RWMutex
	rateLimiters map[OperationType]*RateLimiter
	allowedPaths map[string]bool
	blockedPaths map[string]bool
	allowedDirs  []string // Configurable allowed directories
	trustedPIDs  map[int]bool
	auditLogger  AuditLogger
}

// RateLimiter implements rate limiting for operations
type RateLimiter struct {
	mu        sync.Mutex
	lastReset time.Time
	count     int
	maxCalls  int
	window    time.Duration
}

// AuditLogger interface for logging security events
type AuditLogger interface {
	LogSecurityEvent(event SecurityEvent)
}

// SecurityEvent represents a security-relevant event
type SecurityEvent struct {
	Timestamp   time.Time              `json:"timestamp"`
	EventType   string                 `json:"event_type"`
	Operation   OperationType          `json:"operation"`
	WorkerPID   int                    `json:"worker_pid"`
	Allowed     bool                   `json:"allowed"`
	Reason      string                 `json:"reason"`
	RequestArgs map[string]interface{} `json:"request_args,omitempty"`
	ClientInfo  ClientInfo             `json:"client_info,omitempty"`
}

// ClientInfo contains information about the requesting client
type ClientInfo struct {
	PID  int    `json:"pid"`
	UID  int    `json:"uid"`
	GID  int    `json:"gid"`
	Comm string `json:"comm"` // command name
}

// NewRequestValidator creates a new request validator with configurable allowed directories
func NewRequestValidator(auditLogger AuditLogger) *RequestValidator {
	// Default allowed directories - these will be validated for existence
	defaultAllowedDirs := []string{
		"/opt/pulseup/",
		"/etc/pulseup-agent/",
		"/var/lib/pulseup/",
		"/var/log/pulseup/",
		"/tmp/pulseup/",
	}

	validator := &RequestValidator{
		rateLimiters: make(map[OperationType]*RateLimiter),
		allowedPaths: make(map[string]bool),
		blockedPaths: make(map[string]bool),
		allowedDirs:  validateAndFilterDirs(defaultAllowedDirs),
		trustedPIDs:  make(map[int]bool),
		auditLogger:  auditLogger,
	}

	return validator
}

// validateAndFilterDirs validates that directories exist or can be created
func validateAndFilterDirs(dirs []string) []string {
	var validDirs []string

	for _, dir := range dirs {
		// Check if directory exists
		if _, err := os.Stat(dir); err == nil {
			validDirs = append(validDirs, dir)
			continue
		}

		// Try to create the directory if it doesn't exist
		if err := os.MkdirAll(dir, 0755); err == nil {
			validDirs = append(validDirs, dir)
		}
		// If we can't create it, we skip it (could log this if needed)
	}

	return validDirs
}

// ValidateRequest performs comprehensive validation of a privileged request
func (v *RequestValidator) ValidateRequest(req *PrivilegedRequest, clientInfo ClientInfo) error {
	// Basic request validation
	if err := req.Validate(); err != nil {
		v.logSecurityEvent("request_validation_failed", req, clientInfo, false, err.Error())
		return fmt.Errorf("request validation failed: %w", err)
	}

	// Validate operation type
	op := OperationType(req.Operation)
	if !IsValidOperation(op) {
		v.logSecurityEvent("invalid_operation", req, clientInfo, false, "unknown operation type")
		return fmt.Errorf("invalid operation type: %s", req.Operation)
	}

	// Get operation configuration
	config, err := GetOperationConfig(op)
	if err != nil {
		v.logSecurityEvent("config_error", req, clientInfo, false, err.Error())
		return fmt.Errorf("failed to get operation config: %w", err)
	}

	// Validate client process
	if err := v.validateClient(clientInfo, req); err != nil {
		v.logSecurityEvent("client_validation_failed", req, clientInfo, false, err.Error())
		return fmt.Errorf("client validation failed: %w", err)
	}

	// Check rate limiting
	if config.RateLimited {
		if err := v.checkRateLimit(op, config); err != nil {
			v.logSecurityEvent("rate_limit_exceeded", req, clientInfo, false, err.Error())
			return fmt.Errorf("rate limit exceeded: %w", err)
		}
	}

	// Validate required arguments
	if err := v.validateArguments(req.Args, config); err != nil {
		v.logSecurityEvent("argument_validation_failed", req, clientInfo, false, err.Error())
		return fmt.Errorf("argument validation failed: %w", err)
	}

	// Perform operation-specific validation
	if err := v.validateOperationSpecific(op, req.Args); err != nil {
		v.logSecurityEvent("operation_validation_failed", req, clientInfo, false, err.Error())
		return fmt.Errorf("operation-specific validation failed: %w", err)
	}

	// Log successful validation
	v.logSecurityEvent("request_validated", req, clientInfo, true, "request passed all validation checks")

	return nil
}

// validateClient validates the requesting client process
func (v *RequestValidator) validateClient(clientInfo ClientInfo, req *PrivilegedRequest) error {
	// Verify PID matches
	if clientInfo.PID != req.WorkerPID {
		return fmt.Errorf("PID mismatch: request claims %d, client is %d", req.WorkerPID, clientInfo.PID)
	}

	// Check if process exists
	if _, err := os.FindProcess(clientInfo.PID); err != nil {
		return fmt.Errorf("process %d not found", clientInfo.PID)
	}

	// Verify the process is actually our worker
	expectedComm := "pulseup-worker"
	if !strings.Contains(clientInfo.Comm, expectedComm) {
		return fmt.Errorf("unexpected process name: %s (expected: %s)", clientInfo.Comm, expectedComm)
	}

	// Check if client is in trusted PIDs (if we're maintaining such a list)
	v.mu.RLock()
	trusted := v.trustedPIDs[clientInfo.PID]
	v.mu.RUnlock()

	if !trusted {
		// For now, we'll trust any pulseup-worker process
		// In production, we might want to maintain a registry of trusted PIDs
		v.mu.Lock()
		v.trustedPIDs[clientInfo.PID] = true
		v.mu.Unlock()
	}

	return nil
}

// validateArguments validates the arguments for an operation
func (v *RequestValidator) validateArguments(args map[string]interface{}, config *OperationConfig) error {
	// Check required arguments
	for _, requiredArg := range config.RequiredArgs {
		if _, exists := args[requiredArg]; !exists {
			return fmt.Errorf("missing required argument: %s", requiredArg)
		}
	}

	// Validate argument types and values
	for argName, argValue := range args {
		if err := v.validateArgument(argName, argValue); err != nil {
			return fmt.Errorf("invalid argument %s: %w", argName, err)
		}
	}

	return nil
}

// validateArgument validates a specific argument
func (v *RequestValidator) validateArgument(name string, value interface{}) error {
	strValue, ok := value.(string)
	if !ok {
		// For non-string arguments, we'll do basic type checking
		switch name {
		case "port", "timeout", "retries", "container_id":
			if _, ok := value.(float64); !ok {
				return fmt.Errorf("expected numeric value for %s", name)
			}
		case "env_vars", "ports", "volumes", "networks":
			// These can be maps or slices
			return nil
		}
		return nil
	}

	// Validate string arguments
	switch name {
	case "file_path":
		return v.validateFilePath(strValue)
	case "package_name":
		return v.validatePackageName(strValue)
	case "service_name":
		return v.validateServiceName(strValue)
	case "command":
		return v.validateCommand(strValue)
	}

	return nil
}

// validateFilePath validates file paths to prevent directory traversal attacks
func (v *RequestValidator) validateFilePath(path string) error {
	// Clean the path
	cleanPath := filepath.Clean(path)

	// Check for directory traversal
	if strings.Contains(cleanPath, "..") {
		return fmt.Errorf("directory traversal detected in path: %s", path)
	}

	// Check against blocked paths
	v.mu.RLock()
	for blockedPath := range v.blockedPaths {
		if strings.HasPrefix(cleanPath, blockedPath) {
			v.mu.RUnlock()
			return fmt.Errorf("access to blocked path: %s", path)
		}
	}
	v.mu.RUnlock()

	// For privileged file operations, only allow configured directories
	v.mu.RLock()
	allowedDirs := v.allowedDirs
	v.mu.RUnlock()

	for _, prefix := range allowedDirs {
		if strings.HasPrefix(cleanPath, prefix) {
			return nil
		}
	}

	return fmt.Errorf("file path not in allowed directories: %s", path)
}

// validatePackageName validates system package names
func (v *RequestValidator) validatePackageName(name string) error {
	// Package names should only contain alphanumeric, hyphens, underscores, dots
	validName := regexp.MustCompile(`^[a-zA-Z0-9._+-]+$`)
	if !validName.MatchString(name) {
		return fmt.Errorf("invalid package name format: %s", name)
	}

	// Prevent obviously malicious package names
	maliciousPatterns := []string{
		"rm ", "sudo ", "curl ", "wget ", "sh ", "bash ", "exec",
		";", "|", "&", "$", "`", "(", ")",
	}

	lowerName := strings.ToLower(name)
	for _, pattern := range maliciousPatterns {
		if strings.Contains(lowerName, pattern) {
			return fmt.Errorf("potentially malicious package name: %s", name)
		}
	}

	return nil
}

// validateServiceName validates systemd service names
func (v *RequestValidator) validateServiceName(name string) error {
	// Service names should follow systemd conventions
	validName := regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)
	if !validName.MatchString(name) {
		return fmt.Errorf("invalid service name format: %s", name)
	}

	// Whitelist of allowed services
	allowedServices := map[string]bool{
		"docker":             true,
		"caddy":              true,
		"nginx":              true,
		"apache2":            true,
		"mysql":              true,
		"postgresql":         true,
		"redis":              true,
		"mongodb":            true,
		"pulseup-supervisor": true,
		"pulseup-worker":     true,
	}

	// Remove .service suffix if present
	cleanName := strings.TrimSuffix(name, ".service")

	if !allowedServices[cleanName] {
		return fmt.Errorf("service not in allowlist: %s", name)
	}

	return nil
}

// validateContainerIdentifier validates Docker container IDs and names
func (v *RequestValidator) validateContainerIdentifier(identifier string) error {
	// Container IDs are hex strings, names follow Docker naming conventions
	if len(identifier) == 0 {
		return fmt.Errorf("empty container identifier")
	}

	// Check for obvious injection attempts
	if strings.ContainsAny(identifier, ";|&$`()") {
		return fmt.Errorf("invalid characters in container identifier: %s", identifier)
	}

	return nil
}

// validateDockerImage validates Docker image names
func (v *RequestValidator) validateDockerImage(image string) error {
	// Basic Docker image name validation
	validImage := regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._/-]*[a-zA-Z0-9]$`)
	if !validImage.MatchString(image) {
		return fmt.Errorf("invalid Docker image name format: %s", image)
	}

	return nil
}

// validateBuildContext validates Docker build context paths
func (v *RequestValidator) validateBuildContext(context string) error {
	// Build context should be a valid directory path
	return v.validateFilePath(context)
}

// validateCommand validates command strings for execution
func (v *RequestValidator) validateCommand(command string) error {
	// Basic command injection prevention
	if strings.ContainsAny(command, ";|&$`") {
		return fmt.Errorf("potentially dangerous characters in command: %s", command)
	}

	return nil
}

// validateOperationSpecific performs operation-specific validation
func (v *RequestValidator) validateOperationSpecific(op OperationType, args map[string]interface{}) error {
	if op != OpAgentUpdate {
		return nil
	}

	filePath, ok := args["update_file_path"].(string)
	if !ok {
		return fmt.Errorf("update_file_path is required")
	}

	if _, err := os.Stat(filePath); err != nil {
		return fmt.Errorf("update file not found: %s", filePath)
	}

	manifest, manifestOK := args["checksum_manifest"].(string)
	if !manifestOK || strings.TrimSpace(manifest) == "" {
		return fmt.Errorf("checksum_manifest is required")
	}

	signature, signatureOK := args["signature"].(string)
	if !signatureOK || strings.TrimSpace(signature) == "" {
		return fmt.Errorf("signature is required")
	}

	return nil
}

// checkRateLimit checks if an operation has exceeded its rate limit
func (v *RequestValidator) checkRateLimit(op OperationType, config *OperationConfig) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	limiter, exists := v.rateLimiters[op]
	if !exists {
		limiter = &RateLimiter{
			lastReset: time.Now(),
			count:     0,
			maxCalls:  config.MaxCallsPerMinute,
			window:    time.Minute,
		}
		v.rateLimiters[op] = limiter
	}

	return limiter.CheckAndIncrement()
}

// CheckAndIncrement checks rate limit and increments counter if allowed
func (rl *RateLimiter) CheckAndIncrement() error {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	// Reset counter if window has elapsed
	if now.Sub(rl.lastReset) >= rl.window {
		rl.count = 0
		rl.lastReset = now
	}

	// Check if we've exceeded the limit
	if rl.count >= rl.maxCalls {
		return fmt.Errorf("rate limit exceeded: %d calls per %v", rl.maxCalls, rl.window)
	}

	// Increment counter
	rl.count++
	return nil
}

// logSecurityEvent logs a security event
func (v *RequestValidator) logSecurityEvent(eventType string, req *PrivilegedRequest, clientInfo ClientInfo, allowed bool, reason string) {
	if v.auditLogger != nil {
		event := SecurityEvent{
			Timestamp:   time.Now(),
			EventType:   eventType,
			Operation:   OperationType(req.Operation),
			WorkerPID:   req.WorkerPID,
			Allowed:     allowed,
			Reason:      reason,
			RequestArgs: req.Args,
			ClientInfo:  clientInfo,
		}
		v.auditLogger.LogSecurityEvent(event)
	}
}

// GetClientInfo extracts client information from a Unix socket connection using SO_PEERCRED
func GetClientInfo(conn net.Conn) (ClientInfo, error) {
	var clientInfo ClientInfo

	// For Unix sockets, we can get peer credentials using SO_PEERCRED
	if unixConn, ok := conn.(*net.UnixConn); ok {
		// Get the raw connection to access socket options
		rawConn, err := unixConn.SyscallConn()
		if err != nil {
			return clientInfo, fmt.Errorf("failed to get raw connection: %w", err)
		}

		var pid, uid, gid int
		var credErr error

		// Use the raw connection to get SO_PEERCRED
		err = rawConn.Control(func(fd uintptr) {
			pid, uid, gid, credErr = getPeerCredentials(int(fd))
		})

		if err != nil {
			return clientInfo, fmt.Errorf("failed to control connection: %w", err)
		}

		if credErr != nil {
			return clientInfo, fmt.Errorf("failed to get peer credentials: %w", credErr)
		}

		// Get command name from /proc filesystem
		comm, err := getProcessCommand(pid)
		if err != nil {
			// If we can't get the command name, use "unknown" but continue
			comm = "unknown"
		}

		clientInfo = ClientInfo{
			PID:  pid,
			UID:  uid,
			GID:  gid,
			Comm: comm,
		}

		// Validate that this is actually the pulseup-worker process
		if err := validateWorkerProcess(clientInfo); err != nil {
			return clientInfo, fmt.Errorf("client validation failed: %w", err)
		}
	} else {
		return clientInfo, fmt.Errorf("connection is not a Unix socket")
	}

	return clientInfo, nil
}

// getPeerCredentials extracts PID, UID, GID from a Unix socket using SO_PEERCRED
func getPeerCredentials(fd int) (pid, uid, gid int, err error) {
	// SO_PEERCRED constant (17 on Linux)
	const SO_PEERCRED = 17

	// Structure for ucred (user credentials) - Linux specific
	type ucred struct {
		Pid int32
		Uid uint32
		Gid uint32
	}

	// Get SO_PEERCRED from the socket
	cred := ucred{}
	credSize := unsafe.Sizeof(cred)

	// Use syscall to get socket option SO_PEERCRED
	_, _, errno := syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		uintptr(fd),
		syscall.SOL_SOCKET,
		SO_PEERCRED,
		uintptr(unsafe.Pointer(&cred)),
		uintptr(unsafe.Pointer(&credSize)),
		0,
	)

	if errno != 0 {
		return 0, 0, 0, fmt.Errorf("getsockopt SO_PEERCRED failed: %v", errno)
	}

	return int(cred.Pid), int(cred.Uid), int(cred.Gid), nil
}

// getProcessCommand reads the command name from /proc/PID/comm
func getProcessCommand(pid int) (string, error) {
	commPath := fmt.Sprintf("/proc/%d/comm", pid)
	data, err := ioutil.ReadFile(commPath)
	if err != nil {
		return "", fmt.Errorf("failed to read %s: %w", commPath, err)
	}

	// Remove trailing newline
	comm := strings.TrimSpace(string(data))
	return comm, nil
}

// validateWorkerProcess ensures the connecting process is actually pulseup-worker
func validateWorkerProcess(clientInfo ClientInfo) error {
	// Check command name matches expected worker process
	expectedCommands := []string{"pulseup-worker", "worker"}

	validCommand := false
	for _, expected := range expectedCommands {
		if clientInfo.Comm == expected {
			validCommand = true
			break
		}
	}

	if !validCommand {
		return fmt.Errorf("invalid command name: %s, expected one of %v",
			clientInfo.Comm, expectedCommands)
	}

	// Additional validation: check if process exists and is accessible
	procPath := fmt.Sprintf("/proc/%d", clientInfo.PID)
	if _, err := os.Stat(procPath); err != nil {
		return fmt.Errorf("process %d does not exist or is not accessible", clientInfo.PID)
	}

	// Optional: Check process executable path to ensure it's the correct binary
	// Only check this in production - skip for testing
	if !strings.Contains(os.Args[0], "test") {
		exePath := fmt.Sprintf("/proc/%d/exe", clientInfo.PID)
		if target, err := os.Readlink(exePath); err == nil {
			// In Docker environments (especially with Rosetta on macOS), the exe path might be different
			// Accept either pulseup-worker in path OR if running in Docker environment
			isWorkerBinary := strings.Contains(target, "pulseup-worker")
			isDockerRosetta := strings.Contains(target, "/run/rosetta/rosetta")

			if !isWorkerBinary && !isDockerRosetta {
				return fmt.Errorf("process executable %s does not appear to be pulseup-worker", target)
			}

			// For Rosetta processes, verify the command line contains pulseup-worker
			if isDockerRosetta {
				cmdlinePath := fmt.Sprintf("/proc/%d/cmdline", clientInfo.PID)
				if cmdlineData, err := os.ReadFile(cmdlinePath); err == nil {
					cmdline := string(cmdlineData)
					if !strings.Contains(cmdline, "pulseup-worker") {
						return fmt.Errorf("Rosetta process %s does not have pulseup-worker in cmdline: %s", target, cmdline)
					}
				}
			}
		}
	}
	// Note: We don't fail if we can't read the exe link as it might be restricted

	return nil
}

// AddTrustedPID adds a PID to the trusted list
func (v *RequestValidator) AddTrustedPID(pid int) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.trustedPIDs[pid] = true
}

// SetAllowedDirectories updates the list of allowed directories for file operations
func (v *RequestValidator) SetAllowedDirectories(dirs []string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.allowedDirs = validateAndFilterDirs(dirs)
}

// GetAllowedDirectories returns the current list of allowed directories
func (v *RequestValidator) GetAllowedDirectories() []string {
	v.mu.RLock()
	defer v.mu.RUnlock()

	// Return a copy to prevent modification
	dirs := make([]string, len(v.allowedDirs))
	copy(dirs, v.allowedDirs)
	return dirs
}

// RemoveTrustedPID removes a PID from the trusted list
func (v *RequestValidator) RemoveTrustedPID(pid int) {
	v.mu.Lock()
	defer v.mu.Unlock()
	delete(v.trustedPIDs, pid)
}

// AddAllowedPath adds a path to the allowed list for file operations
func (v *RequestValidator) AddAllowedPath(path string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.allowedPaths[filepath.Clean(path)] = true
}

// AddBlockedPath adds a path to the blocked list for file operations
func (v *RequestValidator) AddBlockedPath(path string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.blockedPaths[filepath.Clean(path)] = true
}
