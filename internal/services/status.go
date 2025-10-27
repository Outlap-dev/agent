package services

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"time"

	"outlap-agent-go/pkg/logger"
	"outlap-agent-go/pkg/types"
)

// QueuedStatusUpdate represents a status update that was queued due to connection issues
type QueuedStatusUpdate struct {
	Type         string                 `json:"type"`      // "service" or "deployment"
	UID          string                 `json:"uid"`       // service_uid or deployment_uid
	Status       string                 `json:"status"`    // status value
	ErrorMessage string                 `json:"error"`     // error message if any
	Event        string                 `json:"event"`     // WebSocket event name
	Payload      map[string]interface{} `json:"payload"`   // complete payload
	Timestamp    time.Time              `json:"timestamp"` // when it was queued
}

// StatusServiceImpl implements the StatusService interface
type StatusServiceImpl struct {
	logger        *logger.Logger
	wsManager     StatusSocket         // WebSocket manager for sending status updates
	queuedMutex   sync.Mutex           // protects queuedUpdates
	queuedUpdates []QueuedStatusUpdate // status updates to retry when connected

	heartbeatMutex       sync.Mutex
	deploymentHeartbeats map[string]context.CancelFunc
	heartbeatInterval    time.Duration
}

const defaultDeploymentHeartbeatInterval = 20 * time.Second

// NewStatusService creates a new Status service
func NewStatusService(logger *logger.Logger) *StatusServiceImpl {
	return &StatusServiceImpl{
		logger:               logger.With("service", "status"),
		queuedUpdates:        make([]QueuedStatusUpdate, 0),
		deploymentHeartbeats: make(map[string]context.CancelFunc),
		heartbeatInterval:    defaultDeploymentHeartbeatInterval,
	}
}

// SetWebSocketManager sets the WebSocket manager for sending status updates
func (s *StatusServiceImpl) SetWebSocketManager(wsManager StatusSocket) {
	s.wsManager = wsManager
	// Try to send any queued updates when WebSocket becomes available
	go s.retryQueuedUpdates()
}

// isConnected checks if the WebSocket manager is available and connected
func (s *StatusServiceImpl) isConnected() bool {
	if s.wsManager == nil {
		return false
	}

	return s.wsManager.IsConnected()
}

// queueStatusUpdate adds a status update to the retry queue
func (s *StatusServiceImpl) queueStatusUpdate(updateType, uid, status, errorMessage, event string, payload map[string]interface{}) {
	s.queuedMutex.Lock()
	defer s.queuedMutex.Unlock()

	update := QueuedStatusUpdate{
		Type:         updateType,
		UID:          uid,
		Status:       status,
		ErrorMessage: errorMessage,
		Event:        event,
		Payload:      payload,
		Timestamp:    time.Now(),
	}

	s.queuedUpdates = append(s.queuedUpdates, update)
	s.logger.Info("Queued status update for retry", "type", updateType, "uid", uid, "status", status, "queue_size", len(s.queuedUpdates))
}

// retryQueuedUpdates attempts to send all queued updates
func (s *StatusServiceImpl) retryQueuedUpdates() {
	s.queuedMutex.Lock()
	defer s.queuedMutex.Unlock()

	if len(s.queuedUpdates) == 0 || !s.isConnected() {
		return
	}

	s.logger.Info("Retrying queued status updates", "count", len(s.queuedUpdates))

	// Process all queued updates
	var failedUpdates []QueuedStatusUpdate
	for _, update := range s.queuedUpdates {
		if err := s.sendStatusUpdate(update.Event, update.Payload); err != nil {
			s.logger.Warn("Failed to retry queued update", "type", update.Type, "uid", update.UID, "error", err)
			// Keep failed updates for next retry (up to 1 hour old)
			if time.Since(update.Timestamp) < time.Hour {
				failedUpdates = append(failedUpdates, update)
			}
		} else {
			s.logger.Debug("Successfully retried queued update", "type", update.Type, "uid", update.UID)
		}
	}

	// Keep only failed updates that are still recent
	s.queuedUpdates = failedUpdates
}

// sendStatusUpdate sends a status update via WebSocket
func (s *StatusServiceImpl) sendStatusUpdate(event string, payload map[string]interface{}) error {
	if !s.isConnected() {
		return fmt.Errorf("not connected")
	}

	return s.wsManager.Emit(event, payload)
}

func (s *StatusServiceImpl) startDeploymentHeartbeat(deploymentUID string) {
	if deploymentUID == "" {
		return
	}

	s.heartbeatMutex.Lock()
	if _, exists := s.deploymentHeartbeats[deploymentUID]; exists {
		s.heartbeatMutex.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.deploymentHeartbeats[deploymentUID] = cancel
	s.heartbeatMutex.Unlock()

	go s.deploymentHeartbeatLoop(ctx, deploymentUID)
}

func (s *StatusServiceImpl) stopDeploymentHeartbeat(deploymentUID string) {
	s.heartbeatMutex.Lock()
	cancel, exists := s.deploymentHeartbeats[deploymentUID]
	if exists {
		delete(s.deploymentHeartbeats, deploymentUID)
	}
	s.heartbeatMutex.Unlock()

	if exists {
		cancel()
	}
}

func (s *StatusServiceImpl) deploymentHeartbeatLoop(ctx context.Context, deploymentUID string) {
	ticker := time.NewTicker(s.heartbeatInterval)
	defer ticker.Stop()

	s.emitDeploymentHeartbeat(deploymentUID)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.emitDeploymentHeartbeat(deploymentUID)
		}
	}
}

func (s *StatusServiceImpl) emitDeploymentHeartbeat(deploymentUID string) {
	if deploymentUID == "" {
		return
	}

	payload := map[string]interface{}{
		"deployment_uid": deploymentUID,
		"timestamp":      time.Now().UTC(),
	}

	if err := s.sendStatusUpdate("deployment_heartbeat", payload); err != nil {
		s.logger.Debug("Deployment heartbeat not sent", "deployment_uid", deploymentUID, "reason", err)
	}
}

// UpdateServiceStatus updates the status of a service
func (s *StatusServiceImpl) UpdateServiceStatus(ctx context.Context, serviceUID string, status types.ServiceStatus, errorMessage string) error {
	s.logger.Debug("Updating service status", "service_uid", serviceUID, "status", status)

	// Validate status
	validStatuses := types.GetServiceStatusChoices()
	if !slices.Contains(validStatuses, status) {
		return fmt.Errorf("invalid service status: %s", status)
	}

	// Prepare payload
	payload := map[string]interface{}{
		"service_uid": serviceUID,
		"status":      string(status),
	}
	if errorMessage != "" {
		payload["error"] = errorMessage
	}

	// Check if we're connected
	if !s.isConnected() {
		s.logger.Warn("WebSocket not connected, queueing service status update", "service_uid", serviceUID, "status", status)
		s.queueStatusUpdate("service", serviceUID, string(status), errorMessage, "update_service_status", payload)
		return nil // Don't return error, just queue for later
	}

	// Send status update immediately
	if err := s.sendStatusUpdate("update_service_status", payload); err != nil {
		s.logger.Error("Failed to send service status update", "service_uid", serviceUID, "status", status, "error", err)
		// Queue for retry
		s.queueStatusUpdate("service", serviceUID, string(status), errorMessage, "update_service_status", payload)
		return fmt.Errorf("failed to send status update: %w", err)
	}

	s.logger.Debug("Service status updated successfully", "service_uid", serviceUID, "status", status)
	return nil
}

// UpdateDeploymentStatus updates the status of a deployment
func (s *StatusServiceImpl) UpdateDeploymentStatus(ctx context.Context, deploymentUID string, status types.DeploymentStatus, errorMessage string, metadata map[string]interface{}) error {
	s.logger.Debug("Updating deployment status", "deployment_uid", deploymentUID, "status", status)

	// Validate status
	validStatuses := types.GetDeploymentStatusChoices()
	if !slices.Contains(validStatuses, status) {
		return fmt.Errorf("invalid deployment status: %s", status)
	}

	// Prepare payload
	payload := map[string]interface{}{
		"deployment_uid": deploymentUID,
		"status":         string(status),
	}
	if errorMessage != "" {
		payload["error"] = errorMessage
	}
	for key, value := range metadata {
		if value == nil {
			continue
		}
		payload[key] = value
	}

	isTerminal := types.IsDeploymentStatusCompleted(status)
	defer func() {
		if isTerminal {
			s.stopDeploymentHeartbeat(deploymentUID)
		} else {
			s.startDeploymentHeartbeat(deploymentUID)
		}
	}()

	// Check if we're connected
	if !s.isConnected() {
		s.logger.Warn("WebSocket not connected, queueing deployment status update", "deployment_uid", deploymentUID, "status", status)
		s.queueStatusUpdate("deployment", deploymentUID, string(status), errorMessage, "update_deployment_status", payload)
		return nil // Don't return error, just queue for later
	}

	// Send status update immediately
	if err := s.sendStatusUpdate("update_deployment_status", payload); err != nil {
		s.logger.Error("Failed to send deployment status update", "deployment_uid", deploymentUID, "status", status, "error", err)
		// Queue for retry
		s.queueStatusUpdate("deployment", deploymentUID, string(status), errorMessage, "update_deployment_status", payload)
		return fmt.Errorf("failed to send deployment status update: %w", err)
	}

	s.logger.Debug("Deployment status updated successfully", "deployment_uid", deploymentUID, "status", status)
	return nil
}

// SendPendingInstallations sends pending installation information
func (s *StatusServiceImpl) SendPendingInstallations(ctx context.Context, pendingTools map[string]interface{}) error {
	s.logger.Debug("Sending pending installations", "tools_count", len(pendingTools))

	if s.wsManager == nil {
		s.logger.Warn("WebSocket manager not available, cannot send pending installations")
		return fmt.Errorf("websocket manager not available")
	}

	// Prepare payload
	payload := map[string]interface{}{
		"pending_tools": pendingTools,
	}

	// Send pending installations
	if err := s.wsManager.Emit("pending_installations", payload); err != nil {
		s.logger.Error("Failed to send pending installations", "error", err)
		return fmt.Errorf("failed to send pending installations: %w", err)
	}

	s.logger.Debug("Pending installations sent successfully")
	return nil
}

// GetServiceEnvVars gets environment variables for a service from the server
func (s *StatusServiceImpl) GetServiceEnvVars(ctx context.Context, serviceUID string) (map[string]interface{}, error) {
	s.logger.Debug("Getting service environment variables", "service_uid", serviceUID)

	if s.wsManager == nil {
		return nil, fmt.Errorf("websocket manager not available")
	}

	// Make the call to get environment variables
	result, err := s.wsManager.Call("get_service_env_vars", map[string]interface{}{
		"service_uid": serviceUID,
	})
	if err != nil {
		s.logger.Error("Failed to get service environment variables", "service_uid", serviceUID, "error", err)
		return map[string]interface{}{
			"success": false,
			"error":   fmt.Sprintf("failed to get env vars: %v", err),
		}, nil
	}

	// Check for errors in the response
	if errorMsg, exists := result["error"]; exists {
		s.logger.Error("Error getting environment variables", "service_uid", serviceUID, "error", errorMsg)
		return map[string]interface{}{
			"success": false,
			"error":   fmt.Sprintf("%v", errorMsg),
		}, nil
	}

	// Return success response with environment variables
	s.logger.Debug("Retrieved service environment variables", "service_uid", serviceUID)
	return map[string]interface{}{
		"success":  true,
		"env_vars": result,
	}, nil
}
