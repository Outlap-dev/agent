package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"outlap-agent-go/pkg/logger"
	"outlap-agent-go/pkg/types"
)

// DatabaseHandler aggregates database-related commands including deployment, backups, logs, and automation.
type DatabaseHandler struct {
	*BaseHandler

	apiBaseURL string
}

// NewDatabaseHandler constructs a DatabaseHandler with optional download configuration.
func NewDatabaseHandler(logger *logger.Logger, services ServiceProvider, apiBaseURL string) *DatabaseHandler {
	base := logger.With("controller", "database")
	return &DatabaseHandler{
		BaseHandler: NewBaseHandler(base, services),
		apiBaseURL:  strings.TrimRight(apiBaseURL, "/"),
	}
}

// Base exposes the embedded base handler for routing helpers.
func (h *DatabaseHandler) Base() *BaseHandler {
	return h.BaseHandler
}

// DeployDatabaseRequest represents the request payload for database deployment.
type DeployDatabaseRequest struct {
	ServiceUID    string `json:"service_uid"`
	Type          string `json:"type"`
	Password      string `json:"password"`
	Port          *int   `json:"port,omitempty"`
	Username      string `json:"username,omitempty"`
	Database      string `json:"database,omitempty"`
	DeploymentUID string `json:"deployment_uid,omitempty"`
}

// BackupDatabaseRequest represents the request payload for creating a backup.
type BackupDatabaseRequest struct {
	ServiceUID string `json:"service_uid"`
	BackupUID  string `json:"backup_uid"`
}

// ListDatabaseBackupsRequest represents the request payload for listing backups.
type ListDatabaseBackupsRequest struct {
	ServiceUID string `json:"service_uid"`
}

// RestoreDatabaseRequest represents the request payload for restoring a backup.
type RestoreDatabaseRequest struct {
	ServiceUID string `json:"service_uid"`
	BackupPath string `json:"backup_path"`
}

// DownloadBackupRequest represents the request payload for uploading a backup file to the API.
type DownloadBackupRequest struct {
	BackupPath string `json:"backup_path"`
	BackupUID  string `json:"backup_uid"`
	ServiceUID string `json:"service_uid"`
}

// UpdateBackupAutomationRequest represents the payload for automation configuration.
type UpdateBackupAutomationRequest struct {
	ServiceUID     string `json:"service_uid"`
	Enabled        *bool  `json:"enabled"`
	CronExpression string `json:"cron_expression"`
	StoragePath    string `json:"storage_path"`
	RetentionDays  int    `json:"retention_days"`
}

// VerifyBackupStoragePathRequest carries the payload for validating automation storage paths.
type VerifyBackupStoragePathRequest struct {
	ServiceUID  string `json:"service_uid"`
	StoragePath string `json:"storage_path"`
}

// Deploy provisions a database container via the database service.
func (h *DatabaseHandler) Deploy(ctx context.Context, data json.RawMessage) (*types.CommandResponse, error) {
	var request DeployDatabaseRequest
	if err := json.Unmarshal(data, &request); err != nil {
		return &types.CommandResponse{Success: false, Error: "invalid request format: " + err.Error()}, nil
	}

	if request.ServiceUID == "" {
		return &types.CommandResponse{Success: false, Error: "service_uid is required"}, nil
	}
	if request.Type == "" {
		return &types.CommandResponse{Success: false, Error: "type is required"}, nil
	}
	if request.Password == "" {
		return &types.CommandResponse{Success: false, Error: "password is required"}, nil
	}

	engine := strings.ToLower(request.Type)
	supportedTypes := map[string]bool{
		"mysql":      true,
		"postgresql": true,
		"mariadb":    true,
		"redis":      true,
		"mongodb":    true,
	}
	if !supportedTypes[engine] {
		return &types.CommandResponse{Success: false, Error: "unsupported database type. Supported types: mysql, postgresql, mariadb, redis, mongodb"}, nil
	}

	if request.Port != nil {
		if *request.Port < 1 || *request.Port > 65535 {
			return &types.CommandResponse{Success: false, Error: "port must be between 1 and 65535"}, nil
		}
	}

	username := strings.TrimSpace(request.Username)
	database := strings.TrimSpace(request.Database)

	switch engine {
	case "postgresql":
		if username == "" {
			username = "admin"
		}
		if database == "" {
			database = "app"
		}
	case "mysql", "mariadb":
		if username == "" {
			username = "admin"
		}
		if database == "" {
			database = "app"
		}
	case "mongodb":
		if username == "" {
			username = "root"
		}
		if database == "" {
			database = "app"
		}
	case "redis":
		if username == "" {
			username = "default"
		}
		if database == "" {
			database = "0"
		}
	default:
		if username == "" {
			username = "admin"
		}
		if database == "" {
			database = "app"
		}
	}

	request.Type = engine

	h.logger.Info("Deploying database",
		"service_uid", request.ServiceUID,
		"type", engine,
		"port", request.Port,
		"username", username,
		"database", database)

	statusService := h.services.GetStatusService()
	if statusService != nil {
		statusService.UpdateServiceStatus(ctx, request.ServiceUID, types.ServiceStatusDeploying, "")
	}

	dbService := h.services.GetDatabaseService()
	if dbService == nil {
		return &types.CommandResponse{Success: false, Error: "database service not available"}, nil
	}

	result, err := dbService.DeployDatabase(ctx, engine, request.Password, request.ServiceUID, request.Port, username, database, request.DeploymentUID)
	if err != nil {
		h.logger.Error("Failed to deploy database", "service_uid", request.ServiceUID, "error", err)
		if statusService != nil {
			statusService.UpdateServiceStatus(ctx, request.ServiceUID, types.ServiceStatusFailed, "Database deployment failed: "+err.Error())
		}
		return &types.CommandResponse{Success: false, Error: "failed to deploy database: " + err.Error()}, nil
	}

	if statusService != nil {
		statusService.UpdateServiceStatus(ctx, request.ServiceUID, types.ServiceStatusRunning, "")
	}

	h.logger.Info("Database deployed successfully",
		"service_uid", request.ServiceUID,
		"container_id", result.ContainerID,
		"port", result.Port)

	return &types.CommandResponse{
		Success: true,
		Data: map[string]interface{}{
			"status":       "success",
			"message":      "Database " + result.Name + " deployed successfully",
			"details":      result,
			"container_id": result.ContainerID,
			"name":         result.Name,
			"port":         result.Port,
			"type":         result.Type,
			"username":     result.Username,
			"database":     result.Database,
			"volume_path":  result.VolumePath,
		},
	}, nil
}

// Logs retrieves recent logs for a database service.
func (h *DatabaseHandler) Logs(ctx context.Context, data json.RawMessage) (*types.CommandResponse, error) {
	var request struct {
		ServiceUID string `json:"service_uid"`
		Lines      int    `json:"lines,omitempty"`
	}
	if err := json.Unmarshal(data, &request); err != nil {
		return &types.CommandResponse{Success: false, Error: "invalid request format"}, nil
	}
	if request.ServiceUID == "" {
		return &types.CommandResponse{Success: false, Error: "service_uid is required"}, nil
	}
	if request.Lines <= 0 {
		request.Lines = 100
	}

	containerName := fmt.Sprintf("outlap-db-%s", request.ServiceUID)

	dockerService := h.services.GetDockerService()
	if dockerService == nil {
		return &types.CommandResponse{Success: false, Error: "docker service not available"}, nil
	}

	logs, err := dockerService.GetContainerLogsByName(ctx, containerName)
	if err != nil {
		h.logger.Error("Failed to get database container logs", "error", err, "container_name", containerName)
		return &types.CommandResponse{Success: false, Error: "failed to get database container logs: " + err.Error()}, nil
	}

	if len(logs) > request.Lines {
		logs = logs[len(logs)-request.Lines:]
	}

	return &types.CommandResponse{Success: true, Data: map[string]interface{}{"logs": logs}}, nil
}

// Backup creates a database backup and reports status updates via websocket.
func (h *DatabaseHandler) Backup(ctx context.Context, data json.RawMessage) (*types.CommandResponse, error) {
	var request BackupDatabaseRequest
	if err := json.Unmarshal(data, &request); err != nil {
		return &types.CommandResponse{Success: false, Error: "invalid request format: " + err.Error()}, nil
	}
	if request.ServiceUID == "" {
		return &types.CommandResponse{Success: false, Error: "service_uid is required"}, nil
	}
	if request.BackupUID == "" {
		return &types.CommandResponse{Success: false, Error: "backup_uid is required"}, nil
	}

	dbService := h.services.GetDatabaseService()
	if dbService == nil {
		return &types.CommandResponse{Success: false, Error: "database service not available"}, nil
	}

	ctxWithMeta := context.WithValue(ctx, types.ContextKeyBackupUID, request.BackupUID)
	ctxWithMeta = context.WithValue(ctxWithMeta, types.ContextKeyBackupServiceUID, request.ServiceUID)
	ctxWithMeta = context.WithValue(ctxWithMeta, types.ContextKeyBackupStartTime, time.Now())

	h.logger.Info("Creating database backup", "service_uid", request.ServiceUID)

	result, err := dbService.BackupDatabase(ctxWithMeta, request.ServiceUID)
	if err != nil {
		h.logger.Error("Failed to create database backup", "service_uid", request.ServiceUID, "error", err)
		h.sendBackupStatusUpdate("failed", request.BackupUID, request.ServiceUID, err.Error(), result)
		return &types.CommandResponse{Success: false, Error: "failed to create database backup: " + err.Error()}, nil
	}

	h.logger.Info("Database backup created successfully",
		"service_uid", request.ServiceUID,
		"backup_path", result.BackupPath,
		"size_bytes", result.Size)

	h.sendBackupStatusUpdate("completed", request.BackupUID, request.ServiceUID, "", result)

	return &types.CommandResponse{
		Success: true,
		Data: map[string]interface{}{
			"status":      "success",
			"message":     "Database backup created successfully",
			"backup_uid":  request.BackupUID,
			"backup_path": result.BackupPath,
			"database":    result.Database,
			"type":        result.Type,
			"size":        result.Size,
			"created_at":  result.CreatedAt,
		},
	}, nil
}

// ListBackups enumerates backups available for a service.
func (h *DatabaseHandler) ListBackups(ctx context.Context, data json.RawMessage) (*types.CommandResponse, error) {
	var request ListDatabaseBackupsRequest
	if err := json.Unmarshal(data, &request); err != nil {
		return &types.CommandResponse{Success: false, Error: "invalid request format: " + err.Error()}, nil
	}
	if request.ServiceUID == "" {
		return &types.CommandResponse{Success: false, Error: "service_uid is required"}, nil
	}

	dbService := h.services.GetDatabaseService()
	if dbService == nil {
		return &types.CommandResponse{Success: false, Error: "database service not available"}, nil
	}

	h.logger.Debug("Listing database backups", "service_uid", request.ServiceUID)

	backups, err := dbService.ListBackups(ctx, request.ServiceUID)
	if err != nil {
		h.logger.Error("Failed to list database backups", "service_uid", request.ServiceUID, "error", err)
		return &types.CommandResponse{Success: false, Error: "failed to list database backups: " + err.Error()}, nil
	}

	return &types.CommandResponse{
		Success: true,
		Data: map[string]interface{}{
			"status":  "success",
			"backups": backups,
			"count":   len(backups),
		},
	}, nil
}

// Restore rehydrates a database from a provided backup path.
func (h *DatabaseHandler) Restore(ctx context.Context, data json.RawMessage) (*types.CommandResponse, error) {
	var request RestoreDatabaseRequest
	if err := json.Unmarshal(data, &request); err != nil {
		return &types.CommandResponse{Success: false, Error: "invalid request format: " + err.Error()}, nil
	}
	if request.ServiceUID == "" {
		return &types.CommandResponse{Success: false, Error: "service_uid is required"}, nil
	}
	if request.BackupPath == "" {
		return &types.CommandResponse{Success: false, Error: "backup_path is required"}, nil
	}

	statusService := h.services.GetStatusService()
	if statusService != nil {
		statusService.UpdateServiceStatus(ctx, request.ServiceUID, types.ServiceStatusDeploying, "Restoring database from backup")
	}

	dbService := h.services.GetDatabaseService()
	if dbService == nil {
		return &types.CommandResponse{Success: false, Error: "database service not available"}, nil
	}

	h.logger.Info("Restoring database from backup",
		"service_uid", request.ServiceUID,
		"backup_path", request.BackupPath)

	if err := dbService.RestoreDatabase(ctx, request.ServiceUID, request.BackupPath); err != nil {
		h.logger.Error("Failed to restore database", "service_uid", request.ServiceUID, "backup_path", request.BackupPath, "error", err)
		if statusService != nil {
			statusService.UpdateServiceStatus(ctx, request.ServiceUID, types.ServiceStatusFailed, "Database restore failed: "+err.Error())
		}
		return &types.CommandResponse{Success: false, Error: "failed to restore database: " + err.Error()}, nil
	}

	if statusService != nil {
		statusService.UpdateServiceStatus(ctx, request.ServiceUID, types.ServiceStatusRunning, "")
	}

	return &types.CommandResponse{
		Success: true,
		Data: map[string]interface{}{
			"status":  "success",
			"message": "Database restored successfully from backup",
		},
	}, nil
}

// DownloadBackup uploads a backup file to the Outlap API for safekeeping.
func (h *DatabaseHandler) DownloadBackup(ctx context.Context, data json.RawMessage) (*types.CommandResponse, error) {
	var request DownloadBackupRequest
	if err := json.Unmarshal(data, &request); err != nil {
		return &types.CommandResponse{Success: false, Error: "invalid request format: " + err.Error()}, nil
	}
	if request.BackupPath == "" {
		return &types.CommandResponse{Success: false, Error: "backup_path is required"}, nil
	}
	if request.BackupUID == "" {
		return &types.CommandResponse{Success: false, Error: "backup_uid is required"}, nil
	}
	if request.ServiceUID == "" {
		return &types.CommandResponse{Success: false, Error: "service_uid is required"}, nil
	}

	if _, err := os.Stat(request.BackupPath); os.IsNotExist(err) {
		return &types.CommandResponse{Success: false, Error: fmt.Sprintf("backup file not found: %s", request.BackupPath)}, nil
	}

	uploadURL := h.uploadURL()

	h.logger.Info("Starting backup download (upload to server)",
		"backup_path", request.BackupPath,
		"backup_uid", request.BackupUID,
		"service_uid", request.ServiceUID,
		"upload_url", uploadURL)

	h.sendDownloadStatus("uploading", request.BackupUID, request.ServiceUID, "")

	if err := h.uploadBackupFile(ctx, uploadURL, request.BackupPath, request.BackupUID, request.ServiceUID); err != nil {
		h.logger.Error("Failed to upload backup file", "error", err)
		h.sendDownloadStatus("upload_failed", request.BackupUID, request.ServiceUID, err.Error())
		return &types.CommandResponse{Success: false, Error: "failed to upload backup file: " + err.Error()}, nil
	}

	h.logger.Info("Backup file uploaded successfully", "backup_path", request.BackupPath, "backup_uid", request.BackupUID)

	h.sendDownloadStatus("upload_completed", request.BackupUID, request.ServiceUID, "")

	return &types.CommandResponse{
		Success: true,
		Data: map[string]interface{}{
			"status":      "success",
			"message":     "Backup file uploaded successfully",
			"backup_uid":  request.BackupUID,
			"backup_path": request.BackupPath,
			"service_uid": request.ServiceUID,
		},
	}, nil
}

// UpdateAutomation configures scheduled backups for a database service.
func (h *DatabaseHandler) UpdateAutomation(ctx context.Context, data json.RawMessage) (*types.CommandResponse, error) {
	var req UpdateBackupAutomationRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return &types.CommandResponse{Success: false, Error: "invalid request payload: " + err.Error()}, nil
	}
	if req.ServiceUID == "" {
		return &types.CommandResponse{Success: false, Error: "service_uid is required"}, nil
	}

	enabled := false
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	config := types.BackupAutomationConfig{
		Enabled:        enabled,
		CronExpression: req.CronExpression,
		StoragePath:    req.StoragePath,
		RetentionDays:  req.RetentionDays,
	}

	dbService := h.services.GetDatabaseService()
	if dbService == nil {
		return &types.CommandResponse{Success: false, Error: "database service not available"}, nil
	}

	if err := dbService.ConfigureAutomation(ctx, req.ServiceUID, config); err != nil {
		h.logger.Error("Failed to configure backup automation", "service_uid", req.ServiceUID, "error", err)
		return &types.CommandResponse{Success: false, Error: "failed to configure backup automation: " + err.Error()}, nil
	}

	h.logger.Info("Backup automation updated", "service_uid", req.ServiceUID, "enabled", config.Enabled, "cron", config.CronExpression)

	return &types.CommandResponse{Success: true, Data: map[string]interface{}{"status": "ok"}}, nil
}

// VerifyAutomationPath ensures the provided storage path can be used for automated backups.
func (h *DatabaseHandler) VerifyAutomationPath(ctx context.Context, data json.RawMessage) (*types.CommandResponse, error) {
	var req VerifyBackupStoragePathRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return &types.CommandResponse{Success: false, Error: "invalid request payload: " + err.Error()}, nil
	}

	serviceUID := strings.TrimSpace(req.ServiceUID)
	storagePath := strings.TrimSpace(req.StoragePath)

	if serviceUID == "" {
		return &types.CommandResponse{Success: false, Error: "service_uid is required"}, nil
	}
	if storagePath == "" {
		return &types.CommandResponse{Success: false, Error: "storage_path is required"}, nil
	}

	dbService := h.services.GetDatabaseService()
	if dbService == nil {
		return &types.CommandResponse{Success: false, Error: "database service not available"}, nil
	}

	result, err := dbService.VerifyBackupStoragePath(ctx, serviceUID, storagePath)
	if err != nil {
		h.logger.Error("Failed to verify backup storage path", "service_uid", serviceUID, "path", storagePath, "error", err)
		return &types.CommandResponse{Success: false, Error: "failed to verify backup storage path: " + err.Error()}, nil
	}
	if result == nil {
		return &types.CommandResponse{Success: false, Error: "verification result is empty"}, nil
	}

	message := strings.TrimSpace(result.Message)
	if message == "" {
		if result.Success {
			message = "Storage path verified"
		} else {
			message = "Storage path verification failed"
		}
	}

	responseData := map[string]interface{}{
		"message": message,
	}
	if result.NormalizedPath != "" {
		responseData["normalized_path"] = result.NormalizedPath
	}

	if !result.Success {
		return &types.CommandResponse{Success: false, Error: message, Data: responseData}, nil
	}

	h.logger.Info("Storage path verified", "service_uid", serviceUID, "path", result.NormalizedPath)
	responseData["status"] = "ok"

	return &types.CommandResponse{Success: true, Data: responseData}, nil
}

func (h *DatabaseHandler) uploadURL() string {
	if h.apiBaseURL == "" {
		return "/api/agent/backups/upload"
	}
	return h.apiBaseURL + "/api/agent/backups/upload"
}

func (h *DatabaseHandler) uploadBackupFile(ctx context.Context, uploadURL, backupPath, backupUID, serviceUID string) error {
	file, err := os.Open(backupPath)
	if err != nil {
		return fmt.Errorf("failed to open backup file: %w", err)
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		return fmt.Errorf("failed to get file info: %w", err)
	}

	pr, pw := io.Pipe()
	writer := multipart.NewWriter(pw)

	go func() {
		var streamErr error
		defer func() {
			if streamErr != nil {
				_ = pw.CloseWithError(streamErr)
				return
			}
			if err := writer.Close(); err != nil {
				_ = pw.CloseWithError(err)
				return
			}
			_ = pw.Close()
		}()

		if err := writer.WriteField("backup_uid", backupUID); err != nil {
			streamErr = fmt.Errorf("failed to write backup_uid field: %w", err)
			return
		}
		if err := writer.WriteField("service_uid", serviceUID); err != nil {
			streamErr = fmt.Errorf("failed to write service_uid field: %w", err)
			return
		}

		part, err := writer.CreateFormFile("backup_file", filepath.Base(backupPath))
		if err != nil {
			streamErr = fmt.Errorf("failed to create form file: %w", err)
			return
		}
		if _, err := io.Copy(part, file); err != nil {
			streamErr = fmt.Errorf("failed to copy file content: %w", err)
			return
		}
	}()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uploadURL, pr)
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("User-Agent", "Outlap-Agent/1.0")

	client := &http.Client{Timeout: 30 * time.Minute}

	h.logger.Info("Uploading backup file", "url", uploadURL, "file_size", fileInfo.Size(), "file_name", filepath.Base(backupPath))

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send HTTP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("upload failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	h.logger.Info("Backup file uploaded successfully", "status_code", resp.StatusCode)
	return nil
}

func (h *DatabaseHandler) sendDownloadStatus(status, backupUID, serviceUID, errorMessage string) {
	wsManager := h.services.GetWebSocketManager()
	if wsManager == nil || !wsManager.IsConnected() {
		h.logger.Warn("WebSocket not connected, skipping status update")
		return
	}

	payload := map[string]interface{}{
		"backup_uid":  backupUID,
		"service_uid": serviceUID,
		"status":      status,
	}
	if errorMessage != "" {
		payload["error_message"] = errorMessage
	}

	if err := wsManager.Emit("backup_download_status", payload); err != nil {
		h.logger.Error("Failed to send backup download status update", "error", err)
	} else {
		h.logger.Info("Backup download status update sent", "status", status, "backup_uid", backupUID)
	}
}

func (h *DatabaseHandler) sendBackupStatusUpdate(status, backupUID, serviceUID, errorMessage string, result *types.DatabaseBackupResult) {
	wsManager := h.services.GetWebSocketManager()
	if wsManager == nil || !wsManager.IsConnected() {
		return
	}

	payload := map[string]interface{}{
		"backup_uid":  backupUID,
		"status":      status,
		"service_uid": serviceUID,
	}

	if result != nil {
		payload["file_path"] = result.BackupPath
		payload["file_size"] = result.Size
	}
	if errorMessage != "" {
		payload["error_message"] = errorMessage
	}

	if err := wsManager.Emit("backup_status_update", payload); err != nil {
		h.logger.Error("Failed to send backup status update", "error", err)
	} else {
		h.logger.Info("Backup status update sent to backend", "service_uid", serviceUID, "status", status)
	}
}
