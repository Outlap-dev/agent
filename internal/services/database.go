package services

import (
	"context"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/go-connections/nat"
	"github.com/google/uuid"
	"github.com/robfig/cron/v3"

	"outlap-agent-go/pkg/logger"
	"outlap-agent-go/pkg/types"
)

var automationCronParser = cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor)

const (
	databaseTypeLabelKey = "outlap.database_type"
)

func getBackupBaseDir() string {
	if override := os.Getenv("PULSEUP_BACKUP_DIR"); override != "" {
		return override
	}
	return "/var/lib/outlap/backups"
}

// DatabasePortInUseError is raised when attempting to use a port that is already in use
type DatabasePortInUseError struct {
	Port          int
	ContainerName string
}

func (e *DatabasePortInUseError) Error() string {
	return fmt.Sprintf("port %d is already in use by container '%s'", e.Port, e.ContainerName)
}

// DatabaseConfig holds configuration for different database types
type DatabaseConfig struct {
	Image              string
	InternalPort       int
	VolumePath         string
	EnvPrefix          string
	RootPasswordVar    string
	DefaultUserVar     string
	DefaultPasswordVar string
	DefaultDatabaseVar string
}

// DatabaseServiceImpl implements the DatabaseService interface
type DatabaseServiceImpl struct {
	logger            *logger.Logger
	dockerService     DockerService
	wsEmitter         WebSocketEmitter
	automationMu      sync.Mutex
	automationCron    *cron.Cron
	automationJobs    map[string]cron.EntryID
	automationConfigs map[string]types.BackupAutomationConfig
	automationExec    func(ctx context.Context, serviceUID string, config types.BackupAutomationConfig)
}

// NewDatabaseService creates a new database service
func NewDatabaseService(logger *logger.Logger, dockerService DockerService) *DatabaseServiceImpl {
	d := &DatabaseServiceImpl{
		logger:            logger.With("service", "database"),
		dockerService:     dockerService,
		automationCron:    cron.New(cron.WithParser(automationCronParser)),
		automationJobs:    make(map[string]cron.EntryID),
		automationConfigs: make(map[string]types.BackupAutomationConfig),
	}
	d.automationExec = d.runScheduledBackup
	d.automationCron.Start()
	return d
}

// SetWebSocketEmitter configures the emitter used for reporting progress and status updates back to the backend.
func (d *DatabaseServiceImpl) SetWebSocketEmitter(emitter WebSocketEmitter) {
	d.automationMu.Lock()
	defer d.automationMu.Unlock()
	d.wsEmitter = emitter
}

// getDatabaseConfig returns configuration for different database types
func (d *DatabaseServiceImpl) getDatabaseConfig(dbType string) (*DatabaseConfig, error) {
	configs := map[string]*DatabaseConfig{
		"mysql": {
			Image:              "mysql:8",
			InternalPort:       3306,
			VolumePath:         "/var/lib/mysql",
			EnvPrefix:          "MYSQL",
			RootPasswordVar:    "MYSQL_ROOT_PASSWORD",
			DefaultUserVar:     "MYSQL_USER",
			DefaultPasswordVar: "MYSQL_PASSWORD",
			DefaultDatabaseVar: "MYSQL_DATABASE",
		},
		"postgresql": {
			Image:              "postgres:16",
			InternalPort:       5432,
			VolumePath:         "/var/lib/postgresql/data",
			EnvPrefix:          "POSTGRES",
			RootPasswordVar:    "POSTGRES_PASSWORD",
			DefaultUserVar:     "POSTGRES_USER",
			DefaultPasswordVar: "POSTGRES_PASSWORD",
			DefaultDatabaseVar: "POSTGRES_DB",
		},
		"mariadb": {
			Image:              "mariadb:11.2",
			InternalPort:       3306,
			VolumePath:         "/var/lib/mysql",
			EnvPrefix:          "MARIADB",
			RootPasswordVar:    "MARIADB_ROOT_PASSWORD",
			DefaultUserVar:     "MARIADB_USER",
			DefaultPasswordVar: "MARIADB_PASSWORD",
			DefaultDatabaseVar: "MARIADB_DATABASE",
		},
		"redis": {
			Image:              "redis:7-alpine",
			InternalPort:       6379,
			VolumePath:         "/data",
			EnvPrefix:          "REDIS",
			RootPasswordVar:    "REDIS_PASSWORD",
			DefaultUserVar:     "",
			DefaultPasswordVar: "",
			DefaultDatabaseVar: "",
		},
		"mongodb": {
			Image:              "mongo:7",
			InternalPort:       27017,
			VolumePath:         "/data/db",
			EnvPrefix:          "MONGO",
			RootPasswordVar:    "MONGO_INITDB_ROOT_PASSWORD",
			DefaultUserVar:     "MONGO_INITDB_ROOT_USERNAME",
			DefaultPasswordVar: "MONGO_INITDB_ROOT_PASSWORD",
			DefaultDatabaseVar: "MONGO_INITDB_DATABASE",
		},
	}

	config, exists := configs[dbType]
	if !exists {
		return nil, fmt.Errorf("unsupported database type: %s", dbType)
	}

	return config, nil
}

func (d *DatabaseServiceImpl) emitProgress(ctx context.Context, percent float64, message string, bytesDone, bytesTotal, etaSeconds int64) {
	if d.wsEmitter == nil || !d.wsEmitter.IsConnected() {
		return
	}

	backupUID, _ := ctx.Value(types.ContextKeyBackupUID).(string)
	serviceUID, _ := ctx.Value(types.ContextKeyBackupServiceUID).(string)
	if backupUID == "" || serviceUID == "" {
		return
	}

	if etaSeconds == 0 {
		if start, ok := ctx.Value(types.ContextKeyBackupStartTime).(time.Time); ok && bytesDone > 0 && bytesTotal > bytesDone {
			elapsed := time.Since(start).Seconds()
			if elapsed > 0 {
				rate := float64(bytesDone) / elapsed
				if rate > 0 {
					remaining := float64(bytesTotal-bytesDone) / rate
					etaSeconds = int64(math.Ceil(remaining))
				}
			}
		}
	}

	payload := map[string]interface{}{
		"backup_uid":  backupUID,
		"service_uid": serviceUID,
		"percent":     percent,
		"message":     message,
		"status":      "in_progress",
	}
	if bytesDone > 0 {
		payload["bytes_done"] = bytesDone
	}
	if bytesTotal > 0 {
		payload["bytes_total"] = bytesTotal
	}
	if etaSeconds > 0 {
		payload["eta_seconds"] = etaSeconds
	}

	if err := d.wsEmitter.Emit("backup_progress_update", payload); err != nil {
		d.logger.Error("Failed to emit backup progress update", "backup_uid", backupUID, "error", err)
	}
}

func (d *DatabaseServiceImpl) emitStatus(ctx context.Context, status string, extra map[string]interface{}) {
	if d.wsEmitter == nil || !d.wsEmitter.IsConnected() {
		return
	}

	backupUID, _ := ctx.Value(types.ContextKeyBackupUID).(string)
	serviceUID, _ := ctx.Value(types.ContextKeyBackupServiceUID).(string)
	if backupUID == "" || serviceUID == "" {
		return
	}

	payload := map[string]interface{}{
		"backup_uid":  backupUID,
		"service_uid": serviceUID,
		"status":      status,
	}
	for k, v := range extra {
		payload[k] = v
	}

	if err := d.wsEmitter.Emit("backup_status_update", payload); err != nil {
		d.logger.Error("Failed to emit backup status update", "backup_uid", backupUID, "error", err)
	}
}

// findAvailablePort finds the next available port starting from startPort
func (d *DatabaseServiceImpl) findAvailablePort(ctx context.Context, startPort int) (int, error) {
	services, err := d.dockerService.ListContainers(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to list containers: %w", err)
	}

	usedPorts := make(map[int]bool)
	for _, service := range services {
		if service.Port > 0 {
			usedPorts[service.Port] = true
		}
	}

	currentPort := startPort
	for usedPorts[currentPort] {
		currentPort++
	}

	return currentPort, nil
}

// isPortInUseByContainer checks if a port is already in use by a Docker container
func (d *DatabaseServiceImpl) isPortInUseByContainer(ctx context.Context, port int) (string, error) {
	services, err := d.dockerService.ListContainers(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to list containers: %w", err)
	}

	for _, service := range services {
		if service.Port == port {
			return service.Name, nil
		}
	}

	return "", nil
}

// DeployDatabase deploys a database container
func (d *DatabaseServiceImpl) DeployDatabase(ctx context.Context, dbType, password, name string, port *int, username, database, deploymentUID string) (*types.DatabaseDeploymentResult, error) {
	d.logger.Info("Deploying database",
		"type", dbType,
		"name", name,
		"port", port,
		"username", username,
		"database", database)

	config, err := d.getDatabaseConfig(dbType)
	if err != nil {
		return nil, err
	}

	if deploymentUID == "" {
		deploymentUID = fmt.Sprintf("dep_%d", time.Now().UnixNano())
	}

	// Check if container already exists and remove it (for redeployment)
	containerName := fmt.Sprintf("outlap-db-%s", name)

	// Always attempt to remove the container, even if ContainerExists fails or returns false
	// This handles edge cases where the container exists but wasn't detected
	d.logger.Debug("Attempting to remove any existing container", "container", containerName)
	if err := d.dockerService.RemoveContainerByName(ctx, containerName); err != nil {
		// Only log as debug if container doesn't exist, error otherwise
		if strings.Contains(err.Error(), "No such container") || strings.Contains(err.Error(), "not found") {
			d.logger.Debug("No existing container to remove", "container", containerName)
		} else {
			d.logger.Error("Failed to remove existing container", "container", containerName, "error", err)
			return nil, fmt.Errorf("failed to remove existing container %s: %w", containerName, err)
		}
	} else {
		d.logger.Info("Successfully removed existing container for redeployment", "container", containerName)
	}

	// Create Docker volume for persistence
	volumeName := fmt.Sprintf("outlap-db-vol-%s", name)
	if err := d.createDockerVolume(ctx, volumeName); err != nil {
		return nil, fmt.Errorf("failed to create Docker volume: %w", err)
	}

	// Find available port if none specified
	var finalPort int
	if port == nil {
		finalPort, err = d.findAvailablePort(ctx, config.InternalPort)
		if err != nil {
			return nil, fmt.Errorf("failed to find available port: %w", err)
		}
	} else {
		finalPort = *port
		// Check if port is already in use
		containerName, err := d.isPortInUseByContainer(ctx, finalPort)
		if err != nil {
			return nil, fmt.Errorf("failed to check port usage: %w", err)
		}
		if containerName != "" {
			return nil, &DatabasePortInUseError{
				Port:          finalPort,
				ContainerName: containerName,
			}
		}
	}

	// Prepare environment variables based on database type
	var environment []string
	switch dbType {
	case "redis":
		// Redis uses a different authentication approach
		if password != "" {
			environment = []string{
				fmt.Sprintf("REDIS_PASSWORD=%s", password),
			}
		}
	case "mongodb":
		// MongoDB requires root username and password
		environment = []string{
			fmt.Sprintf("%s=%s", config.RootPasswordVar, password),
			fmt.Sprintf("%s=%s", config.DefaultUserVar, username),
		}
		if database != "" && database != "default" {
			environment = append(environment, fmt.Sprintf("%s=%s", config.DefaultDatabaseVar, database))
		}
	default:
		// Traditional SQL databases (MySQL, PostgreSQL, MariaDB)
		environment = []string{
			fmt.Sprintf("%s=%s", config.RootPasswordVar, password),
			fmt.Sprintf("%s=%s", config.DefaultUserVar, username),
			fmt.Sprintf("%s=%s", config.DefaultPasswordVar, password),
			fmt.Sprintf("%s=%s", config.DefaultDatabaseVar, database),
		}
	}

	// Pull the image first
	if err := d.dockerService.PullImage(ctx, config.Image); err != nil {
		d.logger.Warn("Failed to pull image, continuing with local image", "image", config.Image, "error", err)
	}

	// Prepare container configuration
	exposedPorts := nat.PortSet{}
	exposedPorts[nat.Port(fmt.Sprintf("%d/tcp", config.InternalPort))] = struct{}{}

	containerConfig := &container.Config{
		Image:        config.Image,
		Env:          environment,
		ExposedPorts: exposedPorts,
		Labels: map[string]string{
			"outlap.service_uid":    name,
			"outlap.deployment_uid": deploymentUID,
			"outlap.managed":        "true",
			databaseTypeLabelKey:    dbType,
		},
	}

	// Add specific command for Redis with password authentication
	if dbType == "redis" && password != "" {
		containerConfig.Cmd = []string{"redis-server", "--requirepass", password}
	}

	// Prepare host configuration
	portBindings := nat.PortMap{}
	portBindings[nat.Port(fmt.Sprintf("%d/tcp", config.InternalPort))] = []nat.PortBinding{
		{
			HostIP:   "0.0.0.0",
			HostPort: strconv.Itoa(finalPort),
		},
	}

	hostConfig := &container.HostConfig{
		PortBindings: portBindings,
		RestartPolicy: container.RestartPolicy{
			Name: "no",
		},
		Mounts: []mount.Mount{
			{
				Type:   mount.TypeVolume,
				Source: volumeName,
				Target: config.VolumePath,
			},
		},
	}

	// Create and start container (containerName already defined above)
	containerID, err := d.dockerService.CreateContainer(ctx, containerConfig, hostConfig, containerName)
	if err != nil {
		return nil, fmt.Errorf("failed to create database container: %w", err)
	}

	// Start the container
	if err := d.dockerService.StartContainer(ctx, containerID); err != nil {
		return nil, fmt.Errorf("failed to start database container: %w", err)
	}

	d.logger.Info("Database deployed successfully",
		"container_id", containerID[:12],
		"name", containerName,
		"port", finalPort,
		"type", dbType)

	return &types.DatabaseDeploymentResult{
		ContainerID:   containerID,
		Name:          containerName,
		Port:          finalPort,
		Type:          dbType,
		Username:      username,
		Database:      database,
		VolumePath:    volumeName,
		DeploymentUID: deploymentUID,
	}, nil
}

// CreateDatabase creates a new database (alias for DeployDatabase for interface compatibility)
func (d *DatabaseServiceImpl) CreateDatabase(ctx context.Context, dbType, name string) error {
	// Use default values for interface compatibility
	_, err := d.DeployDatabase(ctx, dbType, "defaultpassword", name, nil, "admin", "default", "")
	return err
}

// DeleteDatabase removes a database container and optionally its volume
func (d *DatabaseServiceImpl) DeleteDatabase(ctx context.Context, name string) error {
	d.logger.Info("Deleting database", "name", name)

	containerName := fmt.Sprintf("outlap-db-%s", name)

	// Remove the container
	if err := d.dockerService.RemoveContainer(ctx, containerName); err != nil {
		return fmt.Errorf("failed to remove database container: %w", err)
	}

	d.logger.Info("Database deleted successfully", "name", name)
	return nil
}

// BackupDatabase creates a backup of the database
func (d *DatabaseServiceImpl) BackupDatabase(ctx context.Context, name string) (*types.DatabaseBackupResult, error) {
	d.logger.Info("Creating database backup", "name", name)

	if _, ok := ctx.Value(types.ContextKeyBackupStartTime).(time.Time); !ok {
		ctx = context.WithValue(ctx, types.ContextKeyBackupStartTime, time.Now())
	}

	d.emitProgress(ctx, 5, "Preparing backup", 0, 0, 0)

	// Get container information
	containerName := fmt.Sprintf("outlap-db-%s", name)

	// Check if container exists and is running
	containers, err := d.dockerService.ListContainers(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	var containerInfo *types.ServiceInfo
	for _, container := range containers {
		if container.Name == containerName {
			containerInfo = &container
			break
		}
	}

	if containerInfo == nil {
		return nil, fmt.Errorf("database container %s not found", containerName)
	}

	if containerInfo.Status != types.ServiceStatusRunning {
		return nil, fmt.Errorf("database container %s is not running (status: %s)", containerName, containerInfo.Status)
	}

	// Create backup directory on host
	backupDir := getBackupBaseDir()
	databaseBackupDir := filepath.Join(backupDir, name)
	if err := os.MkdirAll(databaseBackupDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create backup directory: %w", err)
	}

	// Generate backup filename with timestamp
	timestamp := time.Now().Format("20060102_150405")
	var backupFilename string
	var backupPath string

	// Detect database type first to determine file extension
	dbType, err := d.detectDatabaseType(ctx, containerInfo.UID)
	if err != nil {
		return nil, fmt.Errorf("failed to detect database type: %w", err)
	}

	switch dbType {
	case "redis":
		backupFilename = fmt.Sprintf("backup_%s.rdb", timestamp)
	case "mongodb":
		backupFilename = fmt.Sprintf("backup_%s.archive", timestamp)
	default:
		backupFilename = fmt.Sprintf("backup_%s.sql", timestamp)
	}
	backupPath = filepath.Join(databaseBackupDir, backupFilename)

	// TODO: Add S3 export functionality here
	// This is where we would implement S3Service.UploadBackup(backupPath) for cloud storage

	var backupCmd []string
	switch dbType {
	case "mysql", "mariadb":
		backupCmd = []string{"sh", "-c", fmt.Sprintf("mysqldump -u root -p$MYSQL_ROOT_PASSWORD --all-databases > /tmp/%s", backupFilename)}
	case "postgresql":
		backupCmd = []string{"sh", "-c", fmt.Sprintf("pg_dumpall -U $POSTGRES_USER > /tmp/%s", backupFilename)}
	case "redis":
		// Redis backup using BGSAVE and copying the dump.rdb file
		backupCmd = []string{"sh", "-c", fmt.Sprintf("redis-cli --rdb /tmp/%s", backupFilename)}
	case "mongodb":
		// MongoDB backup using mongodump
		backupCmd = []string{"sh", "-c", fmt.Sprintf("mongodump --archive=/tmp/%s --gzip", backupFilename)}
	default:
		return nil, fmt.Errorf("unsupported database type: %s", dbType)
	}

	// Execute backup command inside container
	d.logger.Debug("Executing backup command", "container", containerInfo.UID[:12], "command", backupCmd)
	execResult, err := d.dockerService.ExecContainer(ctx, containerInfo.UID, backupCmd)
	if err != nil {
		return nil, fmt.Errorf("failed to execute backup command: %w", err)
	}

	if execResult.ExitCode != 0 {
		return nil, fmt.Errorf("backup command failed: %s", execResult.Error)
	}

	d.emitProgress(ctx, 45, "Backup command completed", 0, 0, 0)

	// Copy backup file from container to host
	copyCmd := []string{"sh", "-c", fmt.Sprintf("cat /tmp/%s", backupFilename)}
	copyResult, err := d.dockerService.ExecContainer(ctx, containerInfo.UID, copyCmd)
	if err != nil {
		return nil, fmt.Errorf("failed to copy backup from container: %w", err)
	}

	if copyResult.ExitCode != 0 {
		return nil, fmt.Errorf("failed to read backup file: %s", copyResult.Error)
	}

	backupBytes := []byte(copyResult.Output)
	bytesTotal := int64(len(backupBytes))
	d.emitProgress(ctx, 75, "Transferring backup data", bytesTotal, bytesTotal, 0)

	// Write backup to host filesystem
	if err := os.WriteFile(backupPath, backupBytes, 0644); err != nil {
		return nil, fmt.Errorf("failed to write backup file: %w", err)
	}

	d.emitProgress(ctx, 90, "Finalizing backup", bytesTotal, bytesTotal, 0)

	// Cleanup temporary file in container
	cleanupCmd := []string{"rm", "-f", fmt.Sprintf("/tmp/%s", backupFilename)}
	_, _ = d.dockerService.ExecContainer(ctx, containerInfo.UID, cleanupCmd) // Ignore errors for cleanup

	// Get file size
	fileInfo, err := os.Stat(backupPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get backup file info: %w", err)
	}

	result := &types.DatabaseBackupResult{
		BackupPath: backupPath,
		Database:   name,
		Type:       dbType,
		Size:       fileInfo.Size(),
		CreatedAt:  time.Now(),
	}

	d.emitProgress(ctx, 100, "Backup complete", bytesTotal, bytesTotal, 0)

	d.logger.Info("Database backup completed successfully",
		"name", name,
		"backup_path", backupPath,
		"size_bytes", fileInfo.Size(),
		"type", dbType)

	return result, nil
}

// RestoreDatabase restores a database from backup
func (d *DatabaseServiceImpl) RestoreDatabase(ctx context.Context, name, backupPath string) error {
	d.logger.Info("Restoring database", "name", name, "backup_path", backupPath)

	// Check if backup file exists
	if _, err := os.Stat(backupPath); err != nil {
		return fmt.Errorf("backup file not found: %w", err)
	}

	// Get container information
	containerName := fmt.Sprintf("outlap-db-%s", name)
	containers, err := d.dockerService.ListContainers(ctx)
	if err != nil {
		return fmt.Errorf("failed to list containers: %w", err)
	}

	var containerInfo *types.ServiceInfo
	for _, container := range containers {
		if container.Name == containerName {
			containerInfo = &container
			break
		}
	}

	if containerInfo == nil {
		return fmt.Errorf("database container %s not found", containerName)
	}

	if containerInfo.Status != types.ServiceStatusRunning {
		return fmt.Errorf("database container %s is not running (status: %s)", containerName, containerInfo.Status)
	}

	// Read backup file
	backupData, err := os.ReadFile(backupPath)
	if err != nil {
		return fmt.Errorf("failed to read backup file: %w", err)
	}

	// Detect database type
	dbType, err := d.detectDatabaseType(ctx, containerInfo.UID)
	if err != nil {
		return fmt.Errorf("failed to detect database type: %w", err)
	}

	// Create temporary file in container with backup data
	var tempFilename string
	switch dbType {
	case "redis":
		tempFilename = fmt.Sprintf("restore_%d.rdb", time.Now().Unix())
	case "mongodb":
		tempFilename = fmt.Sprintf("restore_%d.archive", time.Now().Unix())
	default:
		tempFilename = fmt.Sprintf("restore_%d.sql", time.Now().Unix())
	}
	createFileCmd := []string{"sh", "-c", fmt.Sprintf("cat > /tmp/%s << 'EOF'\n%s\nEOF", tempFilename, string(backupData))}

	execResult, err := d.dockerService.ExecContainer(ctx, containerInfo.UID, createFileCmd)
	if err != nil {
		return fmt.Errorf("failed to create restore file in container: %w", err)
	}

	if execResult.ExitCode != 0 {
		return fmt.Errorf("failed to create restore file: %s", execResult.Error)
	}

	// Execute restore command based on database type
	var restoreCmd []string
	switch dbType {
	case "mysql", "mariadb":
		restoreCmd = []string{"sh", "-c", fmt.Sprintf("mysql -u root -p$MYSQL_ROOT_PASSWORD < /tmp/%s", tempFilename)}
	case "postgresql":
		restoreCmd = []string{"sh", "-c", fmt.Sprintf("psql -U $POSTGRES_USER < /tmp/%s", tempFilename)}
	case "redis":
		// Redis restore by stopping server, replacing dump.rdb, and restarting
		restoreCmd = []string{"sh", "-c", fmt.Sprintf("redis-cli SHUTDOWN NOSAVE && cp /tmp/%s /data/dump.rdb && redis-server --daemonize yes", tempFilename)}
	case "mongodb":
		// MongoDB restore using mongorestore
		restoreCmd = []string{"sh", "-c", fmt.Sprintf("mongorestore --archive=/tmp/%s --gzip --drop", tempFilename)}
	default:
		return fmt.Errorf("unsupported database type: %s", dbType)
	}

	d.logger.Debug("Executing restore command", "container", containerInfo.UID[:12], "command", restoreCmd)
	execResult, err = d.dockerService.ExecContainer(ctx, containerInfo.UID, restoreCmd)
	if err != nil {
		return fmt.Errorf("failed to execute restore command: %w", err)
	}

	if execResult.ExitCode != 0 {
		return fmt.Errorf("restore command failed: %s", execResult.Error)
	}

	// Cleanup temporary file
	cleanupCmd := []string{"rm", "-f", fmt.Sprintf("/tmp/%s", tempFilename)}
	_, _ = d.dockerService.ExecContainer(ctx, containerInfo.UID, cleanupCmd) // Ignore errors for cleanup

	d.logger.Info("Database restore completed successfully", "name", name, "backup_path", backupPath)
	return nil
}

// GetDatabaseStatus returns the status of a database container
func (d *DatabaseServiceImpl) GetDatabaseStatus(ctx context.Context, name string) (types.ServiceStatus, error) {
	d.logger.Debug("Getting database status", "name", name)

	containerName := fmt.Sprintf("outlap-db-%s", name)
	return d.dockerService.GetContainerStatus(ctx, containerName)
}

// createDockerVolume creates a Docker volume if it doesn't exist
func (d *DatabaseServiceImpl) createDockerVolume(ctx context.Context, volumeName string) error {
	// Check if volume already exists
	exists, err := d.dockerService.VolumeExists(ctx, volumeName)
	if err != nil {
		return fmt.Errorf("failed to check if volume exists: %w", err)
	}

	if exists {
		d.logger.Debug("Volume already exists", "volume", volumeName)
		return nil
	}

	// Create the volume
	labels := map[string]string{
		"outlap.component": "database",
		"outlap.type":      "data",
	}

	if err := d.dockerService.CreateVolume(ctx, volumeName, labels); err != nil {
		return fmt.Errorf("failed to create volume: %w", err)
	}

	d.logger.Info("Docker volume created successfully", "volume", volumeName)
	return nil
}

// detectDatabaseType detects the database type by inspecting the container
func (d *DatabaseServiceImpl) detectDatabaseType(ctx context.Context, containerID string) (string, error) {
	inspect, err := d.dockerService.InspectContainer(ctx, containerID)
	if err == nil {
		if inspect.Config != nil {
			if dbType, ok := inspect.Config.Labels[databaseTypeLabelKey]; ok && dbType != "" {
				d.logger.Debug("Detected database type from label", "container_id", containerID, "type", dbType)
				return dbType, nil
			}
		}
	} else {
		d.logger.Debug("Failed to inspect container for database type", "container_id", containerID, "error", err)
	}

	return "", fmt.Errorf("unable to detect database type")
}

// ListBackups returns a list of available backups for a database
func (d *DatabaseServiceImpl) ListBackups(ctx context.Context, name string) ([]types.DatabaseBackupResult, error) {
	d.logger.Debug("Listing database backups", "name", name)

	backupDir := filepath.Join(getBackupBaseDir(), name)

	// Check if backup directory exists
	if _, err := os.Stat(backupDir); os.IsNotExist(err) {
		return []types.DatabaseBackupResult{}, nil // Return empty list if no backups exist
	}

	// Read backup directory
	files, err := os.ReadDir(backupDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read backup directory: %w", err)
	}

	var backups []types.DatabaseBackupResult
	for _, file := range files {
		if file.IsDir() {
			continue // Skip directories
		}

		// Check for valid backup file extensions
		fileName := file.Name()
		var dbType string
		if strings.HasSuffix(fileName, ".sql") {
			dbType = "sql" // Could be MySQL, PostgreSQL, or MariaDB
		} else if strings.HasSuffix(fileName, ".rdb") {
			dbType = "redis"
		} else if strings.HasSuffix(fileName, ".archive") {
			dbType = "mongodb"
		} else {
			continue // Skip files with unknown extensions
		}

		filePath := filepath.Join(backupDir, fileName)
		fileInfo, err := file.Info()
		if err != nil {
			d.logger.Warn("Failed to get file info for backup", "file", filePath, "error", err)
			continue
		}

		backup := types.DatabaseBackupResult{
			BackupPath: filePath,
			Database:   name,
			Type:       dbType,
			Size:       fileInfo.Size(),
			CreatedAt:  fileInfo.ModTime(),
		}

		backups = append(backups, backup)
	}

	d.logger.Debug("Found backups", "name", name, "count", len(backups))
	return backups, nil
}

func (d *DatabaseServiceImpl) ConfigureAutomation(ctx context.Context, serviceUID string, config types.BackupAutomationConfig) error {
	d.automationMu.Lock()
	defer d.automationMu.Unlock()

	// Remove any existing scheduled job
	if entryID, exists := d.automationJobs[serviceUID]; exists {
		d.automationCron.Remove(entryID)
		delete(d.automationJobs, serviceUID)
	}

	d.automationConfigs[serviceUID] = config

	if !config.Enabled || config.CronExpression == "" {
		d.logger.Info("Backup automation disabled", "service_uid", serviceUID)
		return nil
	}

	entryID, err := d.automationCron.AddFunc(config.CronExpression, func() {
		cfg := d.getAutomationConfig(serviceUID)
		if !cfg.Enabled {
			return
		}
		d.automationExec(context.Background(), serviceUID, cfg)
	})
	if err != nil {
		return fmt.Errorf("failed to schedule automation: %w", err)
	}

	d.automationJobs[serviceUID] = entryID
	d.logger.Info("Backup automation configured", "service_uid", serviceUID, "cron", config.CronExpression, "storage_path", config.StoragePath, "retention_days", config.RetentionDays)

	return nil
}

func (d *DatabaseServiceImpl) getAutomationConfig(serviceUID string) types.BackupAutomationConfig {
	d.automationMu.Lock()
	defer d.automationMu.Unlock()
	return d.automationConfigs[serviceUID]
}

func (d *DatabaseServiceImpl) runScheduledBackup(ctx context.Context, serviceUID string, config types.BackupAutomationConfig) {
	backupUID := fmt.Sprintf("auto-%s-%s", serviceUID, uuid.NewString())
	ctx = context.WithValue(ctx, types.ContextKeyBackupUID, backupUID)
	ctx = context.WithValue(ctx, types.ContextKeyBackupServiceUID, serviceUID)
	ctx = context.WithValue(ctx, types.ContextKeyBackupStartTime, time.Now())

	if config.StoragePath != "" {
		if err := os.MkdirAll(config.StoragePath, 0o755); err != nil {
			d.logger.Error("Failed to prepare automation storage path", "service_uid", serviceUID, "path", config.StoragePath, "error", err)
		}
	}

	d.emitStatus(ctx, "in_progress", map[string]interface{}{
		"started_at":  time.Now(),
		"backup_type": "scheduled",
	})

	result, err := d.BackupDatabase(ctx, serviceUID)
	if err != nil {
		d.emitStatus(ctx, "failed", map[string]interface{}{
			"error_message": err.Error(),
			"backup_type":   "scheduled",
		})
		d.logger.Error("Automated backup failed", "service_uid", serviceUID, "error", err)
		return
	}

	finalPath := result.BackupPath
	if config.StoragePath != "" {
		if copiedPath, copyErr := d.copyBackupToPath(result.BackupPath, config.StoragePath); copyErr != nil {
			d.logger.Error("Failed to copy automated backup", "service_uid", serviceUID, "error", copyErr)
		} else {
			finalPath = copiedPath
		}
	}

	if config.RetentionDays > 0 && config.StoragePath != "" {
		if err := d.applyRetention(config.StoragePath, config.RetentionDays); err != nil {
			d.logger.Warn("Failed to enforce backup retention", "service_uid", serviceUID, "error", err)
		}
	}

	fileInfo, err := os.Stat(finalPath)
	if err != nil {
		d.logger.Warn("Unable to stat automated backup file", "path", finalPath, "error", err)
	}

	d.emitStatus(ctx, "completed", map[string]interface{}{
		"file_path": finalPath,
		"file_size": func() int64 {
			if fileInfo != nil {
				return fileInfo.Size()
			}
			return result.Size
		}(),
		"backup_type": "scheduled",
	})

	d.logger.Info("Automated backup completed", "service_uid", serviceUID, "backup_uid", backupUID, "path", finalPath)
}

func (d *DatabaseServiceImpl) VerifyBackupStoragePath(ctx context.Context, serviceUID, storagePath string) (*types.BackupStorageVerificationResult, error) {
	trimmed := strings.TrimSpace(storagePath)
	if trimmed == "" {
		return nil, fmt.Errorf("storage path is required")
	}

	normalized := filepath.Clean(trimmed)
	if !filepath.IsAbs(normalized) {
		normalized = filepath.Join(getBackupBaseDir(), normalized)
	}

	info, err := os.Stat(normalized)
	if err != nil {
		if !os.IsNotExist(err) {
			return &types.BackupStorageVerificationResult{
				Success: false,
				Message: fmt.Sprintf("failed to inspect path: %v", err),
			}, nil
		}
		if mkErr := os.MkdirAll(normalized, 0o755); mkErr != nil {
			return &types.BackupStorageVerificationResult{
				Success: false,
				Message: fmt.Sprintf("failed to create directory: %v", mkErr),
			}, nil
		}
	} else if !info.IsDir() {
		return &types.BackupStorageVerificationResult{
			Success: false,
			Message: fmt.Sprintf("path exists but is not a directory: %s", normalized),
		}, nil
	}

	testFile := filepath.Join(normalized, fmt.Sprintf(".outlap-storage-test-%d", time.Now().UnixNano()))
	if err := os.WriteFile(testFile, []byte("outlap"), 0o644); err != nil {
		return &types.BackupStorageVerificationResult{
			Success: false,
			Message: fmt.Sprintf("failed to write test file: %v", err),
		}, nil
	}
	if err := os.Remove(testFile); err != nil {
		d.logger.Warn("failed to remove storage verification file", "path", testFile, "error", err)
	}

	d.logger.Info("Storage path verified", "service_uid", serviceUID, "path", normalized)

	return &types.BackupStorageVerificationResult{
		Success:        true,
		NormalizedPath: normalized,
		Message:        "Storage path verified",
	}, nil
}

func (d *DatabaseServiceImpl) copyBackupToPath(srcPath, destDir string) (string, error) {
	if destDir == "" {
		return srcPath, nil
	}

	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return srcPath, err
	}

	destination := filepath.Join(destDir, filepath.Base(srcPath))
	src, err := os.Open(srcPath)
	if err != nil {
		return srcPath, err
	}
	defer src.Close()

	dst, err := os.Create(destination)
	if err != nil {
		return srcPath, err
	}
	defer dst.Close()

	if _, err := io.Copy(dst, src); err != nil {
		return srcPath, err
	}

	return destination, nil
}

func (d *DatabaseServiceImpl) applyRetention(path string, retentionDays int) error {
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}

	cutoff := time.Now().AddDate(0, 0, -retentionDays)

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			d.logger.Warn("Failed to stat backup for retention", "name", entry.Name(), "error", err)
			continue
		}
		if info.ModTime().Before(cutoff) {
			filePath := filepath.Join(path, entry.Name())
			if err := os.Remove(filePath); err != nil {
				d.logger.Warn("Failed to remove expired backup", "path", filePath, "error", err)
			} else {
				d.logger.Info("Removed expired automated backup", "path", filePath)
			}
		}
	}

	return nil
}
