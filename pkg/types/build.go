package types

import "time"

// BuildType represents the type of build to perform
type BuildType string

const (
	BuildTypeNixpacks      BuildType = "nixpacks"
	BuildTypeDockerfile    BuildType = "dockerfile"
	BuildTypeDockerCompose BuildType = "docker-compose"
)

// BuildConfig contains configuration for building an application
type BuildConfig struct {
	Name         string            `json:"name"`
	SourcePath   string            `json:"source_path"`
	BaseDir      string            `json:"base_dir"`
	BuildType    BuildType         `json:"build_type"`
	Environment  map[string]string `json:"environment,omitempty"`
	StartCommand string            `json:"start_command,omitempty"`
}

// BuildResult contains the result of a build operation
type BuildResult struct {
	Success       bool      `json:"success"`
	ImageName     string    `json:"image_name"`
	BuildTime     time.Time `json:"build_time"`
	BuildLogs     string    `json:"build_logs,omitempty"`
	Error         string    `json:"error,omitempty"`
	CommitSHA     string    `json:"commit_sha,omitempty"`
	CommitMessage string    `json:"commit_message,omitempty"`
	DeploymentUID string    `json:"deployment_uid,omitempty"`
}

// DeployConfig contains configuration for deploying an application
type DeployConfig struct {
	Name        string            `json:"name"`
	ImageName   string            `json:"image_name"`
	Port        int               `json:"port"`
	Environment map[string]string `json:"environment,omitempty"`
	Command     string            `json:"command,omitempty"`
	Volumes     []string          `json:"volumes,omitempty"`
}

// DeployResult contains the result of a deployment operation
type DeployResult struct {
	Success     bool      `json:"success"`
	ContainerID string    `json:"container_id,omitempty"`
	Port        int       `json:"port,omitempty"`
	DeployTime  time.Time `json:"deploy_time"`
	Error       string    `json:"error,omitempty"`
}

// AppDeploymentStatus represents the status of an application deployment
type AppDeploymentStatus struct {
	Name      string        `json:"name"`
	Status    ServiceStatus `json:"status"`
	Port      int           `json:"port,omitempty"`
	UpdatedAt time.Time     `json:"updated_at,omitempty"`
	Error     string        `json:"error,omitempty"`
}
