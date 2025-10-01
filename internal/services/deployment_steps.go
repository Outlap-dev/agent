package services

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"pulseup-agent-go/pkg/logger"
	"pulseup-agent-go/pkg/types"
)

// deploymentStepTracker manages lifecycle metadata for deployment timeline steps.
type deploymentStepTracker struct {
	logger *logger.Logger
	path   string
	steps  []*types.DeploymentStep
	index  map[string]int
	mu     sync.Mutex
}

var _ types.DeploymentStepRecorder = (*deploymentStepTracker)(nil)

func newDeploymentStepTracker(baseLogger *logger.Logger, logsDir, serviceUID, deploymentUID string, templates ...types.DeploymentStep) *deploymentStepTracker {
	if deploymentUID == "" {
		return nil
	}

	if err := os.MkdirAll(logsDir, 0o755); err != nil {
		baseLogger.Warn("Failed to ensure logs directory for step tracker", "dir", logsDir, "error", err)
		return nil
	}

	path := filepath.Join(logsDir, fmt.Sprintf("%s_steps.json", deploymentUID))

	tracker := &deploymentStepTracker{
		logger: baseLogger.With("component", "deployment_step_tracker", "deployment_uid", deploymentUID, "service_uid", serviceUID),
		path:   path,
		steps:  make([]*types.DeploymentStep, 0, 4),
		index:  make(map[string]int),
	}

	return tracker.withTemplates(templates)
}

func (t *deploymentStepTracker) withTemplates(templates []types.DeploymentStep) *deploymentStepTracker {
	if t == nil || len(templates) == 0 {
		return t
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	for _, tpl := range templates {
		if tpl.ID == "" {
			continue
		}

		step := tpl
		if step.Status == "" {
			step.Status = types.DeploymentStepStatusPending
		}
		if !step.StartedAt.IsZero() {
			step.StartedAt = step.StartedAt.UTC()
		}
		if step.CompletedAt != nil {
			completed := step.CompletedAt.UTC()
			step.CompletedAt = &completed
		}
		if step.Metadata == nil {
			step.Metadata = map[string]interface{}{}
		}

		// Skip if template already exists
		if _, exists := t.index[step.ID]; exists {
			idx := t.index[step.ID]
			t.steps[idx] = &step
			continue
		}

		t.index[step.ID] = len(t.steps)
		t.steps = append(t.steps, &step)
	}

	if len(t.steps) > 0 {
		t.persistLocked()
	}

	return t
}

func (t *deploymentStepTracker) StartStep(id, name, description, logType string) {
	if t == nil {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now().UTC()

	if existing := t.getStepLocked(id); existing != nil {
		existing.Status = types.DeploymentStepStatusRunning
		if existing.Name == "" {
			existing.Name = name
		}
		if description != "" {
			existing.Description = description
		}
		if existing.LogType == "" {
			existing.LogType = logType
		}
		if existing.Metadata == nil {
			existing.Metadata = map[string]interface{}{}
		}
		if existing.StartedAt.IsZero() {
			existing.StartedAt = now
		}
		existing.Error = ""
		existing.CompletedAt = nil
		t.persistLocked()
		return
	}

	step := &types.DeploymentStep{
		ID:        id,
		Name:      name,
		Status:    types.DeploymentStepStatusRunning,
		StartedAt: now,
		LogType:   logType,
		Metadata:  map[string]interface{}{},
	}
	if description != "" {
		step.Description = description
	}

	t.index[id] = len(t.steps)
	t.steps = append(t.steps, step)
	t.persistLocked()
}

func (t *deploymentStepTracker) AppendLog(stepID, level, message string) {
	if t == nil {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if step := t.getStepLocked(stepID); step != nil {
		step.Logs = append(step.Logs, types.DeploymentStepLog{
			Timestamp: time.Now().UTC(),
			Level:     level,
			Message:   message,
		})
		t.persistLocked()
	}
}

func (t *deploymentStepTracker) CompleteStep(stepID string) {
	t.finishStep(stepID, types.DeploymentStepStatusSuccess, "")
}

func (t *deploymentStepTracker) FailStep(stepID, errorMessage string) {
	t.finishStep(stepID, types.DeploymentStepStatusError, errorMessage)
}

func (t *deploymentStepTracker) finishStep(stepID string, status types.DeploymentStepStatus, errorMessage string) {
	if t == nil {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	step := t.getStepLocked(stepID)
	if step == nil {
		return
	}

	step.Status = status
	now := time.Now().UTC()
	if step.StartedAt.IsZero() {
		step.StartedAt = now
	}
	step.CompletedAt = &now
	if errorMessage != "" {
		step.Error = errorMessage
	}

	t.persistLocked()
}

func (t *deploymentStepTracker) getStepLocked(stepID string) *types.DeploymentStep {
	idx, ok := t.index[stepID]
	if !ok {
		t.logger.Debug("Attempted to update unknown deployment step", "step_id", stepID)
		return nil
	}

	if idx < 0 || idx >= len(t.steps) {
		return nil
	}

	return t.steps[idx]
}

func (t *deploymentStepTracker) persistLocked() {
	if t == nil {
		return
	}

	data, err := json.MarshalIndent(t.steps, "", "  ")
	if err != nil {
		t.logger.Warn("Failed to marshal deployment steps", "error", err)
		return
	}

	if err := os.WriteFile(t.path, data, 0o644); err != nil {
		t.logger.Warn("Failed to persist deployment steps", "path", t.path, "error", err)
	}
}

func (t *deploymentStepTracker) SetMetadata(stepID, key string, value interface{}) {
	if t == nil {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	step := t.getStepLocked(stepID)
	if step == nil {
		return
	}

	if step.Metadata == nil {
		step.Metadata = map[string]interface{}{}
	}

	step.Metadata[key] = value
	t.persistLocked()
}
