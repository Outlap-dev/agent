package services

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"

	wscontracts "pulseup-agent-go/pkg/contracts/websocket"
	"pulseup-agent-go/pkg/logger"
	pulseuptypes "pulseup-agent-go/pkg/types"
)

// dockerEventsClient exposes the subset of Docker client functionality needed for streaming events.
type dockerEventsClient interface {
	Events(ctx context.Context, options events.ListOptions) (<-chan events.Message, <-chan error)
}

// ContainerEventServiceImpl watches Docker events for managed containers and reports status changes.
type ContainerEventServiceImpl struct {
	logger        *logger.Logger
	dockerClient  dockerEventsClient
	statusService StatusService
	wsManager     wscontracts.Emitter

	mu       sync.Mutex
	cancel   context.CancelFunc
	running  bool
	stateMu  sync.Mutex
	lastSeen map[string]serviceState
}

type serviceState struct {
	status       pulseuptypes.ServiceStatus
	errorMessage string
}

// NewContainerEventService creates a new container event watcher.
func NewContainerEventService(baseLogger *logger.Logger, dockerClient dockerEventsClient, statusService StatusService) *ContainerEventServiceImpl {
	return &ContainerEventServiceImpl{
		logger:        baseLogger.With("service", "container_events"),
		dockerClient:  dockerClient,
		statusService: statusService,
		lastSeen:      make(map[string]serviceState),
	}
}

// SetWebSocketManager provides the websocket manager used for emitting alerts.
func (c *ContainerEventServiceImpl) SetWebSocketManager(wsManager wscontracts.Emitter) {
	c.wsManager = wsManager
}

// Start begins streaming Docker events for managed containers.
func (c *ContainerEventServiceImpl) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.running {
		return fmt.Errorf("container event service already running")
	}

	if c.dockerClient == nil {
		return fmt.Errorf("docker client not available")
	}

	runCtx, cancel := context.WithCancel(ctx)
	c.cancel = cancel
	c.running = true

	go c.run(runCtx)

	return nil
}

// Stop terminates the event stream.
func (c *ContainerEventServiceImpl) Stop(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.running {
		return nil
	}

	if c.cancel != nil {
		c.cancel()
	}

	c.running = false
	c.cancel = nil
	return nil
}

func (c *ContainerEventServiceImpl) run(ctx context.Context) {
	filterArgs := filters.NewArgs()
	filterArgs.Add("type", "container")
	filterArgs.Add("label", "pulseup.managed=true")

	options := events.ListOptions{Filters: filterArgs}
	backoff := time.Second

	for {
		if ctx.Err() != nil {
			return
		}

		msgCh, errCh := c.dockerClient.Events(ctx, options)
		if msgCh == nil || errCh == nil {
			c.logger.Warn("Docker event stream returned nil channels; retrying")
			if !c.sleepWithContext(ctx, backoff) {
				return
			}
			backoff = c.nextBackoff(backoff)
			continue
		}

		if err := c.consumeEvents(ctx, msgCh, errCh); err != nil {
			if errors.Is(err, context.Canceled) {
				return
			}
			if errors.Is(err, io.EOF) {
				c.logger.Debug("Docker event stream closed; reconnecting")
			} else {
				c.logger.Warn("Docker event stream error", "error", err)
			}
			if !c.sleepWithContext(ctx, backoff) {
				return
			}
			backoff = c.nextBackoff(backoff)
			continue
		}

		backoff = time.Second
	}
}

func (c *ContainerEventServiceImpl) consumeEvents(ctx context.Context, msgCh <-chan events.Message, errCh <-chan error) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case msg, ok := <-msgCh:
			if !ok {
				return io.EOF
			}
			c.handleEvent(ctx, msg)
		case err, ok := <-errCh:
			if !ok {
				return io.EOF
			}
			if err != nil {
				return err
			}
		}
	}
}

func (c *ContainerEventServiceImpl) handleEvent(ctx context.Context, msg events.Message) {
	attrs := msg.Actor.Attributes
	if attrs == nil {
		return
	}

	if attrs["pulseup.managed"] != "true" {
		return
	}

	serviceUID := attrs["pulseup.service_uid"]
	if serviceUID == "" {
		c.logger.Debug("Managed container event missing service UID", "action", msg.Action, "container", msg.Actor.ID)
		return
	}

	action := msg.Action
	timestamp := time.Unix(0, msg.TimeNano)
	if msg.TimeNano == 0 && msg.Time != 0 {
		timestamp = time.Unix(int64(msg.Time), 0)
	}

	c.logger.Debug("Received container lifecycle event",
		"service_uid", serviceUID,
		"action", action,
		"container_id", msg.Actor.ID,
	)

	switch action {
	case "start", "restart":
		c.updateServiceStatus(ctx, serviceUID, pulseuptypes.ServiceStatusRunning, "")
	case "die", "stop", "kill", "destroy", "oom":
		exitCode := attrs["exitCode"]
		errorMessage := ""
		if exitCode != "" && exitCode != "0" {
			errorMessage = fmt.Sprintf("container exited with code %s", exitCode)
		}
		c.updateServiceStatus(ctx, serviceUID, pulseuptypes.ServiceStatusStopped, errorMessage)
		c.emitContainerStopped(msg, serviceUID, timestamp, exitCode)
	case "health_status: healthy":
		c.updateServiceStatus(ctx, serviceUID, pulseuptypes.ServiceStatusRunning, "")
	case "health_status: unhealthy":
		c.updateServiceStatus(ctx, serviceUID, pulseuptypes.ServiceStatusFailed, "container reported unhealthy")
		c.emitContainerStopped(msg, serviceUID, timestamp, attrs["exitCode"])
	default:
		c.logger.Debug("Ignoring container action", "action", action)
	}
}

func (c *ContainerEventServiceImpl) updateServiceStatus(ctx context.Context, serviceUID string, status pulseuptypes.ServiceStatus, errorMessage string) {
	c.stateMu.Lock()
	state := c.lastSeen[serviceUID]
	if state.status == status && state.errorMessage == errorMessage {
		c.stateMu.Unlock()
		return
	}
	c.lastSeen[serviceUID] = serviceState{status: status, errorMessage: errorMessage}
	c.stateMu.Unlock()

	if err := c.statusService.UpdateServiceStatus(ctx, serviceUID, status, errorMessage); err != nil {
		c.logger.Error("Failed to update service status from container event",
			"service_uid", serviceUID,
			"status", status,
			"error", err,
		)
	}
}

func (c *ContainerEventServiceImpl) emitContainerStopped(msg events.Message, serviceUID string, ts time.Time, exitCode string) {
	if c.wsManager == nil {
		return
	}

	payload := map[string]interface{}{
		"service_uid":    serviceUID,
		"container_id":   msg.Actor.ID,
		"container_name": msg.Actor.Attributes["name"],
		"deployment_uid": msg.Actor.Attributes["pulseup.deployment_uid"],
		"action":         string(msg.Action),
		"timestamp":      ts.UTC().Format(time.RFC3339Nano),
	}
	if exitCode != "" {
		payload["exit_code"] = exitCode
	}

	if err := c.wsManager.Emit("container_stopped", payload); err != nil {
		c.logger.Error("Failed to emit container stopped event", "error", err)
	}
}

func (c *ContainerEventServiceImpl) sleepWithContext(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func (c *ContainerEventServiceImpl) nextBackoff(current time.Duration) time.Duration {
	if current >= 30*time.Second {
		return 30 * time.Second
	}
	next := current * 2
	if next > 30*time.Second {
		return 30 * time.Second
	}
	return next
}
