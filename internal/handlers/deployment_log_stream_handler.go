package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"outlap-agent-go/internal/shared/logpaths"
	"outlap-agent-go/pkg/logger"
	"outlap-agent-go/pkg/types"
)

const (
	defaultDeploymentLogFlushInterval = time.Second
	minDeploymentLogFlushInterval     = 200 * time.Millisecond
)

type deploymentLogStream struct {
	logger        *logger.Logger
	svcUID        string
	deplUID       string
	ws            WebSocketManager
	flushInterval time.Duration
	includeSteps  bool
	logTypes      []string
	offsets       map[string]int64
	seq           uint64
	stepsHash     string
	cancel        context.CancelFunc
	wg            sync.WaitGroup
}

type deploymentLogChunk struct {
	logType string
	start   int64
	end     int64
	data    string
}

func newDeploymentLogStream(log *logger.Logger, ws WebSocketManager, serviceUID, deploymentUID string, offsets map[string]int64, includeSteps bool, flushInterval time.Duration) *deploymentLogStream {
	if flushInterval <= 0 {
		flushInterval = defaultDeploymentLogFlushInterval
	} else if flushInterval < minDeploymentLogFlushInterval {
		flushInterval = minDeploymentLogFlushInterval
	}

	copiedOffsets := map[string]int64{}
	for k, v := range offsets {
		copiedOffsets[strings.ToLower(k)] = v
	}

	return &deploymentLogStream{
		logger:        log,
		svcUID:        serviceUID,
		deplUID:       deploymentUID,
		ws:            ws,
		flushInterval: flushInterval,
		includeSteps:  includeSteps,
		logTypes:      []string{"build", "deploy"},
		offsets:       copiedOffsets,
	}
}

func (s *deploymentLogStream) start() {
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	// Flush immediately once to send any pending deltas without waiting a full interval.
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()

		// Perform an initial flush so subscribers get the latest state without delay.
		s.flush(false)

		ticker := time.NewTicker(s.flushInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				s.flush(true)
				return
			case <-ticker.C:
				s.flush(false)
			}
		}
	}()
}

func (s *deploymentLogStream) stop() {
	if s.cancel != nil {
		s.cancel()
	}
	s.wg.Wait()
}

func (s *deploymentLogStream) flush(final bool) {
	chunks := s.collectLogChunks()
	steps, stepsChanged := s.collectSteps()

	if len(chunks) == 0 {
		if !stepsChanged && !final {
			return
		}
		// emit a heartbeat/final notification even without a chunk payload
		startOffset := int64(0)
		if off, ok := s.offsets["build"]; ok {
			startOffset = off
		}
		chunks = append(chunks, deploymentLogChunk{logType: "", start: startOffset, end: startOffset, data: ""})
	}

	timestamp := time.Now().UTC().Format(time.RFC3339Nano)

	for _, chunk := range chunks {
		payload := map[string]interface{}{
			"deployment_uid": s.deplUID,
			"service_uid":    s.svcUID,
			"timestamp":      timestamp,
			"sequence":       s.nextSequence(),
			"start_offset":   chunk.start,
			"end_offset":     chunk.end,
		}

		if chunk.logType != "" {
			payload["log_type"] = chunk.logType
		}
		if chunk.data != "" {
			payload["chunk"] = chunk.data
			payload["size"] = len(chunk.data)
		}
		if stepsChanged && len(steps) > 0 {
			payload["steps"] = steps
		}
		if final {
			payload["final"] = true
		}

		if err := s.ws.Emit("deployment_log_chunk", payload); err != nil {
			s.logger.Warn("failed to emit deployment log chunk", "error", err)
		}
	}
}

func (s *deploymentLogStream) nextSequence() uint64 {
	s.seq++
	return s.seq
}

func (s *deploymentLogStream) collectLogChunks() []deploymentLogChunk {
	chunks := make([]deploymentLogChunk, 0, len(s.logTypes))
	for _, logType := range s.logTypes {
		chunk, ok := s.readLogChunk(logType)
		if ok {
			chunks = append(chunks, chunk)
		}
	}
	return chunks
}

func (s *deploymentLogStream) readLogChunk(logType string) (deploymentLogChunk, bool) {
	path := logpaths.DeploymentLogPath(s.deplUID, logType)
	if path == "" {
		return deploymentLogChunk{}, false
	}

	file, err := os.Open(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			s.logger.Debug("failed to open deployment log file", "path", path, "error", err)
		}
		return deploymentLogChunk{}, false
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		s.logger.Debug("failed to stat deployment log file", "path", path, "error", err)
		return deploymentLogChunk{}, false
	}

	currentOffset := s.offsets[logType]
	if currentOffset < 0 {
		currentOffset = 0
	}

	if info.Size() < currentOffset {
		// File truncated; restart from beginning.
		currentOffset = 0
		s.offsets[logType] = 0
	}

	if info.Size() == currentOffset {
		return deploymentLogChunk{logType: logType, start: currentOffset, end: currentOffset, data: ""}, false
	}

	if _, err := file.Seek(currentOffset, io.SeekStart); err != nil {
		s.logger.Debug("failed to seek deployment log file", "path", path, "error", err)
		return deploymentLogChunk{}, false
	}

	data, err := io.ReadAll(file)
	if err != nil {
		s.logger.Debug("failed to read deployment log file", "path", path, "error", err)
		return deploymentLogChunk{}, false
	}

	start := currentOffset
	end := start + int64(len(data))
	s.offsets[logType] = end

	return deploymentLogChunk{logType: logType, start: start, end: end, data: string(data)}, len(data) > 0
}

func (s *deploymentLogStream) collectSteps() ([]map[string]interface{}, bool) {
	if !s.includeSteps {
		return nil, false
	}

	path := logpaths.DeploymentStepsPath(s.deplUID)
	if path == "" {
		return nil, false
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			s.logger.Debug("failed to read deployment steps file", "path", path, "error", err)
		}
		return nil, false
	}

	hashBytes := sha256.Sum256(data)
	hash := hex.EncodeToString(hashBytes[:])
	if hash == s.stepsHash {
		return nil, false
	}

	var steps []map[string]interface{}
	if err := json.Unmarshal(data, &steps); err != nil {
		s.logger.Debug("failed to decode deployment steps", "path", path, "error", err)
		return nil, false
	}

	s.stepsHash = hash
	return steps, true
}

// DeploymentLogStreamHandler manages deployment log streaming sessions for the agent.
type DeploymentLogStreamHandler struct {
	*BaseHandler
	mu      sync.Mutex
	streams map[string]*deploymentLogStream
}

// NewDeploymentLogStreamHandler constructs a new handler.
func NewDeploymentLogStreamHandler(logger *logger.Logger, services ServiceProvider) *DeploymentLogStreamHandler {
	return &DeploymentLogStreamHandler{
		BaseHandler: NewBaseHandler(logger.With("handler", "service.deploy.logs"), services),
		streams:     make(map[string]*deploymentLogStream),
	}
}

// Base exposes the embedded BaseHandler to satisfy the Controller interface.
func (h *DeploymentLogStreamHandler) Base() *BaseHandler {
	return h.BaseHandler
}

type deploymentLogStreamStartRequest struct {
	ServiceUID      string           `json:"service_uid"`
	DeploymentUID   string           `json:"deployment_uid"`
	Offsets         map[string]int64 `json:"offsets,omitempty"`
	IncludeSteps    bool             `json:"include_steps,omitempty"`
	FlushIntervalMS int              `json:"flush_interval_ms,omitempty"`
}

type deploymentLogStreamStopRequest struct {
	DeploymentUID string `json:"deployment_uid"`
}

// StreamStart starts a background stream that forwards deployment logs to the backend.
func (h *DeploymentLogStreamHandler) StreamStart(ctx context.Context, data json.RawMessage) (*types.CommandResponse, error) {
	var req deploymentLogStreamStartRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return &types.CommandResponse{Success: false, Error: "invalid request format"}, nil
	}

	if req.DeploymentUID == "" {
		return &types.CommandResponse{Success: false, Error: "deployment_uid is required"}, nil
	}
	if req.ServiceUID == "" {
		h.logger.Warn("deployment log stream requested without service_uid", "deployment_uid", req.DeploymentUID)
	}

	wsManager := h.services.GetWebSocketManager()
	if wsManager == nil {
		h.logger.Warn("websocket manager not available for deployment log streaming")
		return &types.CommandResponse{Success: false, Error: "websocket manager not available"}, nil
	}

	flushInterval := defaultDeploymentLogFlushInterval
	if req.FlushIntervalMS > 0 {
		flushInterval = time.Duration(req.FlushIntervalMS) * time.Millisecond
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	if existing, ok := h.streams[req.DeploymentUID]; ok {
		existing.stop()
		delete(h.streams, req.DeploymentUID)
	}

	offsets := req.Offsets
	if offsets == nil {
		offsets = map[string]int64{}
	}

	streamLogger := h.logger.With(
		"component", "deployment_log_stream",
		"deployment_uid", req.DeploymentUID,
		"service_uid", req.ServiceUID,
	)

	stream := newDeploymentLogStream(streamLogger, wsManager, req.ServiceUID, req.DeploymentUID, offsets, req.IncludeSteps, flushInterval)
	h.streams[req.DeploymentUID] = stream
	stream.start()

	return &types.CommandResponse{
		Success: true,
		Data: map[string]interface{}{
			"message":        "Deployment log streaming started",
			"deployment_uid": req.DeploymentUID,
		},
	}, nil
}

// StreamStop terminates an active deployment log stream.
func (h *DeploymentLogStreamHandler) StreamStop(ctx context.Context, data json.RawMessage) (*types.CommandResponse, error) {
	var req deploymentLogStreamStopRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return &types.CommandResponse{Success: false, Error: "invalid request format"}, nil
	}

	if req.DeploymentUID == "" {
		return &types.CommandResponse{Success: false, Error: "deployment_uid is required"}, nil
	}

	h.mu.Lock()
	stream, ok := h.streams[req.DeploymentUID]
	if ok {
		delete(h.streams, req.DeploymentUID)
	}
	h.mu.Unlock()

	if ok {
		stream.stop()
		return &types.CommandResponse{Success: true, Data: map[string]interface{}{"message": "stream stopped", "deployment_uid": req.DeploymentUID}}, nil
	}

	return &types.CommandResponse{Success: false, Error: "no active stream for deployment"}, nil
}
