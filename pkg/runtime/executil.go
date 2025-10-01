package runtime

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
)

const (
	// MaxBufferSize is the maximum size for buffered output (60KB to prevent context overflow)
	MaxBufferSize = 60 * 1024
)

// ExecResult holds the result of a command execution
type ExecResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Error    error
}

// StreamHandler is called for each line of output
type StreamHandler func(line string, isStderr bool)

// ExecOptions configures command execution
type ExecOptions struct {
	// WorkingDir sets the working directory for the command
	WorkingDir string

	// Env sets additional environment variables (KEY=VALUE format)
	Env []string

	// StreamOutput enables streaming output to handlers
	StreamOutput bool

	// StreamHandler is called for each line when StreamOutput is true
	StreamHandler StreamHandler

	// RedactArgs redacts sensitive command arguments in logs
	RedactArgs []string

	// MaxOutputSize limits the captured output size (0 = use default MaxBufferSize)
	MaxOutputSize int
}

// Executor provides safe command execution with streaming support
type Executor struct {
	// Sensitive patterns to redact from logs
	redactPatterns []string
}

// NewExecutor creates a new command executor
func NewExecutor() *Executor {
	return &Executor{
		redactPatterns: []string{},
	}
}

// AddRedactPattern adds a pattern to redact from logs
func (e *Executor) AddRedactPattern(pattern string) {
	e.redactPatterns = append(e.redactPatterns, pattern)
}

// Execute runs a command and returns the result
func (e *Executor) Execute(ctx context.Context, name string, args []string, opts *ExecOptions) *ExecResult {
	if opts == nil {
		opts = &ExecOptions{}
	}

	cmd := exec.CommandContext(ctx, name, args...)

	if opts.WorkingDir != "" {
		cmd.Dir = opts.WorkingDir
	}

	if len(opts.Env) > 0 {
		cmd.Env = append(cmd.Env, opts.Env...)
	}

	maxSize := opts.MaxOutputSize
	if maxSize == 0 {
		maxSize = MaxBufferSize
	}

	// Handle streaming output
	if opts.StreamOutput && opts.StreamHandler != nil {
		return e.executeWithStreaming(cmd, opts, maxSize)
	}

	// Handle buffered output
	return e.executeBuffered(cmd, maxSize)
}

// executeBuffered runs a command with bounded output buffering
func (e *Executor) executeBuffered(cmd *exec.Cmd, maxSize int) *ExecResult {
	var stdoutBuf, stderrBuf boundedBuffer
	stdoutBuf.limit = maxSize
	stderrBuf.limit = maxSize

	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	err := cmd.Run()

	result := &ExecResult{
		Stdout: stdoutBuf.String(),
		Stderr: stderrBuf.String(),
		Error:  err,
	}

	if exitErr, ok := err.(*exec.ExitError); ok {
		result.ExitCode = exitErr.ExitCode()
	}

	return result
}

// executeWithStreaming runs a command with real-time output streaming
func (e *Executor) executeWithStreaming(cmd *exec.Cmd, opts *ExecOptions, maxSize int) *ExecResult {
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return &ExecResult{
			Error: fmt.Errorf("failed to create stdout pipe: %w", err),
		}
	}

	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return &ExecResult{
			Error: fmt.Errorf("failed to create stderr pipe: %w", err),
		}
	}

	if err := cmd.Start(); err != nil {
		return &ExecResult{
			Error: fmt.Errorf("failed to start command: %w", err),
		}
	}

	var wg sync.WaitGroup
	var stdoutBuf, stderrBuf boundedBuffer
	stdoutBuf.limit = maxSize
	stderrBuf.limit = maxSize

	// Stream stdout
	wg.Add(1)
	go func() {
		defer wg.Done()
		e.streamPipe(stdoutPipe, &stdoutBuf, opts.StreamHandler, false)
	}()

	// Stream stderr
	wg.Add(1)
	go func() {
		defer wg.Done()
		e.streamPipe(stderrPipe, &stderrBuf, opts.StreamHandler, true)
	}()

	wg.Wait()

	err = cmd.Wait()

	result := &ExecResult{
		Stdout: stdoutBuf.String(),
		Stderr: stderrBuf.String(),
		Error:  err,
	}

	if exitErr, ok := err.(*exec.ExitError); ok {
		result.ExitCode = exitErr.ExitCode()
	}

	return result
}

// streamPipe reads from a pipe, calls the handler, and stores in a bounded buffer
func (e *Executor) streamPipe(pipe io.Reader, buf *boundedBuffer, handler StreamHandler, isStderr bool) {
	scanner := bufio.NewScanner(pipe)

	// Set a reasonable buffer size for scanner
	scanBuf := make([]byte, 0, 64*1024)
	scanner.Buffer(scanBuf, 1024*1024) // Max 1MB per line

	for scanner.Scan() {
		line := scanner.Text()

		// Call handler if provided
		if handler != nil {
			handler(line, isStderr)
		}

		// Store in bounded buffer
		buf.WriteLine(line)
	}
}

// RedactCommand redacts sensitive arguments from a command string
func (e *Executor) RedactCommand(name string, args []string, redactArgs []string) string {
	cmdParts := append([]string{name}, args...)

	for i, arg := range cmdParts {
		for _, redact := range redactArgs {
			if strings.Contains(arg, redact) {
				cmdParts[i] = "[REDACTED]"
				break
			}
		}

		// Also redact based on registered patterns
		for _, pattern := range e.redactPatterns {
			if strings.Contains(arg, pattern) {
				cmdParts[i] = "[REDACTED]"
				break
			}
		}
	}

	return strings.Join(cmdParts, " ")
}

// boundedBuffer is a buffer that limits its size to prevent memory issues
type boundedBuffer struct {
	buf   bytes.Buffer
	limit int
	size  int
	mu    sync.Mutex
}

func (b *boundedBuffer) Write(p []byte) (n int, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.size >= b.limit {
		return len(p), nil // Silently drop if over limit
	}

	remaining := b.limit - b.size
	toWrite := p
	if len(p) > remaining {
		toWrite = p[:remaining]
	}

	n, err = b.buf.Write(toWrite)
	b.size += n
	return len(p), err // Return full length to satisfy io.Writer
}

func (b *boundedBuffer) WriteLine(line string) {
	b.Write([]byte(line + "\n"))
}

func (b *boundedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// QuickExec is a convenience function for simple command execution
func QuickExec(ctx context.Context, name string, args ...string) *ExecResult {
	executor := NewExecutor()
	return executor.Execute(ctx, name, args, nil)
}

// QuickExecOutput runs a command and returns just the stdout
func QuickExecOutput(ctx context.Context, name string, args ...string) (string, error) {
	result := QuickExec(ctx, name, args...)
	if result.Error != nil {
		return "", result.Error
	}
	return strings.TrimSpace(result.Stdout), nil
}
