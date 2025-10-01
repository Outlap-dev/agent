# Agent Logs Handler

This document describes the new `get_agent_logs` handler that was added to retrieve agent logs.

## Overview

The `get_agent_logs` handler allows retrieving logs from the PulseUp agent itself, following the same pattern as the existing `get_service_logs` and `get_deployment_logs` handlers.

## Usage

### WebSocket Command

```json
{
  "event": "command", 
  "data": {
    "command": "agent.logs.fetch",
    "data": {
      "lines": 100  // Optional: number of lines to retrieve (default: 100)
    }
  }
}
```

### Response

```json
{
  "event": "command_response",
  "data": {
    "success": true,
    "data": {
      "logs": [
        "{\"time\":\"2024-01-01T12:00:00Z\",\"level\":\"INFO\",\"msg\":\"Starting PulseUp Agent\"}",
        "{\"time\":\"2024-01-01T12:01:00Z\",\"level\":\"INFO\",\"msg\":\"Agent ready\"}"
      ]
    }
  }
}
```

## Implementation Details

### Log Sources

The agent logs handler attempts to retrieve logs from multiple sources in order:

1. **Agent log file**: `/var/log/pulseup/agent.log` (if exists)
2. **Docker container logs**: Via `docker logs` command for the current container
3. **System logs**: Via `journalctl` for pulseup-agent service

### Architecture

- **Service**: `AgentLogService` in `internal/services/agent_logs.go`
- **Handler**: `GetAgentLogsHandler` in `internal/handlers/get_agent_logs.go`  
- **Interface**: Added to `ServiceProvider` interface in `internal/handlers/base.go`
- **Registration**: Automatically registered in `internal/services/container.go`

### Error Handling

The service gracefully handles cases where log sources are not available:
- Missing log files
- Docker container not accessible  
- SystemD not available
- Permission issues

When all sources fail or return no logs, it returns an empty array or a placeholder entry.

## Testing

Run tests with:
```bash
# Test the service implementation
go test ./internal/services/agent_logs_test.go ./internal/services/agent_logs.go -v

# Test the handler
go test ./internal/handlers/get_agent_logs_test.go ./internal/handlers/get_agent_logs.go ./internal/handlers/base.go -v

# Demo the functionality  
go run demo/agent_logs_demo.go
```

## Files Added/Modified

### New Files
- `internal/services/agent_logs.go` - AgentLogService implementation
- `internal/services/agent_logs_test.go` - Service tests
- `internal/handlers/get_agent_logs.go` - Handler implementation  
- `internal/handlers/get_agent_logs_test.go` - Handler tests
- `internal/handlers/get_agent_logs_registration_test.go` - Registration tests
- `demo/agent_logs_demo.go` - Demo program

### Modified Files
- `internal/services/interfaces.go` - Added AgentLogService interface
- `internal/handlers/base.go` - Added GetAgentLogService to ServiceProvider
- `internal/services/container.go` - Service registration and initialization
- `internal/handlers/app_installation_test.go` - Updated mock to include new method

The implementation follows the existing patterns in the codebase and maintains consistency with other log handlers.