# PulseUp Agent

A high-performance, containerized agent for the PulseUp platform, rewritten from Python to Go. Uses native WebSockets for real-time communication with PulseUp servers to manage applications, databases, and infrastructure.

## Architecture

The Go agent follows a clean architecture pattern with the following structure:

```
pulseup-agent/
├── cmd/
│   ├── supervisor/      # Privileged supervisor process (runs as root)
│   └── worker/          # Unprivileged worker process (handles WebSocket connection)
├── internal/
│   ├── config/          # Configuration management  
│   ├── services/        # Business logic services
│   ├── handlers/        # Command handlers
│   ├── websocket/       # Modular WebSocket client architecture
│   └── testws/          # Test WebSocket server
├── pkg/
│   ├── types/           # Shared types and structures
│   └── logger/          # Structured logging with slog
├── docs/                # Documentation
├── scripts/             # Build and deployment scripts
└── go.mod
```

## Key Improvements over Python Version

1. **Native WebSockets**: Uses Gorilla WebSocket instead of Socket.IO for better performance and simpler protocol
2. **Structured Logging**: Uses Go's structured logging with JSON output
3. **Type Safety**: Strong typing throughout the application
4. **Dependency Injection**: Clean service container pattern for managing dependencies
5. **Graceful Shutdown**: Proper context-based shutdown handling
6. **Interface-based Design**: All services implement interfaces for better testability

## Services

### Core Services
- **WebSocket Manager**: Handles WebSocket connections with automatic reconnection
- **Service Container**: Manages all services and their dependencies
- **Handler Registry**: Routes commands to appropriate handlers

### Business Services
- **Docker Service**: Container management operations
- **Git Service**: Repository cloning and management
- **Build Service**: Application building and deployment
- **System Service**: Hardware info and system metrics
- **Database Service**: Provisioning, backups, and restores for MySQL, PostgreSQL, MariaDB, Redis, and MongoDB
- **Caddy Service**: Reverse proxy and SSL management (planned)

## Configuration

The agent supports configuration via environment variables or config files:

- `.env` file (for local development)
- `/etc/pulseup-agent/config` (for production)

Required environment variables:
- `WEBSOCKET_URL`: WebSocket server URL (default: `ws://ws.pulseup.io/ws/agent`)
- `JOIN_TOKEN`: One-time enrollment token for obtaining mTLS certificates (only needed for initial enrollment)

Optional auto-reconnection settings:
- `RECONNECT_ENABLED`: Enable automatic reconnection (default: `true`)
- `RECONNECT_INTERVAL`: Initial reconnection delay in seconds (default: `5`)
- `RECONNECT_MAX_ATTEMPTS`: Maximum reconnection attempts, 0 for infinite (default: `0`)
- `RECONNECT_BACKOFF_MAX`: Maximum backoff delay in seconds (default: `60`)

Database backup configuration:
- `PULSEUP_BACKUP_DIR`: Override the default `/var/lib/pulseup/backups` directory where database backups (including MongoDB archives) are stored on the agent

## Building and Running

### Prerequisites
- Docker and Docker Compose
- Go 1.23 or later (for local development)
- Git (for repository operations)

### Quick Start

#### Using Docker Compose (Recommended)
```bash
# Start development environment (equivalent to old 'make dev')
docker-compose up --build

# Start with debugging (equivalent to old 'make dev-debug')
docker-compose -f docker-compose.debug.yml up --build

# Stop services
docker-compose down

# View logs
docker-compose logs -f pulseup-agent
```

#### Local Development
```bash
# Build binaries locally
go build -o pulseup-supervisor ./cmd/supervisor
go build -o pulseup-worker ./cmd/worker

# Run tests
./test.sh
```

#### Configuration
Create a `.env` file for local development:
```bash
# Example .env file
WEBSOCKET_URL=ws://your-server.com/ws/agent_v2
JOIN_TOKEN=your-join-token
LOG_LEVEL=DEBUG
CADDY_HTTP_PORT=8080
CADDY_HTTPS_PORT=8443
```

#### Environment Variables
- `WEBSOCKET_URL`: WebSocket server URL (default: `ws://host.docker.internal:3000/ws/agent_v2`)
- `JOIN_TOKEN`: One-time enrollment token (default: `test-token`)
- `LOG_LEVEL`: Debug level (default: `DEBUG`)
- `CADDY_HTTP_PORT`: HTTP port for Caddy (default: `8080`)
- `CADDY_HTTPS_PORT`: HTTPS port for Caddy (default: `8443`)

## Development

### Adding New Handlers

1. Create a new handler in `internal/handlers/`:

```go
package handlers

import (
    "context"
    "encoding/json"
    "pulseup-agent-go/pkg/types"
)

type MyHandler struct {
    *BaseHandler
}

func NewMyHandler(logger *logger.Logger, services ServiceProvider) *MyHandler {
    return &MyHandler{
        BaseHandler: NewBaseHandler(logger.With("handler", "my_handler"), services),
    }
}

func (h *MyHandler) GetCommand() string {
    return "my_command"
}

func (h *MyHandler) Handle(ctx context.Context, data json.RawMessage) (*types.CommandResponse, error) {
    // Implementation here
    return &types.CommandResponse{
        Success: true,
        Data:    "result",
    }, nil
}
```

2. Register the handler in `internal/services/container.go`:

```go
func (c *ServiceContainer) registerHandlers() error {
    // ... existing handlers ...
    c.handlerRegistry.Register(handlers.NewMyHandler(c.logger, serviceProvider))
    return nil
}
```

### Adding New Services

1. Define the interface in `internal/services/interfaces.go`
2. Create the implementation in `internal/services/my_service.go`
3. Add it to the service container in `internal/services/container.go`
4. Update the service provider if handlers need access to it

## WebSocket Protocol

The agent uses a simple JSON-based protocol over WebSockets:

### Authentication
Upon receiving an `auth_challenge`, the agent responds with an mTLS proof that includes its certificate and a signature generated from the challenge nonce:
```json
{
    "type": "auth_proof",
    "data": {
        "method": "mtls",
        "certificate": "-----BEGIN CERTIFICATE-----...",
        "signature": "base64-signature",
        "nonce": "challenge-nonce",
        "version": "v1.0.0"
    }
}
```

### Incoming Messages
```json
{
    "event": "command",
    "data": {
        "command": "agent.hardware.info",
        "data": {}
    }
}
```

### Outgoing Responses
```json
{
    "event": "command_response",
    "data": {
        "success": true,
        "data": { ... },
        "error": ""
    }
}
```

## Logging

The agent uses structured JSON logging:

```json
{
    "time": "2024-01-01T12:00:00Z",
    "level": "INFO",
    "msg": "Starting PulseUp Agent",
    "component": "main"
}
```

Log levels: DEBUG, INFO, WARN, ERROR

## Deployment

### Systemd Services
The production install runs as two systemd units: a privileged supervisor and an unprivileged worker. The installer in this repository writes both unit files automatically, but if you need to create them manually you can use the following templates.

`/etc/systemd/system/pulseup-supervisor.service`

```ini
[Unit]
Description=PulseUp Supervisor
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
EnvironmentFile=/etc/pulseup-agent/config
ExecStart=/usr/local/bin/pulseup-supervisor
Restart=always
RestartSec=5
RuntimeDirectory=pulseup
RuntimeDirectoryMode=0770
StandardOutput=append:/var/log/pulseup/supervisor.log
StandardError=append:/var/log/pulseup/supervisor.log

[Install]
WantedBy=multi-user.target
```

`/etc/systemd/system/pulseup-worker.service`

```ini
[Unit]
Description=PulseUp Worker
After=pulseup-supervisor.service
Requires=pulseup-supervisor.service

[Service]
Type=simple
User=pulseup-worker
Group=pulseup
EnvironmentFile=/etc/pulseup-agent/config
WorkingDirectory=/opt/pulseup
ExecStart=/usr/local/bin/pulseup-worker
Restart=always
RestartSec=5
SupplementaryGroups=docker
UMask=0027
StandardOutput=append:/var/log/pulseup/worker.log
StandardError=append:/var/log/pulseup/worker.log

[Install]
WantedBy=multi-user.target
```

### Docker
For development the provided `docker-compose.yml` spins up the supervisor and worker processes inside a single container. Refer to that file if you prefer a containerised workflow.

## Testing

The project includes comprehensive test coverage:

```bash
# Run all tests
./test.sh

# Run tests with coverage
./test.sh -c

# Run tests with verbose output
./test.sh -v

# Run tests with race detector
./test.sh -r

# Run specific test packages
./test.sh -p ./internal/handlers
./test.sh -p ./internal/services
```

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup
1. Clone the repository
2. Install Docker and Docker Compose
3. Copy `.env.debug.example` to `.env` and configure
4. Run `docker-compose up --build` to start development environment
5. Run `./test.sh` to verify setup

### Code Style
- Follow standard Go conventions
- Use structured logging with the provided logger
- Add tests for new functionality  
- Ensure all tests pass before submitting PRs

## License

MIT License - see [LICENSE](LICENSE) for details.
