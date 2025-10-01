# Docker Setup and Usage

This document explains how to build and run the PulseUp Agent using Docker, providing a consistent Linux environment regardless of your host OS.

## Overview

The Docker setup provides:
- **Multi-stage build**: Builds the Go application for Linux inside the container
- **Docker-in-Docker (DinD)**: Allows the agent to manage Docker containers
- **Test environment**: Isolated environment for testing deployments
- **Production ready**: Optimized for production deployments

## Quick Start

### Build and Run (Test Environment)

```bash
# Build the Docker image
make docker-build-enhanced

# Run with docker-compose (recommended for testing)
make docker-compose-up

# Or run directly
make docker-run
```

### Production Deployment

```bash
# Build for production
make docker-build-prod

# Run production environment
make docker-compose-prod
```

## Build Options

### Enhanced Docker Build

The enhanced build script (`scripts/docker-build.sh`) provides several options:

```bash
# Basic build
./scripts/docker-build.sh

# Production build
./scripts/docker-build.sh --prod

# Build with custom tag
./scripts/docker-build.sh --tag v1.2.3

# Build without cache
./scripts/docker-build.sh --no-cache

# Build and push to registry
./scripts/docker-build.sh --push
```

### Build Arguments

The Dockerfile accepts the following build arguments:

- `VERSION`: Application version (default: 1.0.0)
- `BUILD_DATE`: Build timestamp (auto-generated)
- `GIT_COMMIT`: Git commit hash (auto-detected)

Example:
```bash
docker build \
  --build-arg VERSION=1.2.3 \
  --build-arg BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ") \
  --build-arg GIT_COMMIT=$(git rev-parse --short HEAD) \
  -t pulseup-agent-go:1.2.3 .
```

## Environment Variables

### Required Variables

- `WEBSOCKET_URL`: WebSocket endpoint for the agent
- `JOIN_TOKEN`: Authentication token

### Optional Variables

- `LOG_LEVEL`: Logging level (DEBUG, INFO, WARN, ERROR)
- `ENVIRONMENT`: Environment type (development, production)

### Example Configuration

```bash
# Test environment
export WEBSOCKET_URL=ws://localhost:3000/ws/agent
export JOIN_TOKEN=test-token
export LOG_LEVEL=DEBUG

# Production environment
export WEBSOCKET_URL=wss://your-server.com/ws/agent
export JOIN_TOKEN=your-production-token
export LOG_LEVEL=INFO
```

## Docker Compose Configurations

### Development/Test Environment (`docker-compose.yml`)

- Mounts source code for development
- Uses Docker volumes for persistence
- Includes debugging ports
- Isolated from host Docker

### Production Environment (`docker-compose.prod.yml`)

- Mounts host Docker socket for production deployments
- Includes health checks
- Resource limits
- Restart policies

## Testing

### Automated Testing

Run the comprehensive Docker test suite:

```bash
make test-docker-build
```

This test suite validates:
1. Docker image builds successfully
2. Container starts properly
3. Docker-in-Docker functionality works
4. Agent binary is executable
5. Resource usage is reasonable

### Manual Testing

```bash
# Build test image
./scripts/docker-build.sh --tag test

# Run interactive container
docker run --rm -it --privileged \
  -e WEBSOCKET_URL=ws://localhost:3000/ws/agent \
  -e JOIN_TOKEN=test-token \
  pulseup-agent-go:test

# Test Docker functionality inside container
docker exec -it <container-id> docker info
docker exec -it <container-id> docker run hello-world
```

## Troubleshooting

### Common Issues

#### 1. Docker Build Fails

```bash
# Clean build without cache
./scripts/docker-build.sh --no-cache

# Check Docker daemon is running
docker info
```

#### 2. Container Won't Start

```bash
# Check container logs
docker logs <container-name>

# Run with debug output
docker run --rm -it --privileged \
  -e LOG_LEVEL=DEBUG \
  pulseup-agent-go:latest
```

#### 3. Docker-in-Docker Issues

```bash
# Ensure privileged mode is enabled
docker run --privileged ...

# Check if Docker daemon started inside container
docker exec <container-id> ps aux | grep dockerd
```

#### 4. Permission Issues

```bash
# Ensure scripts are executable
chmod +x scripts/*.sh

# Check file permissions in container
docker exec <container-id> ls -la /app/
```

### Debugging

#### Enable Debug Logging

```bash
docker run --rm -it --privileged \
  -e LOG_LEVEL=DEBUG \
  -e WEBSOCKET_URL=ws://localhost:3000/ws/agent \
  -e JOIN_TOKEN=test-token \
  pulseup-agent-go:latest
```

#### Access Container Shell

```bash
# Get shell access
docker exec -it <container-name> /bin/bash

# Or run with shell override
docker run --rm -it --privileged \
  pulseup-agent-go:latest /bin/bash
```

## Performance Considerations

### Image Size Optimization

The multi-stage build keeps the final image size minimal:
- Builder stage: ~1GB (includes Go toolchain)
- Final image: ~200MB (only runtime dependencies)

### Resource Limits

Production configuration includes resource limits:
- Memory: 512MB limit, 256MB reservation
- CPU: 0.5 cores limit, 0.25 cores reservation

### Build Cache

Docker layer caching is optimized:
- Dependencies are cached separately from source code
- Only rebuilds when dependencies change

## Security

### Privileged Mode

The container runs in privileged mode for Docker-in-Docker functionality. In production:
- Use dedicated Docker hosts
- Implement proper network isolation
- Monitor container activities

### Secrets Management

Never include secrets in the Docker image:
- Use environment variables
- Mount secret files at runtime
- Use Docker secrets in Swarm mode

## Integration

### CI/CD Pipeline

Example GitHub Actions workflow:

```yaml
- name: Build Docker Image
  run: |
    ./scripts/docker-build.sh --tag ${{ github.sha }}
    
- name: Test Docker Image
  run: |
    make test-docker-build
    
- name: Push to Registry
  run: |
    ./scripts/docker-build.sh --tag ${{ github.sha }} --push
```

### Kubernetes Deployment

The container can be deployed to Kubernetes with proper security contexts and resource limits.

## Makefile Targets

| Target | Description |
|--------|-------------|
| `docker-build` | Simple Docker build |
| `docker-build-enhanced` | Enhanced build with arguments |
| `docker-build-prod` | Production build |
| `docker-run` | Run container directly |
| `docker-compose-up` | Start test environment |
| `docker-compose-down` | Stop test environment |
| `docker-compose-prod` | Start production environment |
| `docker-compose-prod-down` | Stop production environment |
| `test-docker-build` | Run comprehensive Docker tests | 