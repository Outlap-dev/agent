#!/bin/bash

# Check if Docker socket is mounted (indicating we should use host Docker)
if [ -S /var/run/docker.sock ]; then
    echo "Docker socket detected, using host Docker daemon"
    
    # Fix Docker socket permissions for the docker group
    if [ -S /var/run/docker.sock ]; then
        echo "Setting Docker socket group ownership..."
        chgrp docker /var/run/docker.sock 2>/dev/null || echo "Note: Could not change group ownership (may already be correct)"
        chmod g+rw /var/run/docker.sock 2>/dev/null || echo "Note: Could not change permissions (may already be correct)" 
    fi
    
    # Test if Docker is accessible
    if ! docker info >/dev/null 2>&1; then
        echo "Warning: Docker socket mounted but Docker daemon not accessible"
        echo "This is normal on some systems - continuing..."
    else
        echo "Docker daemon is ready"
    fi
else
    echo "No Docker socket detected, starting Docker daemon in container"
    # Start the Docker daemon first
    /usr/local/bin/dind-entrypoint.sh &
    
    # Wait for Docker daemon to be ready
    while ! docker info >/dev/null 2>&1; do
        echo "Waiting for Docker daemon..."
        sleep 1
    done
    
    echo "Docker daemon is ready"
fi

# Signal handler for graceful shutdown
shutdown() {
    echo "Received shutdown signal, stopping processes..."
    if [ -n "$SUPERVISOR_PID" ]; then
        kill $SUPERVISOR_PID 2>/dev/null || true
    fi
    if [ -n "$WORKER_PID" ]; then
        kill $WORKER_PID 2>/dev/null || true
    fi
    exit 0
}

# Trap signals
trap shutdown SIGTERM SIGINT

# Check if debug mode is enabled
if [ "$ENABLE_DEBUG" = "true" ]; then
    echo "Starting two-process architecture with debugger..."
    echo "Starting supervisor with debugger on port 2347..."
    /app/dlv --listen=:2347 --headless=true --api-version=2 --accept-multiclient exec /app/pulseup-supervisor &
    SUPERVISOR_PID=$!
    
    # Wait for supervisor to initialize
    echo "Waiting for supervisor to initialize..."
    sleep 3
    
    echo "Starting worker with debugger on port 2346 (as pulseup-worker user)..."
    # Preserve environment variables when switching users
    # Ensure HOME is set to the target user's home so Docker/Nixpacks use correct config path
    export HOME=/home/pulseup-worker
    sudo -E -H -u pulseup-worker \
        /app/dlv --listen=:2346 --headless=true --api-version=2 --accept-multiclient exec /app/pulseup-worker &
    WORKER_PID=$!
    
    echo "Both processes started in debug mode"
    echo "Supervisor debugger: :2347"
    echo "Worker debugger: :2346"
else
    echo "Starting two-process architecture normally..."
    echo "Starting supervisor..."
    /app/pulseup-supervisor &
    SUPERVISOR_PID=$!
    
    # Wait for supervisor to initialize
    echo "Waiting for supervisor to initialize..."
    sleep 3
    
    echo "Starting worker (as pulseup-worker user)..."
    # Preserve environment variables when switching users
    # Ensure HOME is set so that tooling doesn't attempt to read /root/.docker
    export HOME=/home/pulseup-worker
    sudo -E -H -u pulseup-worker /app/pulseup-worker &
    WORKER_PID=$!
    
    echo "Both processes started"
fi

# Wait for both processes
wait $SUPERVISOR_PID $WORKER_PID 