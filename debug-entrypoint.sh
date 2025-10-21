#!/bin/bash

# Check if Docker socket is mounted (indicating we should use host Docker)
ensure_caddy_permissions() {
    local caddy_root="/etc/pulseup-agent/caddy"
    local caddy_dirs=("$caddy_root" "$caddy_root/config" "$caddy_root/data" "$caddy_root/logs")
    local additional_dirs=("/var/lib/caddy" "/var/log/caddy")

    for dir in "${caddy_dirs[@]}" "${additional_dirs[@]}"; do
        if ! mkdir -p "$dir" 2>/dev/null; then
            echo "Warning: failed to create $dir"
        fi
    done

    # Set ownership so the pulseup agent process can manage domain state files
    if ! chown -R pulseup:pulseup "$caddy_root" /var/lib/caddy /var/log/caddy 2>/dev/null; then
        echo "Warning: failed to adjust ownership for Caddy directories"
    fi

    # Ensure group write permissions so agent updates can succeed even if directories already exist
    chmod -R g+rwX "$caddy_root" /var/lib/caddy /var/log/caddy 2>/dev/null || true
}

SOCKET_PATH=${DOCKER_SOCKET_PATH:-/var/run/docker.sock}
SOCKET_DIR=$(dirname "$SOCKET_PATH")

if [ -S "$SOCKET_PATH" ]; then
    echo "Docker socket detected at $SOCKET_PATH, using host Docker daemon"
    export DOCKER_HOST=${DOCKER_HOST:-unix://$SOCKET_PATH}
    if [[ "$SOCKET_DIR" == /run/user/* ]] && [ -z "$XDG_RUNTIME_DIR" ]; then
        export XDG_RUNTIME_DIR="$SOCKET_DIR"
        echo "Detected rootless Docker runtime; exporting XDG_RUNTIME_DIR=$XDG_RUNTIME_DIR"
    fi
    
    # Fix Docker socket permissions for the docker group
    if [ -S "$SOCKET_PATH" ]; then
        SOCK_GID=$(stat -c '%g' "$SOCKET_PATH")
        SOCK_GROUP_NAME=$(getent group "$SOCK_GID" | cut -d: -f1)
        if [ -z "$SOCK_GROUP_NAME" ]; then
            SOCK_GROUP_NAME="pulseup-docker-$SOCK_GID"
            groupadd -g "$SOCK_GID" "$SOCK_GROUP_NAME" 2>/dev/null || true
        fi
        if [ -n "$SOCK_GROUP_NAME" ]; then
            usermod -aG "$SOCK_GROUP_NAME" pulseup 2>/dev/null || true
            usermod -aG "$SOCK_GROUP_NAME" root 2>/dev/null || true
        fi
        if [ -n "$SOCK_GROUP_NAME" ]; then
            chgrp "$SOCK_GROUP_NAME" "$SOCKET_PATH" 2>/dev/null || echo "Note: Could not change group ownership (may already be correct)"
        fi
        chmod g+rw "$SOCKET_PATH" 2>/dev/null || echo "Note: Could not change permissions (may already be correct)" 
    fi
    
    # Test if Docker is accessible
    if ! docker info >/dev/null 2>&1; then
        DOCKER_INFO_OUTPUT=$(docker info 2>&1 || true)
        if echo "$DOCKER_INFO_OUTPUT" | grep -qi "permission denied"; then
            echo "Permission denied when accessing Docker socket as root. Retrying as pulseup user..."
            if sudo -E -H -u pulseup docker info >/dev/null 2>&1; then
                echo "Docker daemon accessible as pulseup user"
            else
                echo "Docker socket mounted but inaccessible – starting internal Docker daemon fallback"
                export DOCKERD_HOST="unix:///var/run/pulseup-dind.sock"
                export DOCKER_HOST="$DOCKERD_HOST"
                /usr/local/bin/dind-entrypoint.sh &
                while ! docker info >/dev/null 2>&1; do
                    echo "Waiting for internal Docker daemon..."
                    sleep 1
                done
                echo "Internal Docker daemon is ready"
            fi
        else
            echo "Warning: Docker socket mounted but Docker daemon not accessible"
            echo "$DOCKER_INFO_OUTPUT"
            echo "Continuing without Docker connectivity..."
        fi
    else
        echo "Docker daemon is ready"
    fi
else
    echo "No Docker socket detected at $SOCKET_PATH, starting Docker daemon in container"
    # Start the Docker daemon first
    /usr/local/bin/dind-entrypoint.sh &
    
    # Wait for Docker daemon to be ready
    while ! docker info >/dev/null 2>&1; do
        echo "Waiting for Docker daemon..."
        sleep 1
    done
    
    echo "Docker daemon is ready"
fi

# Ensure runtime directories (especially mounted volumes) have the right ownership
ensure_caddy_permissions

# Signal handler for graceful shutdown
shutdown() {
    echo "Received shutdown signal, stopping processes..."
    if [ -n "$AGENT_PID" ]; then
        kill $AGENT_PID 2>/dev/null || true
    fi
    exit 0
}

# Trap signals
trap shutdown SIGTERM SIGINT

# Check if debug mode is enabled
export HOME=/home/pulseup

if [ "$ENABLE_DEBUG" = "true" ]; then
    echo "Starting pulseup-agent with debugger on port 2346..."
    sudo -E -H -u pulseup \
        /app/dlv --listen=:2346 --headless=true --api-version=2 --accept-multiclient exec /app/pulseup-agent &
    AGENT_PID=$!
    echo "Debugger listening on :2346"
else
    echo "Starting pulseup-agent..."
    sudo -E -H -u pulseup /app/pulseup-agent &
    AGENT_PID=$!
fi

wait $AGENT_PID
