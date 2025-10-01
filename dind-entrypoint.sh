#!/bin/sh
set -e

# Start Docker daemon in the background
dockerd > /var/log/dockerd.log 2>&1 &

# Wait for Docker daemon to be ready
retries=10
while ! docker info > /dev/null 2>&1; do
    retries=$((retries - 1))
    if [ $retries -eq 0 ]; then
        echo "Docker daemon failed to start!"
        cat /var/log/dockerd.log # Print logs for debugging
        exit 1
    fi
    sleep 1
done

echo "Docker daemon is ready"

# Execute the command passed to the script (e.g., the Go agent)
exec "$@" 