#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

# Define variables
IMAGE_NAME="pulseup-agent-builder"
TARGET_PLATFORM="linux/amd64" # x86_64
OUTPUT_DIR="dist"
APP_NAME="pulseup-agent" # Assuming the executable name from agent.spec is this

# Ensure the output directory exists
mkdir -p ${OUTPUT_DIR}

echo "Building the ${TARGET_PLATFORM} builder image..."
docker-buildx build --platform "${TARGET_PLATFORM}" -t "${IMAGE_NAME}" -f Dockerfile . --load

echo "Running PyInstaller inside the container..."
# Run the builder container and execute PyInstaller
# Mount the project directory to /app in the container
# Mount the dist directory to /app/dist in the container
# Override the default DinD entrypoint to just run our command
docker run --rm \
    --platform "${TARGET_PLATFORM}" \
    --entrypoint /bin/sh \
    -v "$(pwd):/app" \
    -w /app \
    "${IMAGE_NAME}" \
    -c "pip install pyinstaller && pyinstaller --noconfirm --distpath=/app/${OUTPUT_DIR} --workpath=/app/build agent.spec"

# Optional: Set correct permissions if needed (depends on user running docker)
# sudo chown $(id -u):$(id -g) ${OUTPUT_DIR}/${APP_NAME}

echo "Build complete. Executable located in ${OUTPUT_DIR}/" 