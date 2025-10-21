FROM golang:1.23-alpine AS builder

# Install git for go modules
RUN apk add --no-cache git

# Set working directory
WORKDIR /src

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY cmd/ ./cmd/
COPY internal/ ./internal/
COPY pkg/ ./pkg/

# Build arguments for version info
ARG VERSION
ARG BUILD_DATE
ARG GIT_COMMIT=unknown
ARG ENABLE_DEBUG=false

# Install delve for debugging if needed
RUN if [ "$ENABLE_DEBUG" = "true" ]; then \
    go install github.com/go-delve/delve/cmd/dlv@latest; \
    else \
    touch /go/bin/dlv; \
    fi

# Build agent application for Linux
RUN if [ "$ENABLE_DEBUG" = "true" ]; then \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -gcflags="all=-N -l" \
    -ldflags "-X pulseup-agent-go/internal/config.Version=${VERSION} \
    -X pulseup-agent-go/internal/config.BuildDate=${BUILD_DATE} \
    -X pulseup-agent-go/internal/config.GitCommit=${GIT_COMMIT}" \
    -o pulseup-agent ./cmd/agent; \
    else \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags "-X pulseup-agent-go/internal/config.Version=${VERSION} \
    -X pulseup-agent-go/internal/config.BuildDate=${BUILD_DATE} \
    -X pulseup-agent-go/internal/config.GitCommit=${GIT_COMMIT}" \
    -o pulseup-agent ./cmd/agent; \
    fi

# Production stage
FROM ubuntu:22.04

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies and Docker Engine
RUN apt-get update && apt-get install -y \
    curl \
    sudo \
    ca-certificates \
    gnupg \
    lsb-release \
    dmidecode \
    git \
    # Install Docker Engine requirements
    && mkdir -p /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null \
    && apt-get update \
    # Install Docker Engine, CLI, Containerd
    && apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin \
    && rm -rf /var/lib/apt/lists/*

# Install Nixpacks (for compatibility with Python agent functionality)
RUN curl -sSL https://nixpacks.com/install.sh | bash

# Create a non-root user for the agent process
RUN groupadd --system pulseup && \
    useradd --create-home --shell /bin/bash --uid 1000 --gid pulseup pulseup

# Add pulseup user to docker group for container operations
RUN usermod -aG docker pulseup

# Create Docker config directories and set permissions
RUN mkdir -p /root/.docker /home/pulseup/.docker \
    && echo '{}' > /root/.docker/config.json \
    && echo '{}' > /home/pulseup/.docker/config.json \
    && chmod 644 /root/.docker/config.json /home/pulseup/.docker/config.json \
    && chown -R pulseup:pulseup /home/pulseup/.docker

# Ensure processes default to the pulseup user home when switching user
ENV HOME=/home/pulseup

# Create app directory and runtime directories
WORKDIR /app
RUN mkdir -p /var/run/pulseup && chown root:pulseup /var/run/pulseup && chmod 770 /var/run/pulseup
RUN mkdir -p /opt/pulseup && chown -R pulseup:pulseup /opt/pulseup && chmod 750 /opt/pulseup
RUN mkdir -p /var/lib/pulseup && chown -R pulseup:pulseup /var/lib/pulseup && chmod 770 /var/lib/pulseup

# Create log directories with proper permissions
RUN mkdir -p /var/log/pulseup/deployments && chown -R pulseup:pulseup /var/log/pulseup && chmod -R 750 /var/log/pulseup

# Set up Caddy directories with proper ownership
RUN mkdir -p /etc/caddy /etc/pulseup-agent/caddy /var/lib/caddy && \
    chown -R pulseup:pulseup /etc/pulseup-agent/caddy /var/lib/caddy

# Copy the entrypoint scripts
COPY dind-entrypoint.sh /usr/local/bin/dind-entrypoint.sh
COPY debug-entrypoint.sh /usr/local/bin/debug-entrypoint.sh
RUN chmod +x /usr/local/bin/dind-entrypoint.sh
RUN chmod +x /usr/local/bin/debug-entrypoint.sh

# Build argument to determine if this is a debug build
ARG ENABLE_DEBUG=false

# Copy the compiled binary from builder stage
COPY --from=builder /src/pulseup-agent /app/pulseup-agent
RUN chmod +x /app/pulseup-agent

# Ensure proper permissions for runtime directory access
RUN chown -R root:pulseup /var/run/pulseup && chmod 775 /var/run/pulseup

# Copy delve for debug builds (will fail silently if not present)
COPY --from=builder /go/bin/dlv /app/dlv
RUN chmod +x /app/dlv 2>/dev/null || true

# Set the entrypoint to our debug-aware script
ENTRYPOINT ["/usr/local/bin/debug-entrypoint.sh"] 
