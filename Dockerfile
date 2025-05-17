FROM ubuntu:22.04

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install Python, pip, curl, sudo, and full Docker Engine + dependencies
RUN apt-get update && apt-get install -y \
    python3.10 \
    python3-pip \
    curl \
    sudo \
    ca-certificates \
    gnupg \
    lsb-release \
    dmidecode \
    # Install Docker Engine requirements
    && mkdir -p /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null \
    && apt-get update \
    # Install Docker Engine, CLI, Containerd
    && apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements first to leverage Docker cache
COPY requirements.txt .
RUN pip3 install -r requirements.txt

# Copy the entrypoint script
COPY dind-entrypoint.sh /usr/local/bin/dind-entrypoint.sh
RUN chmod +x /usr/local/bin/dind-entrypoint.sh

# Copy the rest of the application
COPY . .

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/dind-entrypoint.sh"]

# Default command passed to the entrypoint
CMD ["python3", "-m", "debugpy", "--listen", "0.0.0.0:5679", "agent.py"]