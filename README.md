# Outlap Agent

The Outlap Agent is a high-performance, containerized agent for the Outlap platform. It provides real-time communication with Outlap servers to manage applications, databases, and infrastructure on your servers.

## Installation

### Automated Installation (Recommended)

The easiest way to install the Outlap Agent is using our installation script:

```bash
curl -fsSL https://get.outlap.dev/install.sh | sudo bash
```

The installer will:
- Download and verify the latest signed binary for your architecture
- Set up the agent as a systemd service
- Configure automatic updates
- Create the necessary directories and permissions

### Manual Installation

If you prefer to install manually:

1. Download the latest release for your architecture:
   - **Linux AMD64**: `outlap-agent_linux_amd64`
   - **Linux ARM64**: `outlap-agent_linux_arm64`

2. Verify the download (recommended):
   ```bash
   # Download the checksum and signature files
   # Verify the signature using the Outlap public key
   sha256sum -c outlap-agent_linux_amd64.sha256
   ```

3. Install the binary:
   ```bash
   sudo mv outlap-agent_linux_amd64 /usr/local/bin/outlap-agent
   sudo chmod +x /usr/local/bin/outlap-agent
   ```

4. Create the agent user and directories:
   ```bash
   sudo useradd -r -s /bin/false outlap
   sudo mkdir -p /etc/outlap-agent /opt/outlap /var/lib/outlap /var/log/outlap /run/outlap
   sudo chown outlap:outlap /opt/outlap /var/lib/outlap /var/log/outlap /run/outlap
   ```

5. Create the configuration file at `/etc/outlap-agent/config`:
   ```ini
   WEBSOCKET_URL=wss://ws.outlap.dev/ws/agent
   JOIN_TOKEN=your-join-token-from-outlap-dashboard
   LOG_LEVEL=INFO
   ```

6. Set up the systemd service (see systemd configuration below)

### Systemd Configuration

Create `/etc/systemd/system/outlap-agent.service`:

```ini
[Unit]
Description=Outlap Agent
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=simple
User=outlap
Group=outlap
EnvironmentFile=/etc/outlap-agent/config
WorkingDirectory=/opt/outlap
ExecStart=/usr/local/bin/outlap-agent
Restart=always
RestartSec=5
SupplementaryGroups=docker
UMask=0027
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/outlap /var/lib/outlap /var/log/outlap /run/outlap
StandardOutput=append:/var/log/outlap/agent.log
StandardError=append:/var/log/outlap/agent.log

[Install]
WantedBy=multi-user.target
```

Enable and start the service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable outlap-agent
sudo systemctl start outlap-agent
```

## Configuration

The agent is configured via environment variables in `/etc/outlap-agent/config`:

### Required Variables
- `WEBSOCKET_URL`: WebSocket server URL (default: `wss://ws.outlap.dev/ws/agent`)
- `JOIN_TOKEN`: One-time enrollment token obtained from the Outlap dashboard

### Optional Variables
- `LOG_LEVEL`: Logging level - DEBUG, INFO, WARN, ERROR (default: `INFO`)
- `RECONNECT_ENABLED`: Enable automatic reconnection (default: `true`)
- `RECONNECT_INTERVAL`: Initial reconnection delay in seconds (default: `5`)
- `RECONNECT_MAX_ATTEMPTS`: Maximum reconnection attempts, 0 for infinite (default: `0`)
- `RECONNECT_BACKOFF_MAX`: Maximum backoff delay in seconds (default: `60`)
- `OUTLAP_BACKUP_DIR`: Directory for database backups (default: `/var/lib/outlap/backups`)

## Requirements

- **Operating System**: Linux (amd64 or arm64)
- **Docker**: Required for container management features
- **Root Access**: Required for installation (the agent itself runs as an unprivileged user)
- **Network**: Outbound HTTPS/WSS access to Outlap servers

## Features

The Outlap Agent provides:

- **Application Deployment**: Deploy and manage containerized applications
- **Database Management**: Provision, backup, and restore MySQL, PostgreSQL, MariaDB, Redis, and MongoDB
- **System Monitoring**: Hardware information and system metrics
- **Automatic Updates**: Self-updating capability with signature verification
- **Secure Communication**: mTLS authentication with the Outlap platform

## Automatic Updates

The agent includes a built-in automatic update mechanism:

1. The Outlap platform sends update requests when new versions are available
2. The agent downloads and verifies the signed binary
3. A separate updater service (running as root) performs the atomic swap
4. The agent service automatically restarts with the new version

All updates are cryptographically signed and verified before installation.

## Troubleshooting

### Check agent status
```bash
sudo systemctl status outlap-agent
```

### View logs
```bash
sudo journalctl -u outlap-agent -f
# or
sudo tail -f /var/log/outlap/agent.log
```

### Test connectivity
```bash
# Ensure the agent can reach the Outlap servers
curl -I https://ws.outlap.dev
```

### Common Issues

**Agent not connecting:**
- Verify `WEBSOCKET_URL` is correct in `/etc/outlap-agent/config`
- Check firewall settings for outbound HTTPS/WSS connections
- Ensure JOIN_TOKEN is valid (tokens are one-time use during enrollment)

**Permission errors:**
- Verify the outlap user is in the docker group: `sudo usermod -aG docker outlap`
- Check directory permissions: `/opt/outlap`, `/var/lib/outlap`, `/var/log/outlap`

**Docker operations failing:**
- Ensure Docker is installed and running: `sudo systemctl status docker`
- Verify the outlap user has docker access: `sudo -u outlap docker ps`

## Security

The Outlap Agent follows security best practices:

- Runs as an unprivileged user (outlap)
- Uses systemd security features (NoNewPrivileges, ProtectSystem, etc.)
- Employs mTLS for authentication
- Verifies all update signatures before installation
- Minimal attack surface with focused capabilities

## Getting Your Join Token

1. Log in to your Outlap dashboard at https://outlap.dev
2. Navigate to Servers → Add Server
3. Copy the join token provided
4. Use it in your `/etc/outlap-agent/config` file

The join token is used once during initial enrollment to obtain mTLS certificates. After successful enrollment, the agent uses certificate-based authentication.

## Support

For issues, questions, or feature requests:
- Documentation: https://docs.outlap.dev
- Email: support@outlap.dev
- GitHub Issues: https://github.com/Outlap-dev/agent/issues

## License

MIT License - see LICENSE for details.
