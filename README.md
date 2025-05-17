# PulseUp Machine Agent

A machine agent for PulseUp that handles application deployment on servers. This agent connects to the main PulseUp server via WebSocket and manages deployments on the host machine.

## Setup

1. Copy the environment file:
```bash
cp .env.example .env
```

2. Edit the `.env` file with your configuration:
- `WEBSOCKET_URL`: WebSocket URL of the main PulseUp server
- `AGENT_ID`: Unique identifier for this agent

## Running with Docker

Start the agent:
```bash
docker-compose up --build
```

Run in background:
```bash
docker-compose up -d --build
```

Stop the agent:
```bash
docker-compose down
```

## Development

The agent will:
1. Connect to the specified WebSocket server
2. Send an initial identification message
3. Log all received messages
4. Automatically reconnect on connection loss

## Logs

Logs are output to stdout/stderr and can be viewed with:
```bash
docker-compose logs -f
```

## Building
```bash
pyinstaller agent.spec
```
