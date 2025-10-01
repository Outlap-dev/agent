# WebSocket Authentication

The PulseUp Agent uses a message-based authentication system instead of HTTP headers for WebSocket connections.

## Authentication Flow

1. **Connection**: Agent connects to WebSocket server without authentication headers
2. **Auth Message**: Immediately after connection, agent sends authentication message
3. **Server Validation**: Server validates the token and responds accordingly

## Authentication Message Format

Upon successful WebSocket connection, the agent immediately sends:

```json
{
    "type": "auth",
    "token": "b22825085a06024d0d660109379f6c717df35cc2d4707942"
}
```

## Configuration

Set your agent token in the environment:

```bash
# .env file or environment variable
AGENT_TOKEN=b22825085a06024d0d660109379f6c717df35cc2d4707942
```

## Implementation Details

### Go Implementation

```go
// Send authentication message immediately after connection
func (m *Manager) sendAuthMessage() error {
    authMessage := map[string]interface{}{
        "type":  "auth",
        "token": m.config.AgentToken,
    }

    if err := m.conn.WriteJSON(authMessage); err != nil {
        return fmt.Errorf("failed to send auth message: %w", err)
    }

    return nil
}
```

### Connection Sequence

1. `websocket.Dial()` - Connect without headers
2. `sendAuthMessage()` - Send auth message
3. Start message handlers
4. Begin normal operation

## Migration from Headers

**Before (Header-based):**
```go
headers := http.Header{}
headers.Set("Authorization", "Bearer " + token)
conn, _, err := dialer.Dial(url, headers)
```

**After (Message-based):**
```go
conn, _, err := dialer.Dial(url, nil)
// Then immediately send auth message
authMessage := map[string]interface{}{
    "type": "auth",
    "token": token,
}
conn.WriteJSON(authMessage)
```

## Benefits

- **Flexibility**: Can handle complex authentication flows
- **Debugging**: Auth messages are visible in WebSocket logs
- **Standards**: More compatible with various WebSocket implementations
- **Security**: Token is not exposed in HTTP headers/logs

## Error Handling

If authentication fails:
- Connection is immediately closed
- Agent will attempt to reconnect
- Error is logged with appropriate context

## Testing

Use the provided test to verify authentication message format:

```bash
go test ./internal/websocket/... -v
```

Expected output shows the correct JSON format:
```
Authentication message format verified: {"token":"...","type":"auth"}
``` 