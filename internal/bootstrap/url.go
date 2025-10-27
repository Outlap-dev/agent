package bootstrap

import (
	"strings"

	"outlap-agent-go/internal/config"
)

// ConvertWebSocketToHTTP converts websocket endpoints into HTTP endpoints for REST calls.
func ConvertWebSocketToHTTP(wsURL string) string {
	if wsURL == "" {
		return ""
	}

	httpURL := strings.Replace(wsURL, "ws://", "http://", 1)
	httpURL = strings.Replace(httpURL, "wss://", "https://", 1)

	if idx := strings.Index(httpURL, "/ws/"); idx != -1 {
		return httpURL[:idx]
	}

	return httpURL
}

// APIBaseURL derives the API base URL from configuration, falling back to the websocket origin when unset.
func APIBaseURL(cfg *config.Config) string {
	if cfg == nil {
		return ""
	}

	trimmed := strings.TrimRight(strings.TrimSpace(cfg.APIBaseURL), "/")
	if trimmed != "" {
		return trimmed
	}

	return strings.TrimRight(ConvertWebSocketToHTTP(cfg.WebSocketURL), "/")
}
