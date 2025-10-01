package bootstrap

import (
	"time"

	"pulseup-agent-go/internal/config"
	"pulseup-agent-go/internal/enrollment"
	"pulseup-agent-go/pkg/logger"
)

// NewEnroller constructs an enrollment.Enroller when join-token based enrollment is requested.
func NewEnroller(cfg *config.Config, apiURL string, baseLogger *logger.Logger, provider enrollment.SystemInfoProvider) *enrollment.Enroller {
	if cfg == nil || apiURL == "" || provider == nil {
		return nil
	}

	enrollConfig := enrollment.Config{
		APIURL:    apiURL,
		JoinToken: cfg.JoinToken,
		CertDir:   cfg.CertDir,
		Timeout:   30 * time.Second,
	}

	return enrollment.NewEnroller(enrollConfig, baseLogger, provider)
}
