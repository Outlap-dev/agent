package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"outlap-agent-go/pkg/logger"
	"outlap-agent-go/pkg/types"
)

// DomainHandler handles domain management commands exactly like the Python version
type DomainHandler struct {
	*BaseHandler
}

// DomainInfo represents domain metadata returned in responses.
type DomainInfo struct {
	Domain             string    `json:"domain"`
	ServiceUID         string    `json:"service_uid"`
	UpstreamContainer  string    `json:"upstream_container"`
	Port               int       `json:"port"`
	Protocol           string    `json:"protocol"`
	ForceHTTPS         bool      `json:"force_https"`
	RedirectWWW        string    `json:"redirect_www"`
	ManagedCertificate bool      `json:"managed_certificate"`
	CertificateEmail   string    `json:"certificate_email"`
	SSL                bool      `json:"ssl"`
	SSLStatus          string    `json:"ssl_status"`
	LastApplied        time.Time `json:"last_applied"`
}

type domainRequest struct {
	Action             string `json:"action"`
	Domain             string `json:"domain"`
	ServiceUID         string `json:"service_uid"`
	Port               *int   `json:"port"`
	Email              string `json:"email"`
	SSL                *bool  `json:"ssl"`
	ForceHTTPS         *bool  `json:"force_https"`
	RedirectWWW        string `json:"redirect_www"`
	ManagedCertificate *bool  `json:"managed_certificate"`
	Protocol           string `json:"protocol"`
}

// NewDomainHandler creates a new domain handler
func NewDomainHandler(logger *logger.Logger, services ServiceProvider) *DomainHandler {
	return &DomainHandler{
		BaseHandler: NewBaseHandler(logger.With("handler", "domain_handler"), services),
	}
}

// Base returns the underlying BaseHandler for routing helpers.
func (h *DomainHandler) Base() *BaseHandler {
	return h.BaseHandler
}

// Manage processes domain management commands exactly like the Python version
func (h *DomainHandler) Manage(ctx context.Context, data json.RawMessage) (*types.CommandResponse, error) {
	var request domainRequest
	if err := json.Unmarshal(data, &request); err != nil {
		return h.failureResponse(fmt.Sprintf("invalid request payload: %v", err)), nil
	}

	action := strings.TrimSpace(strings.ToLower(request.Action))
	if action == "" {
		return h.failureResponse("action is required (add, remove, update, status)"), nil
	}

	if strings.TrimSpace(request.ServiceUID) == "" {
		return h.failureResponse("service_uid is required"), nil
	}

	switch action {
	case "add_domain", "add", "configure_domain", "upsert":
		return h.handleUpsertDomain(ctx, request)
	case "update_domain", "update":
		return h.handleUpsertDomain(ctx, request)
	case "remove_domain", "remove":
		return h.handleRemoveDomain(ctx, request)
	case "status", "domain_status":
		return h.handleDomainStatus(ctx, request)
	default:
		return h.failureResponse(fmt.Sprintf("invalid action: %s (supported: add, remove, update, status)", request.Action)), nil
	}
}

func (h *DomainHandler) handleUpsertDomain(ctx context.Context, request domainRequest) (*types.CommandResponse, error) {
	domain := strings.TrimSpace(request.Domain)
	if domain == "" {
		return h.failureResponse("domain is required"), nil
	}

	if !h.isValidDomain(domain) {
		return h.failureResponse(fmt.Sprintf("invalid domain format: %s", domain)), nil
	}

	serviceUID := strings.TrimSpace(request.ServiceUID)
	if serviceUID == "" {
		return h.failureResponse("service_uid is required"), nil
	}

	if request.Port == nil {
		return h.failureResponse("port is required"), nil
	}

	protocol := strings.TrimSpace(request.Protocol)
	if protocol == "" {
		protocol = "http"
	}

	managedCertificate := true
	if request.ManagedCertificate != nil {
		managedCertificate = *request.ManagedCertificate
	} else if request.SSL != nil {
		managedCertificate = *request.SSL
	}

	forceHTTPS := managedCertificate
	if request.ForceHTTPS != nil {
		forceHTTPS = *request.ForceHTTPS
	}

	certificateEmail := strings.TrimSpace(request.Email)

	caddyService := h.GetServices().GetCaddyService()
	if caddyService == nil {
		return h.failureResponse("Caddy service not available"), nil
	}

	if err := h.ensureCaddyInstalled(ctx, caddyService); err != nil {
		h.GetLogger().Error("Failed to ensure Caddy is installed", "error", err)
		return h.failureResponse(fmt.Sprintf("Failed to install Caddy: %v", err)), nil
	}

	domainService := h.GetServices().GetDomainService()
	if domainService == nil {
		return h.failureResponse("Domain service not available"), nil
	}

	payload := types.DomainProvisionRequest{
		Domain:             domain,
		ServiceUID:         serviceUID,
		TargetPort:         *request.Port,
		TargetProtocol:     protocol,
		ForceHTTPS:         forceHTTPS,
		RedirectWWW:        request.RedirectWWW,
		ManagedCertificate: managedCertificate,
		CertificateEmail:   certificateEmail,
	}

	info, err := domainService.UpsertDomain(ctx, payload)
	if err != nil {
		h.GetLogger().Error("Failed to configure domain", "domain", domain, "service_uid", serviceUID, "error", err)
		return h.failureResponse(err.Error()), nil
	}

	responseInfo := toDomainInfo(info)

	data := map[string]interface{}{
		"success":     true,
		"message":     fmt.Sprintf("Domain %s configured successfully", domain),
		"domain":      domain,
		"domain_info": responseInfo,
	}

	return &types.CommandResponse{Success: true, Data: data}, nil
}

func (h *DomainHandler) handleRemoveDomain(ctx context.Context, request domainRequest) (*types.CommandResponse, error) {
	domain := strings.TrimSpace(request.Domain)
	if domain == "" {
		return h.failureResponse("domain is required"), nil
	}

	domainService := h.GetServices().GetDomainService()
	if domainService == nil {
		return h.failureResponse("Domain service not available"), nil
	}

	if err := domainService.RemoveDomain(ctx, domain); err != nil {
		h.GetLogger().Error("Failed to remove domain", "domain", domain, "error", err)
		return h.failureResponse(err.Error()), nil
	}

	data := map[string]interface{}{
		"success": true,
		"message": "Domain removed successfully",
		"domain":  domain,
	}

	return &types.CommandResponse{Success: true, Data: data}, nil
}

func (h *DomainHandler) handleDomainStatus(ctx context.Context, request domainRequest) (*types.CommandResponse, error) {
	domain := strings.TrimSpace(request.Domain)
	if domain == "" {
		return h.failureResponse("domain is required"), nil
	}

	domainService := h.GetServices().GetDomainService()
	if domainService == nil {
		return h.failureResponse("Domain service not available"), nil
	}

	info, err := domainService.GetDomain(ctx, domain)
	if err != nil {
		h.GetLogger().Warn("Failed to get domain status", "domain", domain, "error", err)
		return h.failureResponse(err.Error()), nil
	}

	data := map[string]interface{}{
		"success":     true,
		"domain_info": toDomainInfo(info),
	}

	return &types.CommandResponse{Success: true, Data: data}, nil
}

func toDomainInfo(info *types.DomainProxyInfo) DomainInfo {
	if info == nil {
		return DomainInfo{}
	}

	return DomainInfo{
		Domain:             info.Domain,
		ServiceUID:         info.ServiceUID,
		UpstreamContainer:  info.UpstreamContainer,
		Port:               info.TargetPort,
		Protocol:           info.TargetProtocol,
		ForceHTTPS:         info.ForceHTTPS,
		RedirectWWW:        info.RedirectWWW,
		ManagedCertificate: info.ManagedCertificate,
		CertificateEmail:   info.CertificateEmail,
		SSL:                info.ManagedCertificate,
		SSLStatus:          info.SSLStatus,
		LastApplied:        info.LastApplied,
	}
}

func (h *DomainHandler) failureResponse(message string) *types.CommandResponse {
	return &types.CommandResponse{
		Success: false,
		Error:   message,
		Data: map[string]interface{}{
			"success": false,
			"message": message,
		},
	}
}

func (h *DomainHandler) isValidDomain(domain string) bool {
	trimmed := strings.TrimSpace(domain)
	if trimmed == "" {
		return false
	}
	if strings.Contains(trimmed, " ") {
		return false
	}
	return strings.Contains(trimmed, ".")
}

// ensureCaddyInstalled checks if Caddy is running and installs it if not
func (h *DomainHandler) ensureCaddyInstalled(ctx context.Context, caddyService CaddyService) error {
	// Check if it has the extended interface with IsCaddyRunning and InstallCaddy methods
	if extendedCaddy, ok := caddyService.(interface {
		IsCaddyRunning(ctx context.Context) (bool, error)
		InstallCaddy(ctx context.Context) error
	}); ok {
		// Check if Caddy is already running
		isRunning, err := extendedCaddy.IsCaddyRunning(ctx)
		if err != nil {
			h.GetLogger().Error("Failed to check if Caddy is running", "error", err)
			return fmt.Errorf("failed to check Caddy status: %w", err)
		}

		if isRunning {
			h.GetLogger().Debug("Caddy is already running")
			return nil
		}

		// Caddy is not running, install it
		h.GetLogger().Info("Caddy is not running, installing Caddy")
		if err := extendedCaddy.InstallCaddy(ctx); err != nil {
			h.GetLogger().Error("Failed to install Caddy", "error", err)
			return fmt.Errorf("failed to install Caddy: %w", err)
		}

		h.GetLogger().Info("Caddy installed and started successfully")
		return nil
	}

	// Fallback: assume Caddy is available (for basic interface)
	h.GetLogger().Warn("Caddy service does not support auto-installation, assuming it's available")
	return nil
}
