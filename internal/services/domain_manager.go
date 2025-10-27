package services

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"outlap-agent-go/pkg/logger"
	"outlap-agent-go/pkg/types"
)

var (
	errDomainNotFound = errors.New("domain not found")
)

type DomainVerifier func(ctx context.Context, info types.DomainProxyInfo) string

type DomainManagerOption func(*DomainManager)

const (
	defaultVerificationDelay   = 30 * time.Second
	defaultVerificationTimeout = 45 * time.Second
)

type DomainManager struct {
	mu                  sync.RWMutex
	domains             map[string]types.DomainProxyInfo
	caddy               CaddyService
	deployment          DeploymentService
	logger              *logger.Logger
	storagePath         string
	caddyConfigPath     string
	verifier            DomainVerifier
	verificationDelay   time.Duration
	verificationTimeout time.Duration
}

type fileSnapshot struct {
	data   []byte
	exists bool
}

func NewDomainManager(baseLogger *logger.Logger, caddy CaddyService, deployment DeploymentService, opts ...DomainManagerOption) (*DomainManager, error) {
	if caddy == nil {
		return nil, fmt.Errorf("caddy service is required")
	}
	if deployment == nil {
		return nil, fmt.Errorf("deployment service is required")
	}

	mgr := &DomainManager{
		domains:             make(map[string]types.DomainProxyInfo),
		caddy:               caddy,
		deployment:          deployment,
		logger:              baseLogger.With("service", "domain_manager"),
		storagePath:         CaddyDomainsStateFile,
		caddyConfigPath:     CaddyConfigFile,
		verifier:            defaultDomainVerifier,
		verificationDelay:   defaultVerificationDelay,
		verificationTimeout: defaultVerificationTimeout,
	}

	for _, opt := range opts {
		if opt != nil {
			opt(mgr)
		}
	}

	if mgr.storagePath == "" {
		mgr.storagePath = CaddyDomainsStateFile
	}
	if mgr.caddyConfigPath == "" {
		mgr.caddyConfigPath = CaddyConfigFile
	}
	if mgr.verificationTimeout <= 0 {
		mgr.verificationTimeout = defaultVerificationTimeout
	}
	if mgr.verifier == nil {
		mgr.verifier = defaultDomainVerifier
	}

	if err := mgr.load(); err != nil {
		mgr.logger.Warn("Failed to load domain state", "error", err)
	}

	return mgr, nil
}

func (m *DomainManager) snapshotDomainsLocked() map[string]types.DomainProxyInfo {
	clone := make(map[string]types.DomainProxyInfo, len(m.domains))
	for key, value := range m.domains {
		clone[key] = value
	}
	return clone
}

func (m *DomainManager) readFileSnapshot(path string) (fileSnapshot, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		return fileSnapshot{data: append([]byte(nil), data...), exists: true}, nil
	}
	if os.IsNotExist(err) {
		backupPath := path + ".bak"
		backupData, backupErr := os.ReadFile(backupPath)
		if backupErr == nil {
			return fileSnapshot{data: append([]byte(nil), backupData...), exists: true}, nil
		}
		if os.IsNotExist(backupErr) {
			return fileSnapshot{exists: false}, nil
		}
		return fileSnapshot{}, fmt.Errorf("failed to read backup file %s: %w", backupPath, backupErr)
	}
	return fileSnapshot{}, fmt.Errorf("failed to read file %s: %w", path, err)
}

func (m *DomainManager) restoreFileFromSnapshot(path string, snap fileSnapshot) {
	backupPath := path + ".bak"
	if !snap.exists {
		if removeErr := os.Remove(path); removeErr != nil && !os.IsNotExist(removeErr) {
			m.logger.Warn("failed to remove file during rollback", "path", path, "error", removeErr)
		}
		if removeBackupErr := os.Remove(backupPath); removeBackupErr != nil && !os.IsNotExist(removeBackupErr) {
			m.logger.Warn("failed to remove backup during rollback", "path", backupPath, "error", removeBackupErr)
		}
		return
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		m.logger.Warn("failed to prepare directory for rollback", "path", path, "error", err)
		return
	}
	if err := os.WriteFile(path, snap.data, 0o644); err != nil {
		m.logger.Warn("failed to restore file during rollback", "path", path, "error", err)
	} else if err := os.WriteFile(backupPath, snap.data, 0o644); err != nil {
		m.logger.Warn("failed to update backup during rollback", "path", backupPath, "error", err)
	}
}

func (m *DomainManager) commitAndReloadLocked(ctx context.Context, previousDomains map[string]types.DomainProxyInfo, stateSnapshot, configSnapshot fileSnapshot) error {
	if err := m.persistLocked(); err != nil {
		m.domains = previousDomains
		m.restoreFileFromSnapshot(m.storagePath, stateSnapshot)
		return err
	}

	if err := m.applyLocked(ctx, configSnapshot.data, configSnapshot.exists); err != nil {
		m.domains = previousDomains
		m.restoreFileFromSnapshot(m.storagePath, stateSnapshot)
		m.restoreFileFromSnapshot(m.caddyConfigPath, configSnapshot)
		return err
	}

	return nil
}

func (m *DomainManager) UpsertDomain(ctx context.Context, req types.DomainProvisionRequest) (*types.DomainProxyInfo, error) {
	normalizedDomain := normalizeDomain(req.Domain)
	if normalizedDomain == "" {
		return nil, fmt.Errorf("domain is required")
	}

	serviceUID := strings.TrimSpace(req.ServiceUID)
	if serviceUID == "" {
		return nil, fmt.Errorf("service_uid is required")
	}

	port := req.TargetPort
	if port <= 0 || port > 65535 {
		return nil, fmt.Errorf("invalid target port: %d", port)
	}

	protocol := strings.ToLower(strings.TrimSpace(req.TargetProtocol))
	if protocol == "" {
		protocol = "http"
	}
	if protocol != "http" && protocol != "https" {
		return nil, fmt.Errorf("unsupported target protocol: %s", req.TargetProtocol)
	}

	redirect := normalizeRedirectOption(req.RedirectWWW)
	managedCertificate := req.ManagedCertificate
	certificateEmail := strings.TrimSpace(req.CertificateEmail)

	container, err := m.deployment.GetActiveContainer(ctx, serviceUID)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve active container: %w", err)
	}
	if container == nil {
		return nil, fmt.Errorf("no active container for service %s", serviceUID)
	}

	containerName := strings.TrimSpace(container.Name)
	if containerName == "" {
		containerName = strings.TrimSpace(container.ID)
	}
	if containerName == "" {
		return nil, fmt.Errorf("unable to resolve container identifier for service %s", serviceUID)
	}

	now := time.Now().UTC()

	info := types.DomainProxyInfo{
		Domain:             normalizedDomain,
		ServiceUID:         serviceUID,
		UpstreamContainer:  containerName,
		TargetPort:         port,
		TargetProtocol:     protocol,
		ForceHTTPS:         req.ForceHTTPS,
		RedirectWWW:        redirect,
		ManagedCertificate: managedCertificate,
		CertificateEmail:   certificateEmail,
		SSLStatus:          "pending",
		LastApplied:        now,
	}

	if info.CertificateEmail == "" {
		info.CertificateEmail = "domains@outlap.dev"
	}
	if !info.ManagedCertificate {
		info.SSLStatus = "disabled"
	}

	m.mu.Lock()
	previousDomains := m.snapshotDomainsLocked()
	stateSnapshot, err := m.readFileSnapshot(m.storagePath)
	if err != nil {
		m.mu.Unlock()
		return nil, fmt.Errorf("failed to capture domain state snapshot: %w", err)
	}
	configSnapshot, err := m.readFileSnapshot(m.caddyConfigPath)
	if err != nil {
		m.mu.Unlock()
		return nil, fmt.Errorf("failed to capture caddy config snapshot: %w", err)
	}

	if existing, ok := m.domains[normalizedDomain]; ok {
		if existing.SSLStatus != "" {
			info.SSLStatus = existing.SSLStatus
		}
		if info.CertificateEmail == "" {
			info.CertificateEmail = existing.CertificateEmail
		}
	}

	m.domains[normalizedDomain] = info

	if err := m.commitAndReloadLocked(ctx, previousDomains, stateSnapshot, configSnapshot); err != nil {
		m.mu.Unlock()
		return nil, err
	}

	m.mu.Unlock()

	if err := m.ensureNetworkBinding(ctx, containerName); err != nil {
		m.logger.Warn("failed to ensure network binding after config update", "domain", normalizedDomain, "service_uid", serviceUID, "container", containerName, "error", err)
	}

	m.scheduleVerification(info)

	copy := info
	return &copy, nil
}

func (m *DomainManager) RemoveDomain(ctx context.Context, domain string) error {
	normalized := normalizeDomain(domain)
	if normalized == "" {
		return fmt.Errorf("domain is required")
	}

	m.mu.Lock()
	previousDomains := m.snapshotDomainsLocked()
	stateSnapshot, err := m.readFileSnapshot(m.storagePath)
	if err != nil {
		m.mu.Unlock()
		return fmt.Errorf("failed to capture domain state snapshot: %w", err)
	}
	configSnapshot, err := m.readFileSnapshot(m.caddyConfigPath)
	if err != nil {
		m.mu.Unlock()
		return fmt.Errorf("failed to capture caddy config snapshot: %w", err)
	}

	if _, ok := m.domains[normalized]; !ok {
		m.mu.Unlock()
		return errDomainNotFound
	}

	delete(m.domains, normalized)

	if err := m.commitAndReloadLocked(ctx, previousDomains, stateSnapshot, configSnapshot); err != nil {
		m.mu.Unlock()
		return err
	}

	m.mu.Unlock()
	return nil
}

func (m *DomainManager) GetDomain(ctx context.Context, domain string) (*types.DomainProxyInfo, error) {
	normalized := normalizeDomain(domain)
	if normalized == "" {
		return nil, fmt.Errorf("domain is required")
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	info, ok := m.domains[normalized]
	if !ok {
		return nil, errDomainNotFound
	}

	copy := info
	return &copy, nil
}

func (m *DomainManager) RefreshService(ctx context.Context, serviceUID string) error {
	serviceUID = strings.TrimSpace(serviceUID)
	if serviceUID == "" {
		return fmt.Errorf("service_uid is required")
	}

	container, err := m.deployment.GetActiveContainer(ctx, serviceUID)
	if err != nil {
		return fmt.Errorf("failed to resolve active container: %w", err)
	}
	if container == nil {
		return fmt.Errorf("no active container for service %s", serviceUID)
	}

	containerName := strings.TrimSpace(container.Name)
	if containerName == "" {
		containerName = strings.TrimSpace(container.ID)
	}
	if containerName == "" {
		return fmt.Errorf("unable to resolve container identifier for service %s", serviceUID)
	}

	m.mu.Lock()
	previousDomains := m.snapshotDomainsLocked()
	stateSnapshot, err := m.readFileSnapshot(m.storagePath)
	if err != nil {
		m.mu.Unlock()
		return fmt.Errorf("failed to capture domain state snapshot: %w", err)
	}
	configSnapshot, err := m.readFileSnapshot(m.caddyConfigPath)
	if err != nil {
		m.mu.Unlock()
		return fmt.Errorf("failed to capture caddy config snapshot: %w", err)
	}

	updated := false
	var domainsToVerify []types.DomainProxyInfo
	now := time.Now().UTC()
	for key, info := range m.domains {
		if info.ServiceUID != serviceUID {
			continue
		}
		if info.UpstreamContainer == containerName {
			continue
		}
		info.UpstreamContainer = containerName
		info.LastApplied = now
		m.domains[key] = info
		domainsToVerify = append(domainsToVerify, info)
		updated = true
	}

	if !updated {
		m.mu.Unlock()
		if err := m.ensureNetworkBinding(ctx, containerName); err != nil {
			m.logger.Warn("failed to ensure network binding while refreshing service", "service_uid", serviceUID, "container", containerName, "error", err)
		}
		return nil
	}

	if err := m.commitAndReloadLocked(ctx, previousDomains, stateSnapshot, configSnapshot); err != nil {
		m.mu.Unlock()
		return err
	}

	m.mu.Unlock()

	if err := m.ensureNetworkBinding(ctx, containerName); err != nil {
		m.logger.Warn("failed to ensure network binding after service refresh", "service_uid", serviceUID, "container", containerName, "error", err)
	}

	for _, domain := range domainsToVerify {
		m.scheduleVerification(domain)
	}

	return nil
}

func (m *DomainManager) load() error {
	data, err := os.ReadFile(m.storagePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	var items []types.DomainProxyInfo
	if err := json.Unmarshal(data, &items); err != nil {
		return err
	}

	for _, item := range items {
		key := normalizeDomain(item.Domain)
		if key == "" {
			continue
		}
		if item.LastApplied.IsZero() {
			item.LastApplied = time.Now().UTC()
		}
		if item.CertificateEmail == "" {
			item.CertificateEmail = "domains@outlap.dev"
		}
		if item.SSLStatus == "" {
			if item.ManagedCertificate {
				item.SSLStatus = "pending"
			} else {
				item.SSLStatus = "disabled"
			}
		}
		m.domains[key] = item
	}

	return nil
}

func (m *DomainManager) persistLocked() error {
	if err := os.MkdirAll(filepath.Dir(m.storagePath), 0o755); err != nil {
		return fmt.Errorf("failed to ensure domain storage directory: %w", err)
	}

	list := make([]types.DomainProxyInfo, 0, len(m.domains))
	for _, domain := range m.domains {
		list = append(list, domain)
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i].Domain < list[j].Domain
	})

	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal domain state: %w", err)
	}

	tempFile := m.storagePath + ".tmp"
	if err := os.WriteFile(tempFile, data, 0o644); err != nil {
		return fmt.Errorf("failed to write domain state: %w", err)
	}

	if err := os.Rename(tempFile, m.storagePath); err != nil {
		return fmt.Errorf("failed to activate domain state: %w", err)
	}

	if err := os.WriteFile(m.storagePath+".bak", data, 0o644); err != nil {
		m.logger.Warn("failed to update domain state backup", "path", m.storagePath, "error", err)
	}

	return nil
}

func (m *DomainManager) applyLocked(ctx context.Context, previousConfig []byte, hadPrevious bool) error {
	list := make([]types.DomainProxyInfo, 0, len(m.domains))
	for _, domain := range m.domains {
		list = append(list, domain)
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i].Domain < list[j].Domain
	})

	defaultEmail := defaultCaddyEmail
	for _, item := range list {
		if item.CertificateEmail != "" {
			defaultEmail = item.CertificateEmail
			break
		}
	}

	config := renderCaddyConfig(list, defaultEmail)

	if err := os.MkdirAll(filepath.Dir(m.caddyConfigPath), 0o755); err != nil {
		return fmt.Errorf("failed to ensure caddy config directory: %w", err)
	}

	tempFile := m.caddyConfigPath + ".tmp"
	if err := os.WriteFile(tempFile, []byte(config), 0o644); err != nil {
		return fmt.Errorf("failed to write caddyfile: %w", err)
	}

	if err := os.Rename(tempFile, m.caddyConfigPath); err != nil {
		return fmt.Errorf("failed to activate caddyfile: %w", err)
	}

	if err := m.caddy.ReloadConfig(ctx); err != nil {
		if hadPrevious {
			if restoreErr := os.WriteFile(m.caddyConfigPath, previousConfig, 0o644); restoreErr != nil {
				m.logger.Warn("failed to restore previous caddy config after reload error", "error", restoreErr)
			}
		} else if removeErr := os.Remove(m.caddyConfigPath); removeErr != nil && !os.IsNotExist(removeErr) {
			m.logger.Warn("failed to remove caddy config after reload error", "error", removeErr)
		}
		return fmt.Errorf("failed to reload caddy configuration: %w", err)
	}

	if err := os.WriteFile(m.caddyConfigPath+".bak", []byte(config), 0o644); err != nil {
		m.logger.Warn("failed to update caddy config backup", "error", err)
	}

	return nil
}

func (m *DomainManager) ensureNetworkBinding(ctx context.Context, containerName string) error {
	if err := m.ensureCaddyAttached(ctx); err != nil {
		return err
	}

	if err := m.caddy.EnsureContainerInNetwork(ctx, containerName, CaddyNetwork); err != nil {
		return fmt.Errorf("failed to connect container %s to caddy network: %w", containerName, err)
	}

	return nil
}

func (m *DomainManager) ensureCaddyAttached(ctx context.Context) error {
	err := m.caddy.EnsureContainerInNetwork(ctx, CaddyContainerName, CaddyNetwork)
	if err == nil {
		return nil
	}

	if !isContainerNotFoundError(err) {
		return fmt.Errorf("failed to connect caddy container to network: %w", err)
	}

	m.logger.Warn("caddy container missing, attempting reinstall", "error", err)
	if installErr := m.caddy.InstallCaddy(ctx); installErr != nil {
		return fmt.Errorf("failed to reinstall caddy: %w", installErr)
	}

	if retryErr := m.caddy.EnsureContainerInNetwork(ctx, CaddyContainerName, CaddyNetwork); retryErr != nil {
		return fmt.Errorf("failed to connect caddy container to network after reinstall: %w", retryErr)
	}

	return nil
}

func isContainerNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrContainerNotFound) {
		return true
	}

	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "container") && strings.Contains(msg, "not found")
}

func normalizeDomain(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func normalizeRedirectOption(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "to_www", "www":
		return "to_www"
	case "to_root", "root", "no_www":
		return "to_root"
	default:
		return "none"
	}
}

func renderCaddyConfig(domains []types.DomainProxyInfo, defaultEmail string) string {
	builder := &strings.Builder{}

	builder.WriteString("\n# Generated by Outlap Domain Manager\n")
	builder.WriteString("# Changes to this file will be overwritten\n\n")
	builder.WriteString("{")
	builder.WriteString("\n\temail ")
	builder.WriteString(defaultEmail)
	builder.WriteString("\n\tacme_ca https://acme-v02.api.letsencrypt.org/directory\n")
	builder.WriteString("\tauto_https disable_redirects\n")
	builder.WriteString("\tlog {\n\t\toutput file /var/log/caddy/access.log\n\t\tformat json\n\t}\n")
	builder.WriteString("}\n\n")

	builder.WriteString("# Default catch-all for unmatched hosts\n")
	builder.WriteString(":80 {\n\trespond \"Outlap reverse proxy is running. Configure a domain to access your applications.\" 200\n}\n\n")

	for _, domain := range domains {
		builder.WriteString(buildSiteBlock(domain))
	}

	return builder.String()
}

func (m *DomainManager) scheduleVerification(info types.DomainProxyInfo) {
	if m.verifier == nil {
		return
	}
	if !info.ManagedCertificate {
		return
	}

	go func(domainInfo types.DomainProxyInfo) {
		ctx, cancel := context.WithTimeout(context.Background(), m.verificationTimeout)
		defer cancel()

		if delay := m.verificationDelay; delay > 0 {
			timer := time.NewTimer(delay)
			defer timer.Stop()

			select {
			case <-timer.C:
			case <-ctx.Done():
				return
			}
		}

		status := m.verifier(ctx, domainInfo)
		m.updateSSLStatus(domainInfo.Domain, status)
	}(info)
}

func (m *DomainManager) updateSSLStatus(domain, status string) {
	if status == "" {
		return
	}

	normalized := normalizeDomain(domain)
	if normalized == "" {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	info, ok := m.domains[normalized]
	if !ok {
		return
	}
	if info.SSLStatus == status {
		return
	}

	info.SSLStatus = status
	info.LastApplied = time.Now().UTC()
	m.domains[normalized] = info

	if err := m.persistLocked(); err != nil {
		m.logger.Warn("failed to persist domain state after verification", "domain", normalized, "error", err)
	}
}

func defaultDomainVerifier(ctx context.Context, info types.DomainProxyInfo) string {
	host := net.JoinHostPort(info.Domain, "443")
	dialer := &net.Dialer{Timeout: 10 * time.Second}

	if deadline, ok := ctx.Deadline(); ok {
		dialer.Deadline = deadline
	}

	select {
	case <-ctx.Done():
		return "pending"
	default:
	}

	tlsConfig := &tls.Config{
		ServerName:         info.Domain,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", host, tlsConfig)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) {
			return "dns_pending"
		}
		if strings.Contains(err.Error(), "no such host") {
			return "dns_pending"
		}
		if strings.Contains(err.Error(), "context deadline exceeded") || strings.Contains(err.Error(), "timeout") {
			return "pending"
		}
		return "pending"
	}
	_ = conn.Close()
	return "active"
}

func WithDomainStoragePath(path string) DomainManagerOption {
	return func(m *DomainManager) {
		m.storagePath = strings.TrimSpace(path)
	}
}

func WithDomainVerifier(verifier DomainVerifier) DomainManagerOption {
	return func(m *DomainManager) {
		m.verifier = verifier
	}
}

func WithVerificationDelay(delay time.Duration) DomainManagerOption {
	return func(m *DomainManager) {
		m.verificationDelay = delay
	}
}

func WithVerificationTimeout(timeout time.Duration) DomainManagerOption {
	return func(m *DomainManager) {
		m.verificationTimeout = timeout
	}
}

func WithCaddyConfigPath(path string) DomainManagerOption {
	return func(m *DomainManager) {
		m.caddyConfigPath = strings.TrimSpace(path)
	}
}

func buildSiteBlock(info types.DomainProxyInfo) string {
	domainHost := info.Domain
	rootHost := domainHost
	if strings.HasPrefix(domainHost, "www.") {
		rootHost = strings.TrimPrefix(domainHost, "www.")
	}
	wwwHost := "www." + rootHost

	hosts := orderedSet{domainHost}
	switch info.RedirectWWW {
	case "to_www":
		hosts.add(wwwHost)
		hosts.add(rootHost)
	case "to_root":
		hosts.add(rootHost)
		hosts.add(wwwHost)
	}

	builder := &strings.Builder{}
	builder.WriteString(fmt.Sprintf("# %s -> %s:%d\n", domainHost, info.UpstreamContainer, info.TargetPort))
	builder.WriteString(strings.Join(hosts.values(), ", "))
	builder.WriteString(" {\n")

	if info.ManagedCertificate {
		builder.WriteString("\ttls {\n\t\tprotocols tls1.2 tls1.3\n\t}\n")
	} else {
		builder.WriteString("\ttls off\n")
	}

	builder.WriteString("\tencode gzip\n")

	if info.ForceHTTPS {
		builder.WriteString("\t@insecure {\n\t\tprotocol http\n\t}\n")
		builder.WriteString("\thandle @insecure {\n\t\tredir https://{host}{uri} permanent\n\t}\n")
	}

	switch info.RedirectWWW {
	case "to_www":
		builder.WriteString(fmt.Sprintf("\t@root host %s\n", rootHost))
		builder.WriteString(fmt.Sprintf("\thandle @root {\n\t\tredir https://%s{uri} permanent\n\t}\n", wwwHost))
	case "to_root":
		builder.WriteString(fmt.Sprintf("\t@www host %s\n", wwwHost))
		builder.WriteString(fmt.Sprintf("\thandle @www {\n\t\tredir https://%s{uri} permanent\n\t}\n", rootHost))
	}

	upstreamScheme := info.TargetProtocol
	if upstreamScheme == "" {
		upstreamScheme = "http"
	}

	builder.WriteString("\treverse_proxy ")
	builder.WriteString(fmt.Sprintf("%s://%s:%d", upstreamScheme, info.UpstreamContainer, info.TargetPort))
	builder.WriteString("\n}\n\n")

	return builder.String()
}

type orderedSet []string

func (s *orderedSet) add(value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	lower := strings.ToLower(value)
	for _, existing := range *s {
		if strings.ToLower(existing) == lower {
			return
		}
	}
	*s = append(*s, value)
}

func (s orderedSet) values() []string {
	return []string(s)
}
