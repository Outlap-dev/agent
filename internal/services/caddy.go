package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"pulseup-agent-go/pkg/logger"

	containertypes "github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	imagetypes "github.com/docker/docker/api/types/image"
	networktypes "github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/docker/docker/errdefs"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/docker/go-connections/nat"
)

const (
	CaddyStateDir            = "/etc/pulseup-agent/caddy"
	CaddyConfigDir           = "/etc/pulseup-agent/caddy/config"
	CaddyConfigFile          = "/etc/pulseup-agent/caddy/config/Caddyfile"
	CaddyDataDir             = "/etc/pulseup-agent/caddy/data"
	CaddyDomainsFile         = "/etc/pulseup-agent/caddy/domains.json"
	CaddyDomainsStateFile    = "/etc/pulseup-agent/caddy/domains.v2.json"
	CaddyContainerName       = "caddy"
	CaddyContainerConfigDir  = "/etc/caddy"
	CaddyContainerConfigFile = "/etc/caddy/Caddyfile"
	CaddyContainerDataDir    = "/data"
	CaddyNetwork             = "pulseup-net"
	CaddyBridgeNetwork       = "bridge"
	CaddyServiceUID          = "svc_pulseup_caddy"
	CaddyDeploymentUID       = "dep_pulseup_caddy"
	CaddyLifecycleName       = "pulseup-caddy"
	CaddyLifecycleVersion    = "1"
	CaddyComponentLabel      = "pulseup.component"
	DefaultPort              = "80"
)

const (
	defaultCaddyEmail = "domains@pulseup.io"
)

type DomainConfig struct {
	Domain  string            `json:"domain"`
	Target  string            `json:"target"`
	SSL     bool              `json:"ssl"`
	Options map[string]string `json:"options"`
}

type caddyService struct {
	dockerClient *client.Client
	logger       *logger.Logger
	hostRoot     string
}

// NewCaddyService creates a new Caddy service instance
func NewCaddyService(dockerClient *client.Client, logger *logger.Logger) CaddyService {
	hostRoot := strings.TrimSpace(os.Getenv("PULSEUP_CADDY_HOST_PATH"))
	if hostRoot == "" {
		hostRoot = CaddyStateDir
	} else {
		if abs, err := filepath.Abs(hostRoot); err == nil {
			hostRoot = abs
		}
	}

	return &caddyService{
		dockerClient: dockerClient,
		logger:       logger,
		hostRoot:     hostRoot,
	}
}

// IsCaddyRunning checks if the Caddy container is running
func (c *caddyService) IsCaddyRunning(ctx context.Context) (bool, error) {
	args := filters.NewArgs()
	args.Add("name", CaddyContainerName)

	containers, err := c.dockerClient.ContainerList(ctx, containertypes.ListOptions{
		Filters: args,
	})
	if err != nil {
		return false, err
	}

	for _, container := range containers {
		if container.State == "running" {
			return true, nil
		}
	}
	return false, nil
}

// AddRoute adds a new domain route to Caddy
func (c *caddyService) AddRoute(ctx context.Context, domain, target string) error {
	return c.AddSite(ctx, domain, target, true, nil, nil, "youremail@example.com")
}

// AddSite adds a new site to Caddy configuration
func (c *caddyService) AddSite(ctx context.Context, domain, target string, ssl bool, options map[string]string, port *int, email string) error {
	if options == nil {
		options = make(map[string]string)
	}

	// Format target URL if needed
	targetPort := DefaultPort
	if port != nil {
		targetPort = fmt.Sprintf("%d", *port)
	}

	originalTarget := target
	upstreamContainer := ""

	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		// Check if it's a container name
		if c.isContainer(ctx, target) {
			upstreamContainer = target
			// Use container name as hostname in the proxy network
			target = fmt.Sprintf("http://%s:%s", target, targetPort)
		} else {
			// Assume it's a hostname with specified port
			target = fmt.Sprintf("http://%s:%s", target, targetPort)
		}
	} else {
		// When we already have a URL, try to detect if the host is a managed container
		if parsed, err := url.Parse(target); err == nil {
			host := parsed.Hostname()
			if host != "" && c.isContainer(ctx, host) {
				upstreamContainer = host
			}
		}
	}

	// If original target looked like a container name but with scheme/port added later
	if upstreamContainer == "" && originalTarget != target && c.isContainer(ctx, originalTarget) {
		upstreamContainer = originalTarget
	}

	if upstreamContainer != "" {
		// Ensure container is in the PulseUp proxy network
		if err := c.ensureContainerInNetwork(ctx, upstreamContainer, CaddyNetwork); err != nil {
			c.logger.Warn("Failed to connect container %s to PulseUp network: %v", upstreamContainer, err)
		}
	}

	// Create site configuration
	siteConfig := DomainConfig{
		Domain:  domain,
		Target:  target,
		SSL:     ssl,
		Options: options,
	}

	// Read current domains
	domains, err := c.readDomainsFile()
	if err != nil {
		return fmt.Errorf("failed to read domains: %w", err)
	}

	// Add the new domain
	domains[domain] = siteConfig

	// Write updated domains
	if err := c.writeDomainsFile(domains); err != nil {
		return fmt.Errorf("failed to write domains: %w", err)
	}

	// Generate Caddyfile from domains
	if err := c.generateCaddyfile(domains, email); err != nil {
		return fmt.Errorf("failed to generate Caddyfile: %w", err)
	}

	// Reload Caddy
	if err := c.ReloadConfig(ctx); err != nil {
		return fmt.Errorf("failed to reload Caddy config: %w", err)
	}

	return nil
}

// RemoveRoute removes a domain route from Caddy
func (c *caddyService) RemoveRoute(ctx context.Context, domain string) error {
	return c.RemoveSite(ctx, domain)
}

// RemoveSite removes a site from Caddy configuration
func (c *caddyService) RemoveSite(ctx context.Context, domain string) error {
	// Read current domains
	domains, err := c.readDomainsFile()
	if err != nil {
		return fmt.Errorf("failed to read domains: %w", err)
	}

	// Check if domain exists
	if _, exists := domains[domain]; !exists {
		c.logger.Warn("Domain %s not found in Caddy configuration", domain)
		return nil
	}

	// Remove the domain
	delete(domains, domain)

	// Write updated domains
	if err := c.writeDomainsFile(domains); err != nil {
		return fmt.Errorf("failed to write domains: %w", err)
	}

	// Generate Caddyfile from domains
	if err := c.generateCaddyfile(domains, "youremail@example.com"); err != nil {
		return fmt.Errorf("failed to generate Caddyfile: %w", err)
	}

	// Reload Caddy
	if err := c.ReloadConfig(ctx); err != nil {
		return fmt.Errorf("failed to reload Caddy config: %w", err)
	}

	return nil
}

// ReloadConfig reloads the Caddy configuration
func (c *caddyService) ReloadConfig(ctx context.Context) error {
	args := filters.NewArgs()
	args.Add("name", CaddyContainerName)

	containers, err := c.dockerClient.ContainerList(ctx, containertypes.ListOptions{
		Filters: args,
	})
	if err != nil {
		return fmt.Errorf("failed to list containers: %w", err)
	}

	if len(containers) == 0 {
		return fmt.Errorf("Caddy container not found")
	}

	container := containers[0]
	if container.State != "running" {
		c.logger.Warn("Caddy container is not running when attempting reload, starting it", "container", container.Names)
		if err := c.dockerClient.ContainerStart(ctx, container.ID, containertypes.StartOptions{}); err != nil {
			return fmt.Errorf("failed to start Caddy container: %w", err)
		}
	}

	execConfig := containertypes.ExecOptions{
		Cmd:          []string{"caddy", "reload", "--config", CaddyContainerConfigFile, "--adapter", "caddyfile"},
		AttachStdout: true,
		AttachStderr: true,
	}

	execResp, err := c.dockerClient.ContainerExecCreate(ctx, container.ID, execConfig)
	if err != nil {
		return fmt.Errorf("failed to create exec for Caddy reload: %w", err)
	}

	attachResp, err := c.dockerClient.ContainerExecAttach(ctx, execResp.ID, containertypes.ExecStartOptions{
		Detach: false,
		Tty:    false,
	})
	if err != nil {
		return fmt.Errorf("failed to attach to Caddy reload exec: %w", err)
	}
	defer attachResp.Close()

	var stdoutBuf, stderrBuf bytes.Buffer
	if _, err := stdcopy.StdCopy(&stdoutBuf, &stderrBuf, attachResp.Reader); err != nil && err != io.EOF {
		return fmt.Errorf("failed to read Caddy reload output: %w", err)
	}

	inspect, err := c.dockerClient.ContainerExecInspect(ctx, execResp.ID)
	if err != nil {
		return fmt.Errorf("failed to inspect Caddy reload exec: %w", err)
	}

	stdout := strings.TrimSpace(stdoutBuf.String())
	stderr := strings.TrimSpace(stderrBuf.String())

	if inspect.ExitCode != 0 {
		errorMsg := stderr
		if errorMsg == "" {
			errorMsg = stdout
		}
		return fmt.Errorf("caddy reload exited with code %d: %s", inspect.ExitCode, errorMsg)
	}

	if stdout != "" || stderr != "" {
		c.logger.Debug("Caddy reload command output", "stdout", stdout, "stderr", stderr)
	}

	c.logger.Info("Caddy configuration reloaded successfully without restarting container")
	return nil
}

// GetSSLStatus returns the SSL status for a domain
func (c *caddyService) GetSSLStatus(ctx context.Context, domain string) (string, error) {
	domains, err := c.readDomainsFile()
	if err != nil {
		return "", fmt.Errorf("failed to read domains: %w", err)
	}

	config, exists := domains[domain]
	if !exists {
		return "not_configured", nil
	}

	if config.SSL {
		return "enabled", nil
	}
	return "disabled", nil
}

// GenerateSSL generates SSL certificate for a domain
func (c *caddyService) GenerateSSL(ctx context.Context, domain string) error {
	// In Caddy, SSL is automatically generated when SSL is enabled for a domain
	// We just need to ensure the domain has SSL enabled
	domains, err := c.readDomainsFile()
	if err != nil {
		return fmt.Errorf("failed to read domains: %w", err)
	}

	config, exists := domains[domain]
	if !exists {
		return fmt.Errorf("domain %s not found", domain)
	}

	if !config.SSL {
		config.SSL = true
		domains[domain] = config

		if err := c.writeDomainsFile(domains); err != nil {
			return fmt.Errorf("failed to write domains: %w", err)
		}

		if err := c.generateCaddyfile(domains, "youremail@example.com"); err != nil {
			return fmt.Errorf("failed to generate Caddyfile: %w", err)
		}

		if err := c.ReloadConfig(ctx); err != nil {
			return fmt.Errorf("failed to reload Caddy config: %w", err)
		}
	}

	return nil
}

// Initialize sets up the Caddy service with required directories and networks
func (c *caddyService) Initialize(ctx context.Context) error {
	// Create required directories
	if err := os.MkdirAll(CaddyStateDir, 0755); err != nil {
		return fmt.Errorf("failed to create Caddy state directory: %w", err)
	}

	if err := os.MkdirAll(CaddyConfigDir, 0755); err != nil {
		return fmt.Errorf("failed to create Caddy config directory: %w", err)
	}

	if err := os.MkdirAll(CaddyDataDir, 0755); err != nil {
		return fmt.Errorf("failed to create Caddy data directory: %w", err)
	}

	// Create domains.json file if it doesn't exist
	if _, err := os.Stat(CaddyDomainsFile); os.IsNotExist(err) {
		domains := make(map[string]DomainConfig)
		if err := c.writeDomainsFile(domains); err != nil {
			return fmt.Errorf("failed to create domains.json: %w", err)
		}
	}

	if err := c.ensureDomainsStateFile(); err != nil {
		return err
	}

	// Create Caddy network if it doesn't exist
	if err := c.ensureNetwork(ctx, CaddyNetwork); err != nil {
		return fmt.Errorf("failed to create Caddy network: %w", err)
	}

	return nil
}

// InstallCaddy installs and starts the Caddy container
func (c *caddyService) InstallCaddy(ctx context.Context) error {
	// Initialize first
	if err := c.Initialize(ctx); err != nil {
		return err
	}

	// Create basic Caddyfile if it doesn't exist
	if info, err := os.Stat(CaddyConfigFile); err != nil {
		if os.IsNotExist(err) {
			if err := c.createBasicCaddyfile(); err != nil {
				return fmt.Errorf("failed to create basic Caddyfile: %w", err)
			}
		} else {
			return fmt.Errorf("failed to stat Caddyfile: %w", err)
		}
	} else if info.Size() == 0 {
		if err := c.createBasicCaddyfile(); err != nil {
			return fmt.Errorf("failed to refresh empty Caddyfile: %w", err)
		}
	}

	// Pull Caddy image
	c.logger.Info("Pulling Caddy image...")
	if err := c.pullImage(ctx, "caddy:latest"); err != nil {
		return fmt.Errorf("failed to pull Caddy image: %w", err)
	}

	// Start Caddy container
	c.logger.Info("Starting Caddy container...")
	if err := c.startCaddyContainer(ctx); err != nil {
		return fmt.Errorf("failed to start Caddy container: %w", err)
	}

	c.logger.Info("Caddy installed and started successfully")
	return nil
}

// EnsureContainerInNetwork ensures a container is connected to the specified network
func (c *caddyService) EnsureContainerInNetwork(ctx context.Context, containerName, networkName string) error {
	return c.ensureContainerInNetwork(ctx, containerName, networkName)
}

// Helper methods

func (c *caddyService) isContainer(ctx context.Context, name string) bool {
	args := filters.NewArgs()
	args.Add("name", name)

	containers, err := c.dockerClient.ContainerList(ctx, containertypes.ListOptions{
		All:     true,
		Filters: args,
	})
	if err != nil {
		return false
	}
	return len(containers) > 0
}

func (c *caddyService) ensureNetwork(ctx context.Context, networkName string) error {
	args := filters.NewArgs()
	args.Add("name", networkName)

	networks, err := c.dockerClient.NetworkList(ctx, networktypes.ListOptions{
		Filters: args,
	})
	if err != nil {
		return err
	}

	// Check if network already exists
	for _, net := range networks {
		if net.Name == networkName {
			return nil
		}
	}

	// Create network
	_, err = c.dockerClient.NetworkCreate(ctx, networkName, networktypes.CreateOptions{
		Driver: "bridge",
	})
	if err != nil {
		return err
	}

	c.logger.Info("Created Docker network: %s", networkName)
	return nil
}

func (c *caddyService) ensureContainerInNetwork(ctx context.Context, containerName, networkName string) error {
	// Get container by name or ID
	args := filters.NewArgs()
	args.Add("name", containerName)
	args.Add("id", containerName)

	containers, err := c.dockerClient.ContainerList(ctx, containertypes.ListOptions{
		All:     true,
		Filters: args,
	})
	if err != nil {
		return err
	}

	if len(containers) == 0 {
		return fmt.Errorf("container %s not found", containerName)
	}

	container := containers[0]

	// Ensure the network exists first
	if err := c.ensureNetwork(ctx, networkName); err != nil {
		return err
	}

	netArgs := filters.NewArgs()
	netArgs.Add("name", networkName)

	networks, err := c.dockerClient.NetworkList(ctx, networktypes.ListOptions{
		Filters: netArgs,
	})
	if err != nil {
		return err
	}

	if len(networks) == 0 {
		return fmt.Errorf("network %s not found", networkName)
	}

	network := networks[0]

	// Check if container is already connected by ID or name
	normalizedName := strings.TrimPrefix(containerName, "/")
	for id, endpoint := range network.Containers {
		if id == container.ID || strings.TrimPrefix(endpoint.Name, "/") == normalizedName || endpoint.Name == containerName {
			return nil // Already connected
		}
	}

	// Connect container to network
	if err := c.dockerClient.NetworkConnect(ctx, network.ID, container.ID, &networktypes.EndpointSettings{}); err != nil {
		if errdefs.IsConflict(err) {
			return nil
		}
		if strings.Contains(err.Error(), "already exists") {
			return nil
		}
		return err
	}

	c.logger.Info("Connected container %s to network %s", normalizedName, networkName)
	return nil
}

func (c *caddyService) pullImage(ctx context.Context, imageName string) error {
	const pullBufferSize = 1024

	c.logger.Info("Pulling Docker image", "image", imageName)

	pullReader, err := c.dockerClient.ImagePull(ctx, imageName, imagetypes.PullOptions{})
	if err != nil {
		return fmt.Errorf("failed to initiate image pull for %s: %w", imageName, err)
	}
	// Read the pull response to ensure completion
	_, err = io.Copy(io.Discard, pullReader)
	if err != nil {
		return fmt.Errorf("error reading image pull response: %w", err)
	}

	c.logger.Info("Successfully pulled Docker image", "image", imageName)
	return nil
}

func (c *caddyService) startCaddyContainer(ctx context.Context) error {
	// Ensure the proxy network exists before we create the container
	if err := c.ensureNetwork(ctx, CaddyNetwork); err != nil {
		return fmt.Errorf("failed to ensure PulseUp network %s: %w", CaddyNetwork, err)
	}

	// Guarantee a Caddyfile exists so the container boots successfully
	if info, err := os.Stat(CaddyConfigFile); err != nil {
		if os.IsNotExist(err) {
			if writeErr := c.createBasicCaddyfile(); writeErr != nil {
				return fmt.Errorf("failed to write base Caddyfile: %w", writeErr)
			}
		} else {
			return fmt.Errorf("failed to stat Caddyfile: %w", err)
		}
	} else if info.Size() == 0 {
		if writeErr := c.createBasicCaddyfile(); writeErr != nil {
			return fmt.Errorf("failed to refresh empty Caddyfile: %w", writeErr)
		}
	}

	// Check if container already exists
	args := filters.NewArgs()
	args.Add("name", CaddyContainerName)

	containers, err := c.dockerClient.ContainerList(ctx, containertypes.ListOptions{
		All:     true,
		Filters: args,
	})
	if err != nil {
		return err
	}

	// Remove existing container if it exists
	for _, container := range containers {
		c.logger.Info("Removing existing Caddy container: %s", container.ID)
		err = c.dockerClient.ContainerRemove(ctx, container.ID, containertypes.RemoveOptions{
			Force: true,
		})
		if err != nil {
			c.logger.Warn("Failed to remove existing container: %v", err)
		}
	}

	// Create container
	config := &containertypes.Config{
		Image: "caddy:latest",
		Cmd:   []string{"caddy", "run", "--config", CaddyContainerConfigFile},
		ExposedPorts: nat.PortSet{
			"80/tcp":  struct{}{},
			"443/tcp": struct{}{},
		},
		Env: []string{
			fmt.Sprintf("CADDY_CONFIG=%s", CaddyContainerConfigFile),
		},
		Labels: caddyContainerLabels(),
	}

	hostConfig := &containertypes.HostConfig{
		PortBindings: nat.PortMap{
			"80/tcp":  []nat.PortBinding{{HostPort: "80"}},
			"443/tcp": []nat.PortBinding{{HostPort: "443"}},
		},
		Binds: []string{
			fmt.Sprintf("%s:%s:rw", c.hostConfigDir(), CaddyContainerConfigDir),
			fmt.Sprintf("%s:%s:rw", c.hostDataDir(), CaddyContainerDataDir),
		},
		RestartPolicy: containertypes.RestartPolicy{
			Name: "unless-stopped",
		},
	}

	endpoints := map[string]*networktypes.EndpointSettings{
		CaddyNetwork: {},
	}
	if CaddyBridgeNetwork != "" && CaddyBridgeNetwork != CaddyNetwork {
		endpoints[CaddyBridgeNetwork] = &networktypes.EndpointSettings{}
	}

	networkingConfig := &networktypes.NetworkingConfig{
		EndpointsConfig: endpoints,
	}

	response, err := c.dockerClient.ContainerCreate(ctx, config, hostConfig, networkingConfig, nil, CaddyContainerName)
	if err != nil {
		return err
	}

	// Start container
	err = c.dockerClient.ContainerStart(ctx, response.ID, containertypes.StartOptions{})
	if err != nil {
		// TODO: Alert backend-go via websocket when port binding fails (e.g. ports 80/443 already in use) so the deployment can surface the issue to users.
		return err
	}

	if err := c.ensureContainerInNetwork(ctx, response.ID, CaddyNetwork); err != nil {
		c.logger.Warn("Failed to ensure Caddy container is attached to network %s: %v", CaddyNetwork, err)
	}

	c.logger.Info("Caddy container started successfully")
	return nil
}

func (c *caddyService) hostConfigDir() string {
	return filepath.Join(c.hostRoot, "config")
}

func (c *caddyService) hostDataDir() string {
	return filepath.Join(c.hostRoot, "data")
}

func (c *caddyService) createBasicCaddyfile() error {
	return c.generateCaddyfile(map[string]DomainConfig{}, defaultCaddyEmail)
}

func caddyContainerLabels() map[string]string {
	return map[string]string{
		managedLabelKey:          "true",
		serviceUIDLabelKey:       CaddyServiceUID,
		"pulseup.deployment_uid": CaddyDeploymentUID,
		lifecycleFinalNameLabel:  CaddyLifecycleName,
		lifecycleVersionLabel:    CaddyLifecycleVersion,
		CaddyComponentLabel:      "caddy",
	}
}

func (c *caddyService) readDomainsFile() (map[string]DomainConfig, error) {
	domains := make(map[string]DomainConfig)

	if _, err := os.Stat(CaddyDomainsFile); os.IsNotExist(err) {
		return domains, nil
	}

	data, err := os.ReadFile(CaddyDomainsFile)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(data, &domains)
	if err != nil {
		return nil, err
	}

	return domains, nil
}

func (c *caddyService) writeDomainsFile(domains map[string]DomainConfig) error {
	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(CaddyDomainsFile), 0755); err != nil {
		return err
	}

	// Write to temporary file first
	tempFile := CaddyDomainsFile + ".tmp"
	data, err := json.MarshalIndent(domains, "", "  ")
	if err != nil {
		return err
	}

	err = os.WriteFile(tempFile, data, 0644)
	if err != nil {
		return err
	}

	// Move to final location
	return os.Rename(tempFile, CaddyDomainsFile)
}

func (c *caddyService) ensureDomainsStateFile() error {
	if err := os.MkdirAll(filepath.Dir(CaddyDomainsStateFile), 0755); err != nil {
		return fmt.Errorf("failed to create domains state directory: %w", err)
	}

	if _, err := os.Stat(CaddyDomainsStateFile); err != nil {
		if os.IsNotExist(err) {
			if writeErr := os.WriteFile(CaddyDomainsStateFile, []byte("[]\n"), 0644); writeErr != nil {
				return fmt.Errorf("failed to create domains state file: %w", writeErr)
			}
			return nil
		}
		return fmt.Errorf("failed to stat domains state file: %w", err)
	}

	return nil
}

func (c *caddyService) generateCaddyfile(domains map[string]DomainConfig, email string) error {
	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(CaddyConfigFile), 0755); err != nil {
		return err
	}

	// Use provided email or fallback to default
	if email == "" {
		email = "youremail@example.com"
	}

	// Global options
	caddyfile := fmt.Sprintf(`
# Global options
{
	# Email for Let's Encrypt
	email %s
	
	# Use HTTP challenge for Let's Encrypt
	acme_ca https://acme-v02.api.letsencrypt.org/directory
	
	# Handle HTTP challenges without redirects
	auto_https disable_redirects
	
	# Logging settings
	log {
		output file /var/log/caddy/access.log
		format json
	}
}

# Default site - Handles requests to the server's IP without a domain
:80 {
	# Respond with a message for now
	respond "Caddy reverse proxy is running. Configure a domain to access your applications." 200
}
`, email)

	// Add each site
	for domain, config := range domains {
		caddyfile += fmt.Sprintf("\n%s {\n", domain)

		// SSL options
		if config.SSL {
			caddyfile += "	tls {\n"
			caddyfile += "		protocols tls1.2 tls1.3\n"
			caddyfile += "	}\n"
		} else {
			caddyfile += "	tls off\n"
		}

		// Add custom options
		for key, value := range config.Options {
			caddyfile += fmt.Sprintf("	%s %s\n", key, value)
		}

		// Reverse proxy
		caddyfile += fmt.Sprintf("	reverse_proxy %s\n", config.Target)

		// Close site block
		caddyfile += "}\n"
	}

	// Write to temporary file first
	tempFile := CaddyConfigFile + ".tmp"
	err := os.WriteFile(tempFile, []byte(caddyfile), 0644)
	if err != nil {
		return err
	}

	// Move to final location
	return os.Rename(tempFile, CaddyConfigFile)
}
