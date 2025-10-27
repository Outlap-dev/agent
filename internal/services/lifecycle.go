package services

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"outlap-agent-go/pkg/logger"
	"outlap-agent-go/pkg/types"
)

const (
	lifecycleVersionLabel   = "outlap.lifecycle.version"
	lifecycleFinalNameLabel = "outlap.lifecycle.final_name"
	managedLabelKey         = "outlap.managed"
	serviceUIDLabelKey      = "outlap.service_uid"
)

var versionSuffixPattern = regexp.MustCompile(`(?i)-v(\d+)`)

// DeploymentPlan captures the desired state for provisioning a new container version.
type DeploymentPlan struct {
	ServiceUID      string
	DeploymentUID   string
	Version         int
	CandidateName   string
	FinalName       string
	Labels          map[string]string
	Existing        []types.ContainerInstance
	Active          *types.ContainerInstance
	Deploying       *types.ContainerInstance
	StaleCandidates []types.ContainerInstance
}

// ContainerLifecycleService centralizes container discovery, naming, and promotion logic.
type ContainerLifecycleService struct {
	docker DockerService
	logger *logger.Logger
}

// NewContainerLifecycleService constructs a lifecycle coordinator.
func NewContainerLifecycleService(logger *logger.Logger, docker DockerService) *ContainerLifecycleService {
	return &ContainerLifecycleService{
		docker: docker,
		logger: logger.With("service", "container_lifecycle"),
	}
}

// ListServiceContainers retrieves every managed container for a service, ordered by version (desc).
func (s *ContainerLifecycleService) ListServiceContainers(ctx context.Context, serviceUID string) ([]types.ContainerInstance, error) {
	if s.docker == nil {
		return nil, fmt.Errorf("docker service not available")
	}

	names, err := s.docker.FindContainersByLabel(ctx, serviceUIDLabelKey, serviceUID)
	if err != nil {
		return nil, err
	}

	seen := make(map[string]struct{}, len(names))
	containers := make([]types.ContainerInstance, 0, len(names))

	for _, rawName := range names {
		name := normalizeContainerName(rawName)
		if name == "" {
			continue
		}
		if _, exists := seen[name]; exists {
			continue
		}
		seen[name] = struct{}{}

		inspect, err := s.docker.InspectContainer(ctx, name)
		if err != nil {
			s.logger.Warn("failed to inspect container", "container", name, "error", err)
			continue
		}

		version := extractVersion(inspect.Config.Labels, name)
		createdAt := parseCreatedTime(inspect.Created)
		labelsCopy := copyLabels(inspect.Config.Labels)

		containers = append(containers, types.ContainerInstance{
			ID:        inspect.ID,
			Name:      name,
			Version:   version,
			Labels:    labelsCopy,
			State:     inspect.State.Status,
			CreatedAt: createdAt,
		})
	}

	sort.Slice(containers, func(i, j int) bool {
		if containers[i].Version == containers[j].Version {
			return containers[i].CreatedAt.After(containers[j].CreatedAt)
		}
		return containers[i].Version > containers[j].Version
	})

	return containers, nil
}

// GetActiveContainer returns the currently active container, determined by highest promoted version.
func (s *ContainerLifecycleService) GetActiveContainer(ctx context.Context, serviceUID string) (*types.ContainerInstance, error) {
	containers, err := s.ListServiceContainers(ctx, serviceUID)
	if err != nil {
		return nil, err
	}
	return selectActiveContainer(containers), nil
}

// GetDeployingContainer returns a container that is currently being deployed but not yet promoted.
func (s *ContainerLifecycleService) GetDeployingContainer(ctx context.Context, serviceUID string) (*types.ContainerInstance, error) {
	containers, err := s.ListServiceContainers(ctx, serviceUID)
	if err != nil {
		return nil, err
	}
	return selectDeployingContainer(containers), nil
}

// PlanDeployment establishes the canonical naming and metadata for the next container version.
func (s *ContainerLifecycleService) PlanDeployment(ctx context.Context, serviceUID, deploymentUID string) (*DeploymentPlan, error) {
	containers, err := s.ListServiceContainers(ctx, serviceUID)
	if err != nil {
		return nil, err
	}

	highestVersion := 0
	for _, c := range containers {
		if c.Version > highestVersion {
			highestVersion = c.Version
		}
	}

	nextVersion := highestVersion + 1
	candidateName := fmt.Sprintf("outlap-app-%s-v%04d-candidate", serviceUID, nextVersion)
	finalName := fmt.Sprintf("outlap-app-%s-v%04d", serviceUID, nextVersion)

	labels := map[string]string{
		serviceUIDLabelKey:      serviceUID,
		"outlap.deployment_uid": deploymentUID,
		lifecycleVersionLabel:   strconv.Itoa(nextVersion),
		lifecycleFinalNameLabel: finalName,
		managedLabelKey:         "true",
	}

	plan := &DeploymentPlan{
		ServiceUID:      serviceUID,
		DeploymentUID:   deploymentUID,
		Version:         nextVersion,
		CandidateName:   candidateName,
		FinalName:       finalName,
		Labels:          labels,
		Existing:        containers,
		Active:          selectActiveContainer(containers),
		Deploying:       selectDeployingContainer(containers),
		StaleCandidates: identifyStaleCandidates(containers),
	}

	return plan, nil
}

// CleanupStaleCandidates removes any orphaned candidate containers discovered during planning.
func (s *ContainerLifecycleService) CleanupStaleCandidates(ctx context.Context, plan *DeploymentPlan) []error {
	if plan == nil {
		return nil
	}

	var errs []error
	for _, stale := range plan.StaleCandidates {
		if stale.Name == plan.CandidateName {
			continue
		}
		if err := s.docker.StopContainerByName(ctx, stale.Name); err != nil {
			errs = append(errs, fmt.Errorf("stop %s: %w", stale.Name, err))
		}
		if err := s.docker.RemoveContainerByName(ctx, stale.Name); err != nil {
			errs = append(errs, fmt.Errorf("remove %s: %w", stale.Name, err))
		}
	}
	return errs
}

// DecommissionPreviousActive stops and removes the container that was active before the new deployment.
func (s *ContainerLifecycleService) DecommissionPreviousActive(ctx context.Context, plan *DeploymentPlan) error {
	if plan == nil || plan.Active == nil {
		return nil
	}

	// If the previous active container matches the newly promoted one, nothing to do.
	if strings.EqualFold(plan.Active.Name, plan.FinalName) {
		return nil
	}

	if err := s.docker.StopContainerByName(ctx, plan.Active.Name); err != nil {
		return fmt.Errorf("failed to stop previous active container %s: %w", plan.Active.Name, err)
	}

	if err := s.docker.RemoveContainerByName(ctx, plan.Active.Name); err != nil {
		return fmt.Errorf("failed to remove previous active container %s: %w", plan.Active.Name, err)
	}

	return nil
}

// PromoteCandidate finalizes the deployment by renaming the candidate container to its permanent name.
func (s *ContainerLifecycleService) PromoteCandidate(ctx context.Context, plan *DeploymentPlan) error {
	if plan == nil {
		return fmt.Errorf("deployment plan is required")
	}

	exists, err := s.docker.ContainerExists(ctx, plan.FinalName)
	if err != nil {
		return fmt.Errorf("failed to verify final container name availability: %w", err)
	}

	if exists {
		s.logger.Warn("existing container with final name detected; removing", "container", plan.FinalName)
		if err := s.docker.StopContainerByName(ctx, plan.FinalName); err != nil {
			return fmt.Errorf("failed to stop existing container %s: %w", plan.FinalName, err)
		}
		if err := s.docker.RemoveContainerByName(ctx, plan.FinalName); err != nil {
			return fmt.Errorf("failed to remove existing container %s: %w", plan.FinalName, err)
		}
	}

	if err := s.docker.RenameContainer(ctx, plan.CandidateName, plan.FinalName); err != nil {
		return fmt.Errorf("failed to promote container %s to %s: %w", plan.CandidateName, plan.FinalName, err)
	}

	return nil
}

func selectActiveContainer(containers []types.ContainerInstance) *types.ContainerInstance {
	for _, c := range containers {
		if strings.Contains(strings.ToLower(c.Name), "-candidate") {
			continue
		}
		if strings.EqualFold(c.State, "exited") || strings.EqualFold(c.State, "dead") {
			continue
		}
		instance := c
		return &instance
	}
	return nil
}

func selectDeployingContainer(containers []types.ContainerInstance) *types.ContainerInstance {
	for _, c := range containers {
		if strings.Contains(strings.ToLower(c.Name), "-candidate") {
			instance := c
			return &instance
		}
	}
	return nil
}

func identifyStaleCandidates(containers []types.ContainerInstance) []types.ContainerInstance {
	stale := make([]types.ContainerInstance, 0)
	for _, c := range containers {
		if strings.Contains(strings.ToLower(c.Name), "-candidate") {
			stale = append(stale, c)
		}
	}
	return stale
}

func normalizeContainerName(name string) string {
	trimmed := strings.TrimSpace(name)
	return strings.TrimPrefix(trimmed, "/")
}

func extractVersion(labels map[string]string, name string) int {
	if labels != nil {
		if raw, ok := labels[lifecycleVersionLabel]; ok {
			if v, err := strconv.Atoi(raw); err == nil {
				return v
			}
		}
	}

	matches := versionSuffixPattern.FindStringSubmatch(strings.ToLower(name))
	if len(matches) == 2 {
		if v, err := strconv.Atoi(matches[1]); err == nil {
			return v
		}
	}
	return 0
}

func parseCreatedTime(value string) time.Time {
	if value == "" {
		return time.Now()
	}
	if t, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return t
	}
	return time.Now()
}

func copyLabels(src map[string]string) map[string]string {
	if len(src) == 0 {
		return map[string]string{}
	}
	dst := make(map[string]string, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
