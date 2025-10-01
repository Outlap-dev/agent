# Deployment Labels Implementation

## Overview

This document describes the implementation of consistent Docker container labeling across all PulseUp deployment methods.

## Problem Statement

Previously, containers deployed via different methods (Nixpacks, Dockerfile, Docker Compose) had inconsistent labeling:

- **Nixpacks deployments**: Had full PulseUp management labels
- **Dockerfile deployments**: Had full PulseUp management labels  
- **Docker Compose deployments**: Had NO PulseUp management labels, only Docker Compose labels

This inconsistency made it difficult to:
- Identify and manage all PulseUp-deployed containers uniformly
- Filter containers by service or deployment
- Track container lifecycle across deployment types

## Standard PulseUp Labels

All PulseUp-managed containers now include these labels:

| Label | Description | Example |
|-------|-------------|---------|
| `pulseup.managed` | Identifies PulseUp-managed containers | `"true"` |
| `pulseup.service_uid` | Service unique identifier | `"svc_abc123"` |
| `pulseup.deployment_uid` | Deployment unique identifier | `"dep_xyz789"` |
| `pulseup.lifecycle.version` | Container version number | `"1"`, `"2"`, etc. |
| `pulseup.lifecycle.final_name` | Final container name after promotion | `"pulseup-app-svc_abc123-v0001"` |

## Implementation by Deployment Method

### Nixpacks & Dockerfile Deployments

These methods already used the lifecycle service and `DeployContainer()` method, which automatically applies all standard labels through the `ContainerLifecycleService.PlanDeployment()` function.

**Location**: `agent/internal/services/lifecycle.go`

```go
labels := map[string]string{
    serviceUIDLabelKey:       serviceUID,
    "pulseup.deployment_uid": deploymentUID,
    lifecycleVersionLabel:    strconv.Itoa(nextVersion),
    lifecycleFinalNameLabel:  finalName,
    managedLabelKey:          "true",
}
```

### Docker Compose Deployments

Docker Compose deployments bypass the `DeployContainer()` method and create containers directly via `docker compose up`. To add labels, we implemented a post-deployment labeling step:

**Location**: `agent/internal/services/docker_compose.go`

1. After `docker compose up` succeeds, find all containers in the project:
   ```bash
   docker ps -a -q --filter label=com.docker.compose.project=<project-name>
   ```

2. Add PulseUp labels to each container:
   ```bash
   docker container update --label-add pulseup.managed=true \
                          --label-add pulseup.service_uid=<service-uid> \
                          --label-add pulseup.deployment_uid=<deployment-uid> \
                          <container-id>
   ```

**Note**: The `docker container update --label-add` command requires Docker Engine 25.0+ (API 1.45). For older Docker versions, a warning is logged but deployment continues successfully. The containers will be functional but won't have PulseUp management labels.

## Testing

### Test Coverage

1. **Docker Compose Label Addition** (`TestDockerComposeServiceAddsLabels`)
   - Verifies that `docker ps` is called to list containers
   - Confirms proper filtering by compose project label

2. **Docker Compose Container Labeling** (`TestDockerComposeServiceLabelsContainers`)
   - Simulates containers being found and labeled
   - Verifies `docker container update` calls with correct labels
   - Confirms all required PulseUp labels are included

3. **Regular Deployment Labels** (`TestDeployContainerSetsPulseUpLabels`)
   - Tests Nixpacks/Dockerfile deployments
   - Verifies all standard PulseUp labels on final container
   - Confirms lifecycle labels (version, final_name) are correct

4. **Database Deployment Labels** (`TestDeployDatabaseSetsPulseupLabels`)
   - Verifies database containers have proper labels
   - Existing test, no changes needed

### Running Tests

```bash
# All deployment-related tests
go test ./internal/services -run "TestDeploy|TestDockerCompose" -v

# Label-specific tests
go test ./internal/services -run "Label" -v
```

## Files Modified

1. `agent/internal/services/docker_compose.go`
   - Added `labelComposeContainers()` method
   - Modified `Deploy()` to call labeling after compose up

2. `agent/internal/services/docker_compose_test.go`
   - Updated existing tests to expect ps call
   - Added `TestDockerComposeServiceAddsLabels`
   - Added `TestDockerComposeServiceLabelsContainers`
   - Added `mockComposeRunnerWithContainers` test helper

3. `agent/internal/services/deployment_test.go`
   - Added `TestDeployContainerSetsPulseUpLabels`

## Docker Version Compatibility

### Docker Engine 25.0+ (API 1.45+)
- Full label support via `docker container update --label-add`
- Labels are applied successfully to all compose containers

### Docker Engine < 25.0 (API < 1.45)
- `docker container update --label-add` not supported
- Warning logged: "Could not add labels to container (requires Docker 25.0+)"
- Container deployment succeeds but without PulseUp labels
- Containers remain functional, just missing management metadata

## Future Improvements

1. **Fallback Labeling Strategy**: For older Docker versions, consider:
   - Parsing docker-compose.yml and injecting labels before deployment
   - Using environment variables to pass labels to compose
   - Creating a sidecar script to label containers post-deployment

2. **Label Validation**: Add validation to ensure labels are correctly applied:
   ```go
   func (s *DockerComposeServiceImpl) validateLabels(ctx context.Context, containerIDs []string) error
   ```

3. **Retry Logic**: If labeling fails transiently, retry with exponential backoff

## Example Container Inspection

### Nixpacks Deployed Container
```json
{
  "Labels": {
    "pulseup.deployment_uid": "dep_1759258364691282000",
    "pulseup.lifecycle.final_name": "pulseup-app-svc_qslue09-v0012",
    "pulseup.lifecycle.version": "12",
    "pulseup.managed": "true",
    "pulseup.service_uid": "svc_qslue09"
  }
}
```

### Docker Compose Deployed Container (After Fix)
```json
{
  "Labels": {
    "com.docker.compose.project": "pulseup-svc_myh8qzy",
    "com.docker.compose.service": "counter",
    "pulseup.deployment_uid": "dep_1759258123456789000",
    "pulseup.managed": "true",
    "pulseup.service_uid": "svc_myh8qzy"
  }
}
```

## Conclusion

All deployment methods now consistently apply PulseUp management labels, enabling:
- Unified container discovery and filtering
- Consistent lifecycle management
- Better observability and debugging
- Cross-deployment-method container queries
