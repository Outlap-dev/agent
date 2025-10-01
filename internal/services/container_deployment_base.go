package services

import (
	"context"
	"fmt"

	"pulseup-agent-go/pkg/logger"
	"pulseup-agent-go/pkg/types"
)

// containerDeploymentBase provides shared helpers for deployment strategies that
// build Docker images and then hand off to the blue/green deployment service.
type containerDeploymentBase struct {
	logger            *logger.Logger
	deploymentService DeploymentService
}

func newContainerDeploymentBase(baseLogger *logger.Logger, deploymentService DeploymentService) *containerDeploymentBase {
	if deploymentService == nil {
		return nil
	}

	var helperLogger *logger.Logger
	if baseLogger != nil {
		helperLogger = baseLogger.With("component", "container_deployment")
	}

	return &containerDeploymentBase{
		logger:            helperLogger,
		deploymentService: deploymentService,
	}
}

func (b *containerDeploymentBase) imageNameForService(serviceUID string) string {
	if serviceUID == "" {
		return "pulseup-app"
	}
	return fmt.Sprintf("pulseup-app:%s", serviceUID)
}

func (b *containerDeploymentBase) deployBuiltImage(
	ctx context.Context,
	serviceUID, imageName, deploymentUID string,
	envVars map[string]string,
	recorder types.DeploymentStepRecorder,
	stepID string,
) (*types.DeploymentResult, error) {
	if b == nil || b.deploymentService == nil {
		return nil, fmt.Errorf("deployment service not available")
	}

	if imageName == "" {
		imageName = b.imageNameForService(serviceUID)
	}

	if b.logger != nil {
		b.logger.Info("Deploying built container",
			"service_uid", serviceUID,
			"image_name", imageName,
			"deployment_uid", deploymentUID,
		)
	}

	return b.deploymentService.DeployContainer(ctx, serviceUID, imageName, deploymentUID, envVars, recorder, stepID)
}
