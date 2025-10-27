package services

import (
	"context"
	"encoding/json"
	"math"
	"time"

	"outlap-agent-go/pkg/logger"
	"outlap-agent-go/pkg/types"
)

type HardwareReporter struct {
	logger  *logger.Logger
	system  SystemService
	emitter types.WebSocketEmitter
}

func NewHardwareReporter(logger *logger.Logger, system SystemService, emitter types.WebSocketEmitter) *HardwareReporter {
	return &HardwareReporter{
		logger:  logger.With("component", "hardware_reporter"),
		system:  system,
		emitter: emitter,
	}
}

func (r *HardwareReporter) Report(ctx context.Context) error {
	if r == nil {
		return nil
	}
	if r.system == nil {
		return nil
	}
	if r.emitter == nil || !r.emitter.IsConnected() {
		return nil
	}

	hwCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	info, err := r.system.GetHardwareInfo(hwCtx)
	if err != nil {
		r.logger.Error("Failed to collect hardware info", "error", err)
		return err
	}

	payload := BuildHardwarePayload(info)

	if err := r.emitter.Emit("register_hardware_info", payload); err != nil {
		r.logger.Error("Failed to emit hardware info", "error", err)
		return err
	}

	return nil
}

func BuildHardwarePayload(info *types.HardwareInfo) map[string]interface{} {
	if info == nil {
		return map[string]interface{}{}
	}

	metadata := structToMap(info)
	if metadata == nil {
		metadata = map[string]interface{}{}
	}
	if info.Hostname != "" {
		metadata["default_name"] = info.Hostname
	}

	return map[string]interface{}{
		"hostname":       info.Hostname,
		"default_name":   info.Hostname,
		"ip_address":     info.PublicIP,
		"private_ip":     info.PrimaryIP,
		"cpu_model":      info.CPU.Model,
		"cpu_arch":       info.CPU.Arch,
		"cpu_cores":      info.CPUPhysicalCores,
		"cpu_count":      info.CPULogicalCount,
		"ram_gb":         roundFloat(info.TotalMemoryGB, 2),
		"storage_gb":     roundFloat(info.StorageTotalGB, 2),
		"os_name":        info.OS.Name,
		"os_version":     info.OS.Version,
		"kernel_version": info.OS.Kernel,
		"metadata":       metadata,
		"collected_at":   time.Now().UTC(),
	}
}

func structToMap(v interface{}) map[string]interface{} {
	if v == nil {
		return map[string]interface{}{}
	}
	bytes, err := json.Marshal(v)
	if err != nil {
		return map[string]interface{}{}
	}
	var out map[string]interface{}
	if err := json.Unmarshal(bytes, &out); err != nil {
		return map[string]interface{}{}
	}
	return out
}

func roundFloat(value float64, precision int) float64 {
	if precision <= 0 {
		return value
	}
	factor := math.Pow(10, float64(precision))
	return math.Round(value*factor) / factor
}
