package services

import (
	"context"
	"fmt"
	"io"
	stdnet "net"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/load"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"

	"outlap-agent-go/pkg/logger"
	"outlap-agent-go/pkg/types"
)

// SystemServiceImpl implements the SystemService interface
type SystemServiceImpl struct {
	logger *logger.Logger
}

// NewSystemService creates a new system service
func NewSystemService(logger *logger.Logger) *SystemServiceImpl {
	return &SystemServiceImpl{
		logger: logger.With("service", "system"),
	}
}

// GetSystemMetrics returns current system metrics
func (s *SystemServiceImpl) GetSystemMetrics(ctx context.Context) (*types.SystemMetrics, error) {
	s.logger.Debug("Getting system metrics")

	// Get CPU metrics
	cpuPercent, err := cpu.Percent(time.Second, false)
	if err != nil {
		return nil, fmt.Errorf("failed to get CPU usage: %w", err)
	}

	loadAvg, err := load.Avg()
	if err != nil {
		s.logger.Warn("Failed to get load average", "error", err)
		loadAvg = &load.AvgStat{} // Use empty struct as fallback
	}

	// Get memory metrics
	memInfo, err := mem.VirtualMemory()
	if err != nil {
		return nil, fmt.Errorf("failed to get memory info: %w", err)
	}

	// Get disk metrics
	diskInfo, err := disk.Usage("/")
	if err != nil {
		return nil, fmt.Errorf("failed to get disk info: %w", err)
	}

	// Get network metrics
	netStats, err := net.IOCounters(false)
	if err != nil {
		s.logger.Warn("Failed to get network stats", "error", err)
		netStats = []net.IOCountersStat{{}} // Use empty struct as fallback
	}

	var cpuUsage float64
	if len(cpuPercent) > 0 {
		cpuUsage = cpuPercent[0]
	}

	var bytesIn, bytesOut uint64
	if len(netStats) > 0 {
		bytesIn = netStats[0].BytesRecv
		bytesOut = netStats[0].BytesSent
	}

	// Get host info for uptime
	hostInfo, err := host.Info()
	if err != nil {
		s.logger.Warn("Failed to get host info for uptime", "error", err)
		hostInfo = &host.InfoStat{} // Use empty struct as fallback
	}

	metrics := &types.SystemMetrics{
		CPU: types.CPUMetrics{
			Usage:     cpuUsage,
			LoadAvg1:  loadAvg.Load1,
			LoadAvg5:  loadAvg.Load5,
			LoadAvg15: loadAvg.Load15,
		},
		Memory: types.MemoryMetrics{
			Total:     memInfo.Total,
			Used:      memInfo.Used,
			Available: memInfo.Available,
			Usage:     memInfo.UsedPercent,
		},
		Disk: types.DiskMetrics{
			Total: diskInfo.Total,
			Used:  diskInfo.Used,
			Free:  diskInfo.Free,
			Usage: diskInfo.UsedPercent,
		},
		Network: types.NetworkMetrics{
			BytesIn:  bytesIn,
			BytesOut: bytesOut,
		},
		Uptime:    time.Duration(hostInfo.Uptime) * time.Second,
		Timestamp: time.Now(),
	}

	return metrics, nil
}

// getPublicIP attempts to get the public IP address
func (s *SystemServiceImpl) getPublicIP(ctx context.Context) string {
	// Try multiple services in case one is down
	services := []string{
		"https://api.ipify.org",
		"https://icanhazip.com",
		"https://ipecho.net/plain",
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	for _, service := range services {
		req, err := http.NewRequestWithContext(ctx, "GET", service, nil)
		if err != nil {
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}

		ip := strings.TrimSpace(string(body))
		if ip != "" {
			return ip
		}
	}

	return "unknown"
}

// GetHardwareInfo returns hardware information
func (s *SystemServiceImpl) GetHardwareInfo(ctx context.Context) (*types.HardwareInfo, error) {
	s.logger.Debug("Getting hardware information")

	// Get CPU info
	cpuInfo, err := cpu.Info()
	if err != nil {
		return nil, fmt.Errorf("failed to get CPU info: %w", err)
	}

	// Get CPU counts
	logicalCount, err := cpu.Counts(true) // logical cores (with hyperthreading)
	if err != nil {
		s.logger.Warn("Failed to get logical CPU count", "error", err)
		logicalCount = runtime.NumCPU() // fallback
	}

	physicalCount, err := cpu.Counts(false) // physical cores
	if err != nil {
		s.logger.Warn("Failed to get physical CPU count", "error", err)
		physicalCount = logicalCount // fallback to logical count
	}

	// Get memory info
	memInfo, err := mem.VirtualMemory()
	if err != nil {
		return nil, fmt.Errorf("failed to get memory info: %w", err)
	}

	// Get disk info
	diskInfo, err := disk.Usage("/")
	if err != nil {
		return nil, fmt.Errorf("failed to get disk info: %w", err)
	}

	// Get network interfaces
	interfaces, err := net.Interfaces()
	if err != nil {
		s.logger.Warn("Failed to get network interfaces", "error", err)
		interfaces = []net.InterfaceStat{} // Use empty slice as fallback
	}

	// Get host info
	hostInfo, err := host.Info()
	if err != nil {
		return nil, fmt.Errorf("failed to get host info: %w", err)
	}

	// Get public IP
	publicIP := s.getPublicIP(ctx)

	// Build CPU info
	var cpuModel string
	var cpuCores int
	if len(cpuInfo) > 0 {
		cpuModel = cpuInfo[0].ModelName
		cpuCores = int(cpuInfo[0].Cores)
	}

	// Build network interfaces and determine a primary IP
	var (
		networkInterfaces []types.NetworkInterface
		primaryIP         string
	)
	for _, iface := range interfaces {
		if len(iface.Addrs) == 0 {
			continue
		}
		addr := iface.Addrs[0].Addr
		networkInterfaces = append(networkInterfaces, types.NetworkInterface{
			Name: iface.Name,
			IP:   addr,
			MAC:  iface.HardwareAddr,
		})
		if primaryIP == "" {
			// Prefer a non-loopback IPv4 address if available
			if ip := extractPrimaryIP(addr); ip != "" {
				primaryIP = ip
			}
		}
	}

	// Convert bytes to GB
	totalMemoryGB := float64(memInfo.Total) / (1024 * 1024 * 1024)
	storageTotalGB := float64(diskInfo.Total) / (1024 * 1024 * 1024)

	hardwareInfo := &types.HardwareInfo{
		CPU: types.CPUInfo{
			Model: cpuModel,
			Cores: cpuCores,
			Arch:  runtime.GOARCH,
		},
		Memory: types.MemoryInfo{
			Total: memInfo.Total,
		},
		Storage: types.StorageInfo{
			Total: diskInfo.Total,
			Type:  "unknown", // Could be enhanced to detect SSD/HDD
		},
		Network: types.NetworkInfo{
			Interfaces: networkInterfaces,
		},
		OS: types.OSInfo{
			Name:    hostInfo.Platform,
			Version: hostInfo.PlatformVersion,
			Kernel:  hostInfo.KernelVersion,
		},
		Hostname:  hostInfo.Hostname,
		PrimaryIP: primaryIP,
		// New fields for server information
		PublicIP:         publicIP,
		CPUPhysicalCores: physicalCount,
		CPULogicalCount:  logicalCount,
		TotalMemoryGB:    totalMemoryGB,
		StorageTotalGB:   storageTotalGB,
	}

	return hardwareInfo, nil
}

func extractPrimaryIP(addr string) string {
	if addr == "" {
		return ""
	}
	value := addr
	if idx := strings.Index(addr, "/"); idx >= 0 {
		value = addr[:idx]
	}
	ip := stdnet.ParseIP(strings.TrimSpace(value))
	if ip == nil {
		return ""
	}
	if ip.IsLoopback() {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

// GetDiskUsage returns disk usage information
func (s *SystemServiceImpl) GetDiskUsage(ctx context.Context) (*types.DiskMetrics, error) {
	diskInfo, err := disk.Usage("/")
	if err != nil {
		return nil, fmt.Errorf("failed to get disk usage: %w", err)
	}

	return &types.DiskMetrics{
		Total: diskInfo.Total,
		Used:  diskInfo.Used,
		Free:  diskInfo.Free,
		Usage: diskInfo.UsedPercent,
	}, nil
}

// GetNetworkInfo returns network interface information
func (s *SystemServiceImpl) GetNetworkInfo(ctx context.Context) (*types.NetworkInfo, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to get network interfaces: %w", err)
	}

	var networkInterfaces []types.NetworkInterface
	for _, iface := range interfaces {
		if len(iface.Addrs) > 0 {
			networkInterfaces = append(networkInterfaces, types.NetworkInterface{
				Name: iface.Name,
				IP:   iface.Addrs[0].Addr,
				MAC:  iface.HardwareAddr,
			})
		}
	}

	return &types.NetworkInfo{
		Interfaces: networkInterfaces,
	}, nil
}

// commandExists checks if a command exists in PATH
func (s *SystemServiceImpl) commandExists(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}
