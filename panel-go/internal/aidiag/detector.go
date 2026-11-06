package aidiag

import (
	"context"
	"fmt"
	"strings"

	"paylater-mon/internal/models"
	"paylater-mon/internal/servercore"
)

const (
	cpuThreshold    = 90.0
	memoryThreshold = 90.0
	diskThreshold   = 90.0
)

// Detector — обнаружение проблем серверов и контейнеров.
type Detector struct {
	serverCore *servercore.Service
}

// NewDetector создаёт детектор проблем.
func NewDetector(sc *servercore.Service) *Detector {
	return &Detector{serverCore: sc}
}

// Detect собирает список текущих проблем.
func (d *Detector) Detect(ctx context.Context) []Detection {
	var problems []Detection
	if !d.serverCore.IsMonitoringEnabled(ctx) {
		return problems
	}
	servers := d.serverCore.GetServersWithMetrics(ctx)
	for _, s := range servers {
		if !s.IsAvailable() {
			problems = append(problems, Detection{
				ServerName: s.Name, ServerIP: s.IpAddress, Env: envFromName(s.Name),
				Type: "ServerOffline", Severity: "critical",
				Title:       fmt.Sprintf("Сервер недоступен: %s", s.Name),
				Description: fmt.Sprintf("Статус сервера: %s. Сервер не отвечает.", s.Status),
				Context:     buildMetricsContext(s),
			})
		}
		if s.CpuUsagePercent >= cpuThreshold {
			problems = append(problems, Detection{
				ServerName: s.Name, ServerIP: s.IpAddress, Env: envFromName(s.Name),
				Type: "HighCpu", Severity: "critical",
				Title:       fmt.Sprintf("Высокая загрузка CPU: %.1f%% на %s", s.CpuUsagePercent, s.Name),
				Description: fmt.Sprintf("CPU usage %.1f%% превышает порог %.0f%%.", s.CpuUsagePercent, cpuThreshold),
				Context:     buildMetricsContext(s),
			})
		}
		if s.MemoryUsagePercent >= memoryThreshold {
			problems = append(problems, Detection{
				ServerName: s.Name, ServerIP: s.IpAddress, Env: envFromName(s.Name),
				Type: "HighMemory", Severity: "critical",
				Title:       fmt.Sprintf("Высокое использование RAM: %.1f%% на %s", s.MemoryUsagePercent, s.Name),
				Description: fmt.Sprintf("Memory usage %.1f%% (used %.1f/%.1f GB) превышает порог %.0f%%.", s.MemoryUsagePercent, s.MemoryUsedGB, s.MemoryTotalGB, memoryThreshold),
				Context:     buildMetricsContext(s),
			})
		}
		if s.DiskUsagePercent >= diskThreshold {
			problems = append(problems, Detection{
				ServerName: s.Name, ServerIP: s.IpAddress, Env: envFromName(s.Name),
				Type: "HighDisk", Severity: "critical",
				Title:       fmt.Sprintf("Мало места на диске: %.1f%% на %s", s.DiskUsagePercent, s.Name),
				Description: fmt.Sprintf("Disk usage %.1f%% (used %.1f/%.1f GB) превышает порог %.0f%%.", s.DiskUsagePercent, s.DiskUsedGB, s.DiskTotalGB, diskThreshold),
				Context:     buildMetricsContext(s),
			})
		}
	}
	// Проблемы контейнеров
	for _, host := range servers {
		if host.TotalContainers == 0 && host.RunningContainers == 0 {
			continue
		}
		containers, err := d.serverCore.GetContainers(ctx, host.Name)
		if err != nil {
			continue
		}
		for _, c := range containers {
			if c.Running {
				continue
			}
			isDown := c.State == "exited" || c.State == "stopped" || c.State == "dead"
			problemType := "ContainerUnhealthy"
			severity := "warning"
			if isDown {
				problemType = "ContainerDown"
				severity = "critical"
			}
			label := "нездоров"
			if isDown {
				label = "упал"
			}
			problems = append(problems, Detection{
				ServerName: host.Name, ServerIP: host.IpAddress, Env: envFromName(host.Name),
				Type: problemType, Severity: severity,
				Title:       fmt.Sprintf("Контейнер %s: %s на %s", label, c.Name, host.Name),
				Description: fmt.Sprintf("Контейнер «%s» (%s) — состояние: %s.", c.Name, c.Image, c.Status),
				Context:     fmt.Sprintf("Server: %s (%s), container: %s, state=%s", host.IpAddress, host.OperatingSystem, c.Name, c.Status),
			})
		}
	}
	return problems
}

// GetServerContext возвращает контекст метрик сервера для ручной диагностики.
func (d *Detector) GetServerContext(ctx context.Context, serverName string) string {
	servers, _ := d.serverCore.GetServers(ctx)
	for _, s := range servers {
		if strings.EqualFold(s.Name, serverName) || strings.EqualFold(s.Title, serverName) {
			return buildMetricsContext(s)
		}
	}
	return fmt.Sprintf("Сервер: %s (не найден в ServerCore)", serverName)
}

func buildMetricsContext(s models.ServerHost) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Server: %s\n", s.Name))
	if s.IpAddress != "" {
		sb.WriteString(fmt.Sprintf("IP: %s\n", s.IpAddress))
	}
	if s.Status != "" {
		sb.WriteString(fmt.Sprintf("Status: %s\n", s.Status))
	}
	if s.OperatingSystem != "" {
		sb.WriteString(fmt.Sprintf("OS: %s\n", s.OperatingSystem))
	}
	if s.CpuUsagePercent > 0 {
		sb.WriteString(fmt.Sprintf("CPU usage: %.1f%%\n", s.CpuUsagePercent))
	}
	if s.CpuCores > 0 {
		sb.WriteString(fmt.Sprintf("CPU cores: %d\n", s.CpuCores))
	}
	if s.MemoryUsagePercent > 0 {
		sb.WriteString(fmt.Sprintf("RAM usage: %.1f%% (used %.1f/%.1f GB)\n", s.MemoryUsagePercent, s.MemoryUsedGB, s.MemoryTotalGB))
	}
	if s.DiskUsagePercent > 0 {
		sb.WriteString(fmt.Sprintf("Disk usage: %.1f%% (used %.1f/%.1f GB)\n", s.DiskUsagePercent, s.DiskUsedGB, s.DiskTotalGB))
	}
	if s.Uptime != "" {
		sb.WriteString(fmt.Sprintf("Uptime: %s\n", s.Uptime))
	}
	if s.RunningContainers > 0 || s.TotalContainers > 0 {
		sb.WriteString(fmt.Sprintf("Containers: running %d / total %d\n", s.RunningContainers, s.TotalContainers))
	}
	return sb.String()
}

func envFromName(name string) string {
	l := strings.ToLower(name)
	switch {
	case strings.Contains(l, "prod"):
		return "prod"
	case strings.Contains(l, "test"):
		return "test"
	case strings.Contains(l, "adm"):
		return "adm"
	}
	return "other"
}
