// Package models — общие модели данных панели мониторинга.
package models

import (
	"time"
)

// ServerHost — модель сервера из Servercore API (Nova) с метриками.
type ServerHost struct {
	ID                 string  `json:"id"`
	Name               string  `json:"name"`
	Title              string  `json:"title"`
	Status             string  `json:"status"`
	IpAddress          string  `json:"ip_address"`
	Location           string  `json:"location"`
	OperatingSystem    string  `json:"operating_system"`
	TrafficType        string  `json:"traffic_type"`
	CpuUsagePercent    float64 `json:"cpu_usage_percent"`
	CpuCores           int     `json:"cpu_cores"`
	MemoryTotalGB      float64 `json:"memory_total_gb"`
	MemoryUsedGB       float64 `json:"memory_used_gb"`
	MemoryUsagePercent float64 `json:"memory_usage_percent"`
	DiskTotalGB        float64 `json:"disk_total_gb"`
	DiskUsedGB         float64 `json:"disk_used_gb"`
	DiskUsagePercent   float64 `json:"disk_usage_percent"`
	Uptime             string  `json:"uptime"`
	RunningContainers  int     `json:"running_containers"`
	TotalContainers    int     `json:"total_containers"`
}

// IsAvailable — доступен ли сервер.
func (s *ServerHost) IsAvailable() bool {
	switch lower(s.Status) {
	case "active", "started", "running":
		return true
	}
	return false
}

// Container — Docker-контейнер с метриками.
type Container struct {
	ID             string  `json:"id"`
	Name           string  `json:"name"`
	Image          string  `json:"image"`
	Status         string  `json:"status"`
	State          string  `json:"state"`
	Running        bool    `json:"running"`
	CreatedAt      string  `json:"created_at"`
	StartedAt      string  `json:"started_at"`
	RestartCount   int     `json:"restart_count"`
	CpuPercent     float64 `json:"cpu_percent"`
	MemoryUsageMB  float64 `json:"memory_usage_mb"`
	MemoryLimitMB  float64 `json:"memory_limit_mb"`
	MemoryPercent  float64 `json:"memory_percent"`
	NetworkRxBytes float64 `json:"network_rx_bytes"`
	NetworkTxBytes float64 `json:"network_tx_bytes"`
}

// ContainerNetwork — Docker-сеть с подключёнными контейнерами (пункт 12).
type ContainerNetwork struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Driver     string   `json:"driver"`
	Scope      string   `json:"scope"`
	Containers []string `json:"containers"`
}

// VmTemplate — образ ОС для создания ВМ.
type VmTemplate struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	OperatingSystem string `json:"operating_system"`
	Version         string `json:"version"`
	Description     string `json:"description"`
	Size            int64  `json:"size"`
	Status          string `json:"status"`
}

// VmPreset — конфигурация (тариф) ВМ.
type VmPreset struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Cpu         int    `json:"cpu"`
	RamMb       int    `json:"ram_mb"`
	DiskGb      int    `json:"disk_gb"`
	Description string `json:"description"`
}

// VmNetwork — сеть для создания ВМ (Neutron).
type VmNetwork struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	SubnetID string `json:"subnet_id"`
	Status   string `json:"status"`
}

// VmSecurityGroup — группа безопасности для создания ВМ.
type VmSecurityGroup struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// VmKeyPair — SSH-ключ для создания ВМ.
type VmKeyPair struct {
	Name        string `json:"name"`
	Fingerprint string `json:"fingerprint"`
}

// VmCreateRequest — запрос на создание ВМ.
type VmCreateRequest struct {
	Name            string `json:"name"`
	TemplateID      string `json:"template_id"`
	OsID            string `json:"os_id"`
	Cpu             int    `json:"cpu"`
	RamMb           int    `json:"ram_mb"`
	DiskGb          int    `json:"disk_gb"`
	Location        string `json:"location"`
	Comment         string `json:"comment"`
	NetworkID       string `json:"network_id"`
	SecurityGroupID string `json:"security_group_id"`
	KeyPairName     string `json:"key_pair_name"`
}

// VmOperationResult — результат операции с ВМ.
type VmOperationResult struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	VmID    string `json:"vm_id"`
}

// GraylogClusterNode — нода кластера Graylog.
type GraylogClusterNode struct {
	NodeID             string `json:"node_id"`
	ShortNodeID        string `json:"short_node_id"`
	Hostname           string `json:"hostname"`
	IsMaster           bool   `json:"is_master"`
	ProcessingMessages int64  `json:"processing_message_count"`
	LastStatusUpdate   string `json:"last_status_report"`
	Throughput         int64  `json:"throughput"`
	Lifecycle          string `json:"lifecycle"`
	Type               string `json:"type"`
}

// GraylogStream — stream Graylog.
type GraylogStream struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Disabled    bool   `json:"disabled"`
}

// GraylogMessage — сообщение из поиска логов.
type GraylogMessage struct {
	Timestamp string `json:"timestamp"`
	Source    string `json:"source"`
	Level     string `json:"level"`
	Message   string `json:"message"`
	Index     string `json:"index"`
}

// GraylogSearchResult — результат поиска логов.
type GraylogSearchResult struct {
	Total    int64            `json:"total"`
	Messages []GraylogMessage `json:"messages"`
	Error    string           `json:"error,omitempty"`
}

// ZeebeMetrics — метрики Zeebe из Prometheus.
type ZeebeMetrics struct {
	IsConnected     bool                          `json:"is_connected"`
	ErrorMessage    string                        `json:"error_message"`
	Counters        map[string]float64            `json:"counters"`
	Gauges          map[string]float64            `json:"gauges"`
	CountersByLabel map[string]map[string]float64 `json:"counters_by_label"`
	GaugesByLabel   map[string]map[string]float64 `json:"gauges_by_label"`
	Processors      []ZeebeProcessorMetric        `json:"processors"`
	Partitions      []ZeebePartitionMetric        `json:"partitions"`
}

type ZeebeProcessorMetric struct {
	Type      string `json:"type"`
	Partition int    `json:"partition"`
	Count     int64  `json:"count"`
	FullName  string `json:"full_name"`
}

type ZeebePartitionMetric struct {
	PartitionID      int    `json:"partition_id"`
	RecordsProcessed int64  `json:"records_processed"`
	LatencyCount     int64  `json:"latency_count"`
	BatchCount       int64  `json:"batch_count"`
	Role             string `json:"role"`
	IsHealthy        bool   `json:"is_healthy"`
}

// OperateProcessInstance — инстанс процесса из Operate API.
type OperateProcessInstance struct {
	Key                  int64  `json:"key"`
	ProcessDefinitionKey int64  `json:"processDefinitionKey"`
	BpmnProcessID        string `json:"bpmnProcessId"`
	ProcessVersion       int    `json:"processVersion"`
	State                string `json:"state"`
	StartDate            string `json:"startDate"`
	EndDate              string `json:"endDate"`
	Incident             bool   `json:"incident"`
	TenantID             string `json:"tenantId"`
	ParentKey            int64  `json:"parentKey"`
}

// ProcessInstanceInfo — расширенная информация об инстансе.
type ProcessInstanceInfo struct {
	Key                  int64     `json:"key"`
	ProcessDefinitionKey int64     `json:"process_definition_key"`
	BpmnProcessID        string    `json:"bpmn_process_id"`
	ProcessVersion       int       `json:"process_version"`
	State                string    `json:"state"`
	StartDate            time.Time `json:"start_date"`
	EndDate              time.Time `json:"end_date"`
	HasIncident          bool      `json:"has_incident"`
	IsStuck              bool      `json:"is_stuck"`
	TenantID             string    `json:"tenant_id"`
	ParentKey            int64     `json:"parent_key"`
}

// RunningDuration — строка длительности работы.
func (p *ProcessInstanceInfo) RunningDurationFormatted() string {
	if p.StartDate.IsZero() {
		return ""
	}
	d := time.Since(p.StartDate)
	if d < 0 {
		d = 0
	}
	return FormatDuration(d)
}

func FormatDuration(d time.Duration) string {
	if d >= 24*time.Hour {
		return fmtInt(int(d.Hours()/24)) + "д " + fmtInt(int(d.Hours())%24) + "ч " + fmtInt(int(d.Minutes())%60) + "м"
	}
	if d >= time.Hour {
		return fmtInt(int(d.Hours())) + "ч " + fmtInt(int(d.Minutes())%60) + "м"
	}
	if d >= time.Minute {
		return fmtInt(int(d.Minutes())) + "м " + fmtInt(int(d.Seconds())%60) + "с"
	}
	return fmtInt(int(d.Seconds())) + "с"
}

// Incident — запись локальной истории инцидентов.
type Incident struct {
	Type      string    `json:"type"`
	Host      string    `json:"host"`
	Detail    string    `json:"detail"`
	Status    string    `json:"status"`
	Timestamp time.Time `json:"timestamp"`
}
