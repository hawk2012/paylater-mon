// Package zeebe — метрики Zeebe через SSH-туннель (Prometheus) + Operate API.
package zeebe

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"paylater-mon/internal/config"
	"paylater-mon/internal/models"
	"paylater-mon/internal/servercore"

	"golang.org/x/crypto/ssh"
)

// Service — Zeebe метрики и процессы через SSH-туннель.
type Service struct {
	cfg        *config.Config
	serverCore *servercore.Service
	http       *http.Client

	mu        sync.Mutex
	sshClient *ssh.Client
	targetEnv string
}

// New создаёт сервис Zeebe.
func New(cfg *config.Config, sc *servercore.Service) *Service {
	return &Service{cfg: cfg, serverCore: sc, http: &http.Client{Timeout: 30 * time.Second}}
}

// ApplyConfig обновляет конфигурацию на лету (без перезапуска).
func (s *Service) ApplyConfig(cfg *config.Config) {
	s.mu.Lock()
	s.cfg = cfg
	s.mu.Unlock()
}

// EnvURL возвращает URL Zeebe для заданного окружения (пункт 23).
// Приоритет: ProdURL/TestURL (multi-env), затем общий URL.
func (s *Service) EnvURL(env string) string {
	if env == "test" && s.cfg.Zeebe.TestURL != "" {
		return s.cfg.Zeebe.TestURL
	}
	if env == "prod" && s.cfg.Zeebe.ProdURL != "" {
		return s.cfg.Zeebe.ProdURL
	}
	return s.cfg.Zeebe.URL
}

// AvailableEnvs возвращает список доступных окружений.
func (s *Service) AvailableEnvs() []string {
	var envs []string
	if s.cfg.Zeebe.ProdURL != "" || s.cfg.Zeebe.URL != "" {
		envs = append(envs, "prod")
	}
	if s.cfg.Zeebe.TestURL != "" {
		envs = append(envs, "test")
	}
	if len(envs) == 0 {
		envs = []string{"prod"}
	}
	return envs
}

// SetTargetEnv устанавливает окружение (prod/test) для подключения.
func (s *Service) SetTargetEnv(env string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.targetEnv != env {
		s.targetEnv = env
		s.closeTunnel()
	}
}

// GetTargetEnv возвращает текущее окружение (prod/test).
func (s *Service) GetTargetEnv() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.targetEnv
}

// zeebeServerName определяет SSH-сервер для туннеля Zeebe:
//  1. явный zeebe.server_name из конфига;
//  2. сервер, чей IP совпадает с хостом из URL окружения (EnvURL)
//     — надёжнее поиска по имени, т.к. в PROD используется uz-prod-camunda87-1
//     (172.31.32.69), а uz-prod-camunda-1 (172.31.32.61) выведен из эксплуатации;
//  3. fallback на FindServerName(env, "camunda").
func (s *Service) zeebeServerName(ctx context.Context, env string) (string, error) {
	if name := strings.TrimSpace(s.cfg.Zeebe.ServerName); name != "" {
		return name, nil
	}
	if u := s.EnvURL(env); u != "" {
		if host := extractHost(u); host != "" {
			servers, _ := s.serverCore.GetServers(ctx)
			for _, sv := range servers {
				if strings.EqualFold(strings.TrimSpace(sv.IpAddress), host) {
					return sv.Name, nil
				}
			}
		}
	}
	return s.serverCore.FindServerName(ctx, env, "camunda")
}

// extractHost возвращает хост (IP или имя) из URL.
func extractHost(rawURL string) string {
	u := strings.TrimSpace(rawURL)
	// Убираем схему.
	if i := strings.Index(u, "://"); i >= 0 {
		u = u[i+3:]
	}
	// Убираем путь.
	if i := strings.Index(u, "/"); i >= 0 {
		u = u[:i]
	}
	// IPv6 в скобках: "[::1]:8080".
	if strings.HasPrefix(u, "[") {
		if i := strings.Index(u, "]"); i >= 0 {
			return strings.TrimSpace(u[1:i])
		}
	}
	// Убираем порт.
	if i := strings.LastIndex(u, ":"); i >= 0 {
		host := u[:i]
		if host != "" {
			u = host
		}
	}
	return strings.TrimSpace(u)
}

// ensureTunnel устанавливает SSH-соединение для Zeebe-сервера.
func (s *Service) ensureTunnel(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sshClient != nil {
		// Проверяем живость.
		_, _, err := s.sshClient.SendRequest("keepalive@openssh.com", true, nil)
		if err == nil {
			return nil
		}
		s.closeTunnel()
	}

	env := s.targetEnv
	if env == "" {
		if strings.Contains(strings.ToLower(s.cfg.Zeebe.URL), "test") {
			env = "test"
		} else {
			env = "prod"
		}
	}
	serverName, err := s.zeebeServerName(ctx, env)
	if err != nil || serverName == "" {
		return fmt.Errorf("zeebe: camunda server not found for env %s", env)
	}
	servers, _ := s.serverCore.GetServers(ctx)
	var server *models.ServerHost
	for i := range servers {
		if strings.EqualFold(servers[i].Name, serverName) {
			server = &servers[i]
			break
		}
	}
	if server == nil || server.IpAddress == "" {
		return fmt.Errorf("zeebe: server %s has no IP", serverName)
	}
	user, pass := s.serverCore.GetServerCredentials(ctx, server.ID, server.Name)
	if pass == "" {
		return fmt.Errorf("zeebe: no SSH password for %s", serverName)
	}
	port := s.cfg.ServerCore.SshPort
	if port <= 0 {
		port = 22
	}
	sshCfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(pass)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}
	conn, err := ssh.Dial("tcp", net.JoinHostPort(server.IpAddress, strconv.Itoa(port)), sshCfg)
	if err != nil {
		return fmt.Errorf("zeebe: SSH dial %s: %v", server.IpAddress, err)
	}
	s.sshClient = conn
	return nil
}

func (s *Service) closeTunnel() {
	if s.sshClient != nil {
		s.sshClient.Close()
		s.sshClient = nil
	}
}

// dialThroughSSH возвращает http.Transport, туннелирующий TCP через SSH.
func (s *Service) dialThroughSSH(ctx context.Context, remoteHost string, remotePort int) (*http.Transport, error) {
	if err := s.ensureTunnel(ctx); err != nil {
		return nil, err
	}
	s.mu.Lock()
	client := s.sshClient
	s.mu.Unlock()
	if client == nil {
		return nil, fmt.Errorf("zeebe: SSH tunnel not active")
	}
	tr := &http.Transport{
		DialContext: func(_ context.Context, network, addr string) (net.Conn, error) {
			return client.Dial("tcp", fmt.Sprintf("%s:%d", remoteHost, remotePort))
		},
	}
	return tr, nil
}

// GetMetrics получает метрики Zeebe через Prometheus actuator.
func (s *Service) GetMetrics(ctx context.Context) (models.ZeebeMetrics, error) {
	m := models.ZeebeMetrics{
		Counters:        map[string]float64{},
		Gauges:          map[string]float64{},
		CountersByLabel: map[string]map[string]float64{},
		GaugesByLabel:   map[string]map[string]float64{},
	}
	tr, err := s.dialThroughSSH(ctx, "127.0.0.1", 9600)
	if err != nil {
		m.ErrorMessage = err.Error()
		return m, nil
	}
	hc := &http.Client{Transport: tr, Timeout: 15 * time.Second}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:9600/actuator/prometheus", nil)
	resp, err := hc.Do(req)
	if err != nil {
		m.ErrorMessage = err.Error()
		return m, nil
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		m.ErrorMessage = fmt.Sprintf("HTTP %d", resp.StatusCode)
		return m, nil
	}
	parsePrometheus(body, &m)
	m.IsConnected = true
	return m, nil
}

// GetActiveProcessInstancesCount — количество активных инстансов.
func (s *Service) GetActiveProcessInstancesCount(ctx context.Context) int64 {
	m, err := s.GetMetrics(ctx)
	if err != nil {
		return 0
	}
	for k, v := range m.Gauges {
		lk := strings.ToLower(k)
		if strings.Contains(lk, "running") || (strings.Contains(lk, "active") && strings.Contains(lk, "instance")) {
			return int64(v)
		}
	}
	return 0
}

// GetProcessInstances запрашивает Operate API (через SSH-туннель на порт Operate).
func (s *Service) GetProcessInstances(ctx context.Context, size int, withIncidents, stuckOnly *bool) ([]models.OperateProcessInstance, int, error) {
	operatePort := s.cfg.Zeebe.OperatePort
	if operatePort == 0 {
		operatePort = 8080
	}
	tr, err := s.dialThroughSSH(ctx, "127.0.0.1", operatePort)
	if err != nil {
		return nil, 0, err
	}
	hc := &http.Client{Transport: tr, Timeout: 15 * time.Second}

	filterObj := map[string]interface{}{"state": "ACTIVE"}
	sort := []map[string]string{{"field": "startDate", "order": "DESC"}}
	if withIncidents != nil && *withIncidents {
		filterObj["incident"] = true
	} else if stuckOnly != nil && *stuckOnly {
		threshold := s.cfg.Zeebe.StuckThresholdHours
		if threshold == 0 {
			threshold = 24
		}
		stuckDate := time.Now().UTC().Add(-time.Duration(threshold)*time.Hour).Format("2006-01-02T15:04:05.000") + "+0000"
		filterObj["startDate"] = "<" + stuckDate
		sort = []map[string]string{{"field": "startDate", "order": "ASC"}}
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"filter": filterObj,
		"size":   size,
		"sort":   sort,
	})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "http://127.0.0.1/v1/process-instances/search", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, 0, err
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("operate API HTTP %d", resp.StatusCode)
	}
	var doc struct {
		Items []models.OperateProcessInstance `json:"items"`
		Total int                             `json:"total"`
	}
	json.Unmarshal(body, &doc)
	return doc.Items, doc.Total, nil
}

// GetActiveProcesses — активные процессы.
func (s *Service) GetActiveProcesses(ctx context.Context, size int) []models.ProcessInstanceInfo {
	items, _, err := s.GetProcessInstances(ctx, size, nil, nil)
	if err != nil {
		return nil
	}
	return mapInstances(items, false, false)
}

// GetStuckProcesses — зависшие процессы.
func (s *Service) GetStuckProcesses(ctx context.Context, size int) []models.ProcessInstanceInfo {
	items, _, err := s.GetProcessInstances(ctx, size, nil, boolPtr(true))
	if err != nil {
		return nil
	}
	return mapInstances(items, false, true)
}

// GetProcessesWithIncidents — процессы с инцидентами.
func (s *Service) GetProcessesWithIncidents(ctx context.Context, size int) []models.ProcessInstanceInfo {
	items, _, err := s.GetProcessInstances(ctx, size, boolPtr(true), nil)
	if err != nil {
		return nil
	}
	return mapInstances(items, true, false)
}

func boolPtr(b bool) *bool { return &b }

func mapInstances(items []models.OperateProcessInstance, hasIncident, isStuck bool) []models.ProcessInstanceInfo {
	var list []models.ProcessInstanceInfo
	for _, item := range items {
		info := models.ProcessInstanceInfo{
			Key:                  item.Key,
			ProcessDefinitionKey: item.ProcessDefinitionKey,
			BpmnProcessID:        item.BpmnProcessID,
			ProcessVersion:       item.ProcessVersion,
			State:                item.State,
			HasIncident:          item.Incident || hasIncident,
			IsStuck:              isStuck,
			TenantID:             item.TenantID,
			ParentKey:            item.ParentKey,
		}
		info.StartDate = parseOperateDate(item.StartDate)
		info.EndDate = parseOperateDate(item.EndDate)
		list = append(list, info)
	}
	return list
}

func parseOperateDate(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	layouts := []string{"2006-01-02T15:04:05.000Z0700", time.RFC3339, "2006-01-02T15:04:05"}
	for _, l := range layouts {
		if t, err := time.Parse(l, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

// Close закрывает SSH-туннель.
func (s *Service) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closeTunnel()
}
