// Package servercore — мониторинг серверов и контейнеров через Servercore API
// (IAM-токен через Keystone, Nova compute, SSH для docker ps).
package servercore

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"paylater-mon/internal/config"
	"paylater-mon/internal/models"
	"paylater-mon/internal/sshclient"
)

// IamAuthURL — эндпоинт Keystone для получения project-scoped IAM-токена.
const IamAuthURL = "https://cloud.api.servercore.com/identity/v3/auth/tokens"

// Service — интеграция с Servercore.
type Service struct {
	cfg  *config.Config
	http *http.Client
	log  Logger

	mu        sync.Mutex
	iamToken  string
	iamExpiry time.Time
	computeEp string
	glanceEp  string
	neutronEp string
	projectID string

	passMu    sync.Mutex
	passCache map[string]string

	// Кэш реальных метрик (CPU/RAM/Disk через SSH) для GetServersWithMetrics.
	metricsMu   sync.Mutex
	realMetrics map[string]realMetricEntry

	// TTL-кэш для GetServers/GetContainers (пункт 2 IMPROVEMENTS.md).
	cacheMu        sync.Mutex
	serversCache   []models.ServerHost
	serversAt      time.Time
	containerCache map[string]containerCacheEntry
}

type containerCacheEntry struct {
	containers []models.Container
	at         time.Time
}

type realMetricEntry struct {
	m  *models.ServerHost
	at time.Time
}

// Кэш-константы.
const (
	serversCacheTTL    = 30 * time.Second
	containersCacheTTL = 15 * time.Second
	realMetricsTTL     = 60 * time.Second
)

// Logger — минимальный логгер.
type Logger interface {
	Infof(format string, args ...interface{})
	Warnf(format string, args ...interface{})
	Errorf(format string, args ...interface{})
}

// New создаёт сервис Servercore.
func New(cfg *config.Config, log Logger) *Service {
	return &Service{
		cfg:            cfg,
		http:           &http.Client{Timeout: 30 * time.Second},
		log:            log,
		passCache:      make(map[string]string),
		containerCache: make(map[string]containerCacheEntry),
		realMetrics:    make(map[string]realMetricEntry),
	}
}

// ApplyConfig обновляет конфигурацию на лету (без перезапуска).
func (s *Service) ApplyConfig(cfg *config.Config) {
	s.mu.Lock()
	s.cfg = cfg
	s.iamToken = ""
	s.iamExpiry = time.Time{}
	s.computeEp = ""
	s.mu.Unlock()
}

// InvalidateCaches сбрасывает TTL-кэши (вызывается при изменении конфигурации/перезагрузке).
func (s *Service) InvalidateCaches() {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	s.serversCache = nil
	s.serversAt = time.Time{}
	s.containerCache = make(map[string]containerCacheEntry)
	s.metricsMu.Lock()
	s.realMetrics = make(map[string]realMetricEntry)
	s.metricsMu.Unlock()
}

// IsMonitoringEnabled — мониторинг включён, если удалось получить IAM-токен.
func (s *Service) IsMonitoringEnabled(ctx context.Context) bool {
	tok, err := s.GetIamToken(ctx)
	return err == nil && tok != ""
}

// GetIamToken получает (и кэширует) project-scoped IAM-токен через Keystone.
func (s *Service) GetIamToken(ctx context.Context) (string, error) {
	s.mu.Lock()
	if s.iamToken != "" && time.Now().Before(s.iamExpiry) {
		tok := s.iamToken
		s.mu.Unlock()
		return tok, nil
	}
	s.mu.Unlock()

	sc := s.cfg.ServerCore
	if sc.IamUsername == "" || sc.IamPassword == "" {
		return "", fmt.Errorf("servercore: IAM credentials not set")
	}

	payload := map[string]interface{}{
		"auth": map[string]interface{}{
			"identity": map[string]interface{}{
				"methods": []string{"password"},
				"password": map[string]interface{}{
					"user": map[string]interface{}{
						"name":     sc.IamUsername,
						"domain":   map[string]interface{}{"name": sc.IamDomainName},
						"password": sc.IamPassword,
					},
				},
			},
		},
	}
	if sc.IamProjectID != "" {
		payload["auth"].(map[string]interface{})["scope"] = map[string]interface{}{
			"project": map[string]interface{}{"id": sc.IamProjectID},
		}
	}

	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		body, _ := json.Marshal(payload)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, IamAuthURL, bytes.NewReader(body))
		if err != nil {
			return "", err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")

		resp, err := s.http.Do(req)
		if err != nil {
			lastErr = err
			time.Sleep(time.Duration(1+attempt) * time.Second)
			continue
		}
		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode == http.StatusUnauthorized {
			lastErr = fmt.Errorf("servercore: IAM auth rejected (401)")
			time.Sleep(time.Duration(1+attempt) * time.Second)
			continue
		}
		if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("servercore: IAM auth HTTP %d: %s", resp.StatusCode, truncate(string(respBody), 300))
		}

		token := resp.Header.Get("X-Subject-Token")
		if token == "" {
			return "", fmt.Errorf("servercore: IAM response missing X-Subject-Token")
		}

		s.parseKeystoneResponse(respBody)
		s.mu.Lock()
		s.iamToken = token
		s.iamExpiry = time.Now().Add(time.Hour)
		s.mu.Unlock()
		return token, nil
	}
	return "", lastErr
}

func (s *Service) parseKeystoneResponse(body []byte) {
	var doc struct {
		Token struct {
			Project struct {
				ID string `json:"id"`
			} `json:"project"`
			Catalog []struct {
				Type      string `json:"type"`
				Endpoints []struct {
					Interface string `json:"interface"`
					URL       string `json:"url"`
				} `json:"endpoints"`
			} `json:"catalog"`
		} `json:"token"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return
	}
	if doc.Token.Project.ID != "" {
		s.projectID = doc.Token.Project.ID
	}
	for _, svc := range doc.Token.Catalog {
		for _, ep := range svc.Endpoints {
			if ep.Interface != "public" || ep.URL == "" {
				continue
			}
			url := strings.TrimRight(ep.URL, "/")
			switch svc.Type {
			case "compute":
				if s.computeEp == "" {
					s.computeEp = url
				}
			case "image":
				if s.glanceEp == "" {
					s.glanceEp = url
				}
			case "network":
				if s.neutronEp == "" {
					s.neutronEp = url
				}
			}
		}
	}
}

// glanceEndpoint возвращает эндпоинт Glance (для получения образов ОС).
func (s *Service) glanceEndpoint() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.glanceEp
}

// neutronEndpoint возвращает эндпоинт Neutron (для сетей).
func (s *Service) neutronEndpoint() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.neutronEp
}

// sendIAM выполняет запрос с авторизацией IAM и повторяет один раз при 401.
func (s *Service) sendIAM(ctx context.Context, method, url string, payload []byte) (*http.Response, error) {
	token, err := s.GetIamToken(ctx)
	if err != nil || token == "" {
		return nil, fmt.Errorf("servercore: no IAM token: %v", err)
	}

	do := func(tok string) (*http.Response, error) {
		var body io.Reader
		if payload != nil {
			body = bytes.NewReader(payload)
		}
		req, err := http.NewRequestWithContext(ctx, method, url, body)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("X-Auth-Token", tok)
		req.Header.Set("Accept", "application/json")
		if payload != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		return s.http.Do(req)
	}

	resp, err := do(token)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		resp.Body.Close()
		s.mu.Lock()
		s.iamToken = ""
		s.iamExpiry = time.Time{}
		s.computeEp = ""
		s.mu.Unlock()
		newTok, err := s.GetIamToken(ctx)
		if err == nil && newTok != "" {
			return do(newTok)
		}
		return resp, nil
	}
	return resp, nil
}

// GetServers получает список активных серверов (исключая выведенные из
// эксплуатации и группы с monitored=false) через Nova compute API (с TTL-кэшем 30с).
func (s *Service) GetServers(ctx context.Context) ([]models.ServerHost, error) {
	all, err := s.GetAllServers(ctx)
	if err != nil {
		return nil, err
	}
	return s.filterMonitored(all), nil
}

// GetAllServers возвращает ВСЕ серверы, включая выведенные из эксплуатации.
// Используется для отображения секции «Выведены из эксплуатации» на странице
// «Серверы» (с TTL-кэшем 30с).
func (s *Service) GetAllServers(ctx context.Context) ([]models.ServerHost, error) {
	s.cacheMu.Lock()
	if s.serversCache != nil && time.Since(s.serversAt) < serversCacheTTL {
		cached := s.serversCache
		s.cacheMu.Unlock()
		return cached, nil
	}
	s.cacheMu.Unlock()

	servers := s.getServersUncached(ctx)

	s.cacheMu.Lock()
	s.serversCache = servers
	s.serversAt = time.Now()
	s.cacheMu.Unlock()
	return servers, nil
}

// filterMonitored оставляет только серверы, подлежащие мониторингу:
// исключает выведенные из эксплуатации (excluded_servers) и группы с monitored=false.
func (s *Service) filterMonitored(hosts []models.ServerHost) []models.ServerHost {
	var out []models.ServerHost
	for _, h := range hosts {
		if _, monitored := s.CategorizeServer(h.Name, h.IpAddress); monitored {
			out = append(out, h)
		}
	}
	return out
}

// CategorizeServer определяет группу и статус мониторинга сервера по имени.
// Приоритет: excluded_servers → server_groups → "Прочие" (monitored=true).
func (s *Service) CategorizeServer(name, ip string) (group string, monitored bool) {
	// 1. Выведенные из эксплуатации — высший приоритет.
	if s.IsServerExcluded(name, ip) {
		return "Выведены из эксплуатации", false
	}
	// 2. Группы по шаблону имени.
	lower := strings.ToLower(name)
	for _, g := range s.cfg.ServerCore.ServerGroups {
		if g.Pattern == "" {
			continue
		}
		if strings.Contains(lower, strings.ToLower(g.Pattern)) {
			return g.Name, g.Monitored
		}
	}
	// 3. Прочие — мониторим по умолчанию.
	return "Прочие", true
}

// ServerGroupDisplay — группа серверов для UI.
type ServerGroupDisplay struct {
	Name      string
	Monitored bool
	Servers   []models.ServerHost
}

// GetServersGrouped возвращает все серверы, сгруппированные по категориям.
// Мониторируемые группы обогащаются метриками из GetServersWithMetrics.
func (s *Service) GetServersGrouped(ctx context.Context) []ServerGroupDisplay {
	all, _ := s.GetAllServers(ctx)
	// Метрики для мониторируемых серверов.
	withMetrics := s.GetServersWithMetrics(ctx)
	metricsMap := make(map[string]models.ServerHost, len(withMetrics))
	for _, m := range withMetrics {
		metricsMap[m.Name] = m
	}

	order := []string{}
	groups := map[string]*ServerGroupDisplay{}
	for _, h := range all {
		grp, mon := s.CategorizeServer(h.Name, h.IpAddress)
		// Если есть метрики — используем обогащённую запись.
		if mm, ok := metricsMap[h.Name]; ok {
			h = mm
		}
		gd, ok := groups[grp]
		if !ok {
			gd = &ServerGroupDisplay{Name: grp, Monitored: mon}
			groups[grp] = gd
			order = append(order, grp)
		}
		gd.Servers = append(gd.Servers, h)
	}

	out := make([]ServerGroupDisplay, 0, len(order))
	for _, name := range order {
		out = append(out, *groups[name])
	}
	return out
}

// GetServersWithMetrics возвращает серверы с РЕАЛЬНЫМИ метриками CPU/RAM/Disk,
// собранными через SSH (с TTL-кэшем realMetricsTTL).
func (s *Service) GetServersWithMetrics(ctx context.Context) []models.ServerHost {
	servers, _ := s.GetServers(ctx)
	out := make([]models.ServerHost, len(servers))
	copy(out, servers)

	var wg sync.WaitGroup
	var sem = make(chan struct{}, 4)
	for i := range out {
		sv := &out[i]
		if !sv.IsAvailable() {
			continue
		}
		if m := s.realMetricsCached(sv.Name); m != nil {
			applyServerMetrics(sv, m)
			continue
		}
		wg.Add(1)
		go func(h *models.ServerHost) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			m, err := s.GetServerMetrics(ctx, h.Name)
			if err != nil || m == nil {
				return
			}
			s.cacheRealMetrics(h.Name, m)
			applyServerMetrics(h, m)
		}(sv)
	}
	wg.Wait()
	return out
}

// applyServerMetrics переносит реальные метрики из источника в целевую запись.
func applyServerMetrics(dst *models.ServerHost, src *models.ServerHost) {
	if src.CpuUsagePercent > 0 {
		dst.CpuUsagePercent = src.CpuUsagePercent
	}
	if src.CpuCores > 0 {
		dst.CpuCores = src.CpuCores
	}
	if src.MemoryUsagePercent > 0 {
		dst.MemoryUsagePercent = src.MemoryUsagePercent
	}
	if src.MemoryUsedGB > 0 {
		dst.MemoryUsedGB = src.MemoryUsedGB
	}
	if src.MemoryTotalGB > 0 {
		dst.MemoryTotalGB = src.MemoryTotalGB
	}
	if src.DiskUsagePercent > 0 {
		dst.DiskUsagePercent = src.DiskUsagePercent
	}
	if src.DiskUsedGB > 0 {
		dst.DiskUsedGB = src.DiskUsedGB
	}
	if src.DiskTotalGB > 0 {
		dst.DiskTotalGB = src.DiskTotalGB
	}
	if src.Uptime != "" {
		dst.Uptime = src.Uptime
	}
	dst.RunningContainers = src.RunningContainers
	dst.TotalContainers = src.TotalContainers
}

// realMetricsCached возвращает копию закэшированных метрик, если они свежие.
func (s *Service) realMetricsCached(name string) *models.ServerHost {
	s.metricsMu.Lock()
	defer s.metricsMu.Unlock()
	if e, ok := s.realMetrics[name]; ok && time.Since(e.at) < realMetricsTTL {
		m := *e.m
		return &m
	}
	return nil
}

// cacheRealMetrics сохраняет реальные метрики сервера.
func (s *Service) cacheRealMetrics(name string, m *models.ServerHost) {
	s.metricsMu.Lock()
	defer s.metricsMu.Unlock()
	c := *m
	s.realMetrics[name] = realMetricEntry{m: &c, at: time.Now()}
}

func (s *Service) getServersUncached(ctx context.Context) []models.ServerHost {
	if !s.IsMonitoringEnabled(ctx) {
		return []models.ServerHost{}
	}
	ep := s.computeEndpoint()
	if ep == "" {
		return []models.ServerHost{}
	}

	for _, path := range []string{"/servers/detail", "/servers"} {
		resp, err := s.sendIAM(ctx, http.MethodGet, ep+path, nil)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			continue
		}
		hosts := parseNovaServers(body)
		if len(hosts) > 0 {
			s.enrichWithNova(ctx, hosts, ep)
			return hosts
		}
	}
	return []models.ServerHost{}
}

// IsServerExcluded — исключён ли сервер (по имени или IP) из мониторинга.
func (s *Service) IsServerExcluded(name, ip string) bool {
	for _, e := range s.cfg.ServerCore.ExcludedServers {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if strings.EqualFold(name, e) || strings.EqualFold(strings.TrimSpace(ip), e) {
			return true
		}
	}
	return false
}

func (s *Service) computeEndpoint() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.computeEp
}

// FindServerName находит имя сервера по шаблону "uz-{env}-{role}".
// Fallback: сервер, в имени которого встречается роль (например "camunda").
func (s *Service) FindServerName(ctx context.Context, env, role string) (string, error) {
	servers, err := s.GetServers(ctx)
	if err != nil {
		return "", err
	}
	prefix := "uz-" + env + "-" + role
	roleLower := strings.ToLower(role)
	for _, sv := range servers {
		if strings.HasPrefix(strings.ToLower(sv.Name), strings.ToLower(prefix)) {
			return sv.Name, nil
		}
	}
	// Fallback: сервер, в имени которого встречается роль.
	for _, sv := range servers {
		if strings.Contains(strings.ToLower(sv.Name), roleLower) {
			return sv.Name, nil
		}
	}
	return "", nil
}

// RunSSHCommand выполняет произвольную команду на сервере через SSH (публичный API
// для модулей tlsscan и т.п.). Подключение устанавливается заново при каждом вызове.
func (s *Service) RunSSHCommand(ctx context.Context, serverName, command string) (string, error) {
	client, err := s.getSshClient(ctx, serverName)
	if err != nil {
		return "", err
	}
	defer client.Close()
	return client.RunContext(ctx, command)
}

// GetSSHClient возвращает подключённый SSH-клиент для сервера (публичный API
// для встроенного TLS-сканера: соединение переиспользуется на все порты/версии).
func (s *Service) GetSSHClient(ctx context.Context, serverName string) (*sshclient.Client, error) {
	return s.getSshClient(ctx, serverName)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
