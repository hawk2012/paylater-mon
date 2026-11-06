package servercore

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"paylater-mon/internal/models"
	"paylater-mon/internal/sshclient"
)

// GetContainers получает Docker-контейнеры сервера через SSH (с TTL-кэшем 15с).
func (s *Service) GetContainers(ctx context.Context, serverName string) ([]models.Container, error) {
	// Проверяем кэш.
	s.cacheMu.Lock()
	if entry, ok := s.containerCache[serverName]; ok && time.Since(entry.at) < containersCacheTTL {
		cached := entry.containers
		s.cacheMu.Unlock()
		return cached, nil
	}
	s.cacheMu.Unlock()

	containers, err := s.getContainersUncached(ctx, serverName)
	if err != nil {
		return containers, err
	}

	// Сохраняем в кэш.
	s.cacheMu.Lock()
	s.containerCache[serverName] = containerCacheEntry{containers: containers, at: time.Now()}
	s.cacheMu.Unlock()
	return containers, nil
}

func (s *Service) getContainersUncached(ctx context.Context, serverName string) ([]models.Container, error) {
	client, err := s.getSshClient(ctx, serverName)
	if err != nil {
		return []models.Container{}, err
	}
	defer client.Close()

	out, err := client.Run("docker ps -a --format '{{json .}}'")
	if err != nil {
		return []models.Container{}, err
	}
	var containers []models.Container
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var m map[string]string
		if json.Unmarshal([]byte(line), &m) != nil {
			continue
		}
		state := m["State"]
		c := models.Container{
			ID:        m["ID"],
			Name:      strings.TrimPrefix(m["Names"], "/"),
			Image:     m["Image"],
			Status:    m["Status"],
			State:     state,
			Running:   strings.EqualFold(state, "running"),
			CreatedAt: m["CreatedAt"],
			StartedAt: m["CreatedAt"],
		}
		containers = append(containers, c)
	}

	// docker stats для запущенных контейнеров
	var running []models.Container
	for i := range containers {
		if containers[i].Running {
			running = append(running, containers[i])
		}
	}
	if len(running) > 0 {
		statsOut, _ := client.Run("docker stats --no-stream --format '{{json .}}'")
		for _, line := range strings.Split(strings.TrimSpace(statsOut), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			var m map[string]string
			if json.Unmarshal([]byte(line), &m) != nil {
				continue
			}
			id := m["ID"]
			for i := range containers {
				if containers[i].ID != "" && strings.HasPrefix(strings.ToLower(containers[i].ID), strings.ToLower(id)) {
					containers[i].CpuPercent = parsePercent(m["CPUPerc"])
					containers[i].MemoryPercent = parsePercent(m["MemPerc"])
					if parts := strings.Split(m["MemUsage"], "/"); len(parts) == 2 {
						containers[i].MemoryUsageMB = parseDockerMem(parts[0])
						containers[i].MemoryLimitMB = parseDockerMem(parts[1])
					}
					break
				}
			}
		}
	}
	return containers, nil
}

// GetServerMetrics получает метрики сервера (CPU/RAM/Disk/Uptime) через SSH.
func (s *Service) GetServerMetrics(ctx context.Context, serverName string) (*models.ServerHost, error) {
	if !s.IsMonitoringEnabled(ctx) {
		return nil, fmt.Errorf("servercore: monitoring disabled")
	}
	servers, err := s.GetServers(ctx)
	if err != nil {
		return nil, err
	}
	// Копируем запись сервера: не мутируем TTL-кэш GetServers.
	var server models.ServerHost
	found := false
	for i := range servers {
		if strings.EqualFold(servers[i].Name, serverName) || strings.EqualFold(servers[i].Title, serverName) {
			server = servers[i]
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("servercore: server %q not found", serverName)
	}

	client, err := s.getSshClient(ctx, serverName)
	if err != nil {
		return &server, nil
	}
	defer client.Close()

	// CPU: надёжно ищем поле "id"/"idle" по имени (не по позиции колонки —
	// на разных версиях top поле steal может стоять на 8-й позиции и давать
	// ложную загрузку 100%-steal). Fallback на /proc/stat (среднее с boot).
	cpuCmd := `out=$(top -bn1 2>/dev/null | grep 'Cpu(s)' | awk '{id=-1; for(i=1;i<=NF;i++){if($i ~ /^%?idle?[,%]*$/){id=$(i-1)+0}} if(id>=0) printf "%.1f", 100-id; else print "ERR"}'); if [ "$out" = "ERR" ]; then grep '^cpu ' /proc/stat | awk '{idle=$5; total=0; for(i=2;i<=11;i++) total+=$i; if(total>0) printf "%.1f", (total-idle)*100/total; else print "0"}'; else echo "$out"; fi`
	if out, err := client.Run(cpuCmd); err == nil {
		cp := strings.TrimSpace(out)
		if v := parsePercent(cp); v > 0 {
			server.CpuUsagePercent = clampPercent(round1(v))
		}
	}
	if out, err := client.Run("awk '/MemTotal/{t=$2} /MemAvailable/{a=$2} END{printf \"%.1f %.1f %.1f\", t/1048576, (t-a)/1048576, (t-a)/t*100}' /proc/meminfo"); err == nil {
		parts := strings.Fields(out)
		if len(parts) >= 3 {
			server.MemoryTotalGB = atof(parts[0])
			server.MemoryUsedGB = atof(parts[1])
			server.MemoryUsagePercent = clampPercent(round1(atof(parts[2])))
		}
	}
	if out, err := client.Run("df -B1 / | awk 'NR==2{printf \"%.1f %.1f %.1f\", $2/1073741824, $3/1073741824, $3/$2*100}'"); err == nil {
		parts := strings.Fields(out)
		if len(parts) >= 3 {
			server.DiskTotalGB = atof(parts[0])
			server.DiskUsedGB = atof(parts[1])
			server.DiskUsagePercent = clampPercent(round1(atof(parts[2])))
		}
	}
	if out, err := client.Run("uptime -p"); err == nil {
		server.Uptime = strings.TrimSpace(out)
	}
	containers, _ := s.GetContainers(ctx, serverName)
	server.TotalContainers = len(containers)
	for _, c := range containers {
		if c.Running {
			server.RunningContainers++
		}
	}
	return &server, nil
}

// clampPercent ограничивает процент в диапазоне [0, 100].
func clampPercent(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

// getSshClient подключается к серверу по SSH, используя IP из Nova и пароль из API.
func (s *Service) getSshClient(ctx context.Context, serverName string) (*sshclient.Client, error) {
	if !s.IsMonitoringEnabled(ctx) || serverName == "" {
		return nil, fmt.Errorf("servercore: monitoring disabled")
	}
	servers, err := s.GetServers(ctx)
	if err != nil {
		return nil, err
	}
	var server *models.ServerHost
	for i := range servers {
		if strings.EqualFold(servers[i].Name, serverName) || strings.EqualFold(servers[i].Title, serverName) {
			server = &servers[i]
			break
		}
	}
	if server == nil || server.IpAddress == "" {
		return nil, fmt.Errorf("servercore: server %q not found or no IP", serverName)
	}

	user, pass := s.GetServerCredentials(ctx, server.ID, server.Name)
	if pass == "" {
		return nil, fmt.Errorf("servercore: no SSH password for %q", serverName)
	}
	port := s.cfg.ServerCore.SshPort
	if port <= 0 {
		port = 22
	}
	client, err := sshclient.ConnectContextWithKey(ctx, server.IpAddress, port, user, pass, s.cfg.ServerCore.SshPrivateKeyPath, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("servercore: SSH to %s: %v", server.IpAddress, err)
	}
	return client, nil
}

// GetServerCredentials возвращает (username, password) из Servercore API.
func (s *Service) GetServerCredentials(ctx context.Context, serverID, serverName string) (string, string) {
	user := s.cfg.ServerCore.SshUsername
	if user == "" {
		user = "root"
	}
	pass := s.getServerPassword(ctx, serverID, serverName)
	return user, pass
}

// getServerPassword получает пароль root из Nova os-server-password.
// Если существующий пароль недоступен (API не вернул / RSA не расшифровался) —
// генерируется новый через Nova changePassword action.
func (s *Service) getServerPassword(ctx context.Context, serverID, serverName string) string {
	ep := s.computeEndpoint()
	if ep == "" {
		return ""
	}
	id := serverID
	if id == "" {
		id = serverName
	}
	if id == "" {
		return ""
	}
	candidates := []string{
		ep + "/servers/" + id + "/os-server-password",
		ep + "/servers/" + id + "/os-credentials",
	}
	if serverName != "" && serverName != id {
		candidates = append(candidates,
			ep+"/servers/"+serverName+"/os-server-password",
			ep+"/servers/"+serverName+"/os-credentials")
	}
	for _, url := range candidates {
		resp, err := s.sendIAM(ctx, http.MethodGet, url, nil)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			continue
		}
		pass := extractStringField(body, []string{"password", "root_password", "admin_password", "pass"}, false)
		if pass == "" {
			continue
		}
		// RSA-зашифрованный пароль (длинный base64) — нужен приватный ключ.
		if len(pass) > 60 {
			if dec := s.tryDecryptPassword(pass, serverName); dec != "" {
				return dec
			}
			continue
		}
		return pass
	}
	// Пароль не получен — генерируем новый через Nova API (прежнее поведение).
	return s.setServerPassword(ctx, serverID, serverName)
}

// setServerPassword устанавливает новый пароль через Nova changePassword action.
func (s *Service) setServerPassword(ctx context.Context, serverID, serverName string) string {
	key := serverID
	if key == "" {
		key = serverName
	}
	s.passMu.Lock()
	if cached, ok := s.passCache[key]; ok {
		s.passMu.Unlock()
		return cached
	}
	s.passMu.Unlock()

	ep := s.computeEndpoint()
	if ep == "" {
		return ""
	}
	id := serverID
	if id == "" {
		id = serverName
	}
	if id == "" {
		return ""
	}
	newPass := randomPassword(24)
	payload, _ := json.Marshal(map[string]interface{}{
		"changePassword": map[string]string{"adminPass": newPass},
	})
	url := ep + "/servers/" + id + "/action"
	resp, err := s.sendIAM(ctx, http.MethodPost, url, payload)
	if err != nil {
		return ""
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusNoContent {
		return ""
	}
	s.passMu.Lock()
	s.passCache[key] = newPass
	s.passMu.Unlock()
	return newPass
}

func parsePercent(s string) float64 {
	s = strings.TrimSpace(strings.TrimSuffix(s, "%"))
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0
	}
	return f
}

func parseDockerMem(s string) float64 {
	s = strings.TrimSpace(s)
	switch {
	case strings.HasSuffix(s, "GiB"):
		return atof(strings.TrimSuffix(s, "GiB")) * 1024
	case strings.HasSuffix(s, "MiB"):
		return atof(strings.TrimSuffix(s, "MiB"))
	case strings.HasSuffix(s, "KiB"):
		return atof(strings.TrimSuffix(s, "KiB")) / 1024
	case strings.HasSuffix(s, "B"):
		return atof(strings.TrimSuffix(s, "B")) / (1024 * 1024)
	}
	return 0
}

func atof(s string) float64 {
	f, _ := strconv.ParseFloat(strings.TrimSpace(s), 64)
	return f
}

func round1(f float64) float64 {
	return float64(int(f*10+0.5)) / 10
}

func randomPassword(length int) string {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_-+=<>?"
	b := make([]byte, length)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = chars[int(b[i])%len(chars)]
	}
	return string(b)
}

func extractStringField(body []byte, fields []string, fallback bool) string {
	var m map[string]interface{}
	if json.Unmarshal(body, &m) != nil {
		return ""
	}
	if v := extractStringRecursive(m, fields, 0, 5); v != "" {
		return v
	}
	if !fallback {
		return ""
	}
	return findAnyString(m, 0, 5)
}

func extractStringRecursive(m map[string]interface{}, fields []string, depth, maxDepth int) string {
	if depth > maxDepth {
		return ""
	}
	for k, v := range m {
		for _, f := range fields {
			if strings.EqualFold(k, f) {
				if s, ok := v.(string); ok && s != "" {
					return s
				}
			}
		}
		if sub, ok := v.(map[string]interface{}); ok {
			if r := extractStringRecursive(sub, fields, depth+1, maxDepth); r != "" {
				return r
			}
		}
		if arr, ok := v.([]interface{}); ok {
			for _, item := range arr {
				if sub, ok := item.(map[string]interface{}); ok {
					if r := extractStringRecursive(sub, fields, depth+1, maxDepth); r != "" {
						return r
					}
				}
			}
		}
	}
	return ""
}

func findAnyString(m map[string]interface{}, depth, maxDepth int) string {
	if depth > maxDepth {
		return ""
	}
	for _, v := range m {
		if s, ok := v.(string); ok && s != "" {
			return s
		}
		if sub, ok := v.(map[string]interface{}); ok {
			if r := findAnyString(sub, depth+1, maxDepth); r != "" {
				return r
			}
		}
		if arr, ok := v.([]interface{}); ok {
			for _, item := range arr {
				if sub, ok := item.(map[string]interface{}); ok {
					if r := findAnyString(sub, depth+1, maxDepth); r != "" {
						return r
					}
				}
			}
		}
	}
	return ""
}
