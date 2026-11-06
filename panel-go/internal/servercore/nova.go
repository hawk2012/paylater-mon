package servercore

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"paylater-mon/internal/models"
)

func parseNovaServers(body []byte) []models.ServerHost {
	var doc struct {
		Servers []json.RawMessage `json:"servers"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil
	}
	var list []models.ServerHost
	for _, raw := range doc.Servers {
		h := novaServerToHost(raw)
		list = append(list, h)
	}
	return list
}

func novaServerToHost(raw json.RawMessage) models.ServerHost {
	var s map[string]interface{}
	_ = json.Unmarshal(raw, &s)
	h := models.ServerHost{}
	if v, ok := s["id"].(string); ok {
		h.ID = v
	}
	if v, ok := s["name"].(string); ok {
		h.Name = v
		h.Title = v
	}
	h.Status = mapNovaStatus(str(s, "status"))
	h.IpAddress = extractNovaIp(s)
	if img, ok := s["image"].(map[string]interface{}); ok {
		imgName := str(img, "name")
		imgID := str(img, "id")
		// Пункт 61: если имя образа пустое или это GUID — пробуем
		// нормализовать, иначе оставляем как есть.
		h.OperatingSystem = normalizeOSName(imgName, imgID)
	}
	if fl, ok := s["flavor"].(map[string]interface{}); ok {
		h.CpuCores = toInt(fl, "vcpus", "cpu")
		if ram := toF64(fl, "ram", "memory"); ram > 0 {
			h.MemoryTotalGB = ram / 1024.0
		}
		h.DiskTotalGB = toF64(fl, "disk", "storage")
	}
	if meta, ok := s["metadata"].(map[string]interface{}); ok {
		if v := toF64(meta, "cpu_usage", "cpu_load"); v > 0 {
			h.CpuUsagePercent = v
		}
		if v := toF64(meta, "memory_usage", "ram_usage"); v > 0 {
			h.MemoryUsagePercent = v
		}
		if v := toF64(meta, "disk_usage", "storage_usage"); v > 0 {
			h.DiskUsagePercent = v
		}
	}
	return h
}

// normalizeOSName нормализует имя образа ОС из Nova:
//   - пустое имя или GUID → "Unknown (GUID)";
//   - "ubuntu-22.04-x86_64" → "Ubuntu 22.04";
//   - "windows-server-2019" → "Windows Server 2019";
//   - "debian-12" → "Debian 12".
//
// Пункт 61 IMPROVEMENTS.md: раньше отображался лишь GUID из ServerCore,
// а не сама операционная система.
func normalizeOSName(name, id string) string {
	name = strings.TrimSpace(name)
	id = strings.TrimSpace(id)
	if name != "" && !looksLikeGUID(name) {
		return prettifyOSName(name)
	}
	if id != "" {
		if looksLikeGUID(id) {
			return "Unknown (" + id[:8] + ")"
		}
		return prettifyOSName(id)
	}
	return "Unknown"
}

// looksLikeGUID проверяет, является ли строка UUID/GUID.
func looksLikeGUID(s string) bool {
	s = strings.TrimSpace(s)
	// UUID: 8-4-4-4-12 hex digits.
	if len(s) == 36 {
		dashes := 0
		for _, c := range s {
			if c == '-' {
				dashes++
			}
		}
		return dashes == 4
	}
	// Только hex и длинный → скорее всего GUID.
	if len(s) >= 32 {
		allHex := true
		for _, c := range s {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				allHex = false
				break
			}
		}
		return allHex
	}
	return false
}

// prettifyOSName превращает техническое имя образа в читаемое название ОС.
func prettifyOSName(s string) string {
	s = strings.TrimSpace(s)
	low := strings.ToLower(s)
	switch {
	case strings.Contains(low, "ubuntu"):
		return "Ubuntu " + extractVersion(low, "ubuntu")
	case strings.Contains(low, "debian"):
		return "Debian " + extractVersion(low, "debian")
	case strings.Contains(low, "centos"):
		return "CentOS " + extractVersion(low, "centos")
	case strings.Contains(low, "rocky"):
		return "Rocky Linux " + extractVersion(low, "rocky")
	case strings.Contains(low, "almalinux") || strings.Contains(low, "alma"):
		return "AlmaLinux " + extractVersion(low, "alma")
	case strings.Contains(low, "windows"):
		return prettifyWindowsName(low)
	case strings.Contains(low, "fedora"):
		return "Fedora " + extractVersion(low, "fedora")
	case strings.Contains(low, "opensuse") || strings.Contains(low, "suse"):
		return "openSUSE " + extractVersion(low, "suse")
	case strings.Contains(low, "routeros") || strings.Contains(low, "mikrotik"):
		return "MikroTik RouterOS " + extractVersion(low, "routeros")
	case strings.Contains(low, "freebsd"):
		return "FreeBSD " + extractVersion(low, "freebsd")
	}
	return s
}

// extractVersion извлекает версию из строки вида "ubuntu-22.04-x86_64".
func extractVersion(low, prefix string) string {
	idx := strings.Index(low, prefix)
	if idx < 0 {
		return ""
	}
	rest := low[idx+len(prefix):]
	rest = strings.TrimLeft(rest, "-_. ")
	// Берём цифры и точки.
	var ver strings.Builder
	for _, c := range rest {
		if (c >= '0' && c <= '9') || c == '.' {
			ver.WriteRune(c)
		} else if c == '-' || c == '_' || c == ' ' {
			break
		}
	}
	return ver.String()
}

// prettifyWindowsName форматирует имя Windows-образа.
func prettifyWindowsName(low string) string {
	if strings.Contains(low, "2019") {
		return "Windows Server 2019"
	}
	if strings.Contains(low, "2022") {
		return "Windows Server 2022"
	}
	if strings.Contains(low, "2016") {
		return "Windows Server 2016"
	}
	if strings.Contains(low, "2012") {
		return "Windows Server 2012"
	}
	if strings.Contains(low, "10") {
		return "Windows 10"
	}
	if strings.Contains(low, "11") {
		return "Windows 11"
	}
	return "Windows"
}

func (s *Service) enrichWithNova(ctx context.Context, hosts []models.ServerHost, ep string) {
	var sem = make(chan struct{}, 4)
	var wg sync.WaitGroup
	for i := range hosts {
		if hosts[i].ID == "" {
			continue
		}
		wg.Add(1)
		go func(h *models.ServerHost) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			url := ep + "/servers/" + h.ID
			resp, err := s.sendIAM(ctx, http.MethodGet, url, nil)
			if err != nil {
				return
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return
			}
			var doc struct {
				Server map[string]interface{} `json:"server"`
			}
			if json.Unmarshal(body, &doc) != nil {
				return
			}
			srv := doc.Server
			if st := str(srv, "status"); st != "" {
				h.Status = mapNovaStatus(st)
			}
			if fl, ok := srv["flavor"].(map[string]interface{}); ok {
				h.CpuCores = toInt(fl, "vcpus", "cpu")
				if ram := toF64(fl, "ram", "memory"); ram > 0 {
					h.MemoryTotalGB = ram / 1024.0
				}
				h.DiskTotalGB = toF64(fl, "disk", "storage")
			}
			if addr, ok := srv["addresses"].(map[string]interface{}); ok {
				for _, net := range addr {
					arr, ok := net.([]interface{})
					if !ok {
						continue
					}
					for _, ep2 := range arr {
						m, ok := ep2.(map[string]interface{})
						if !ok {
							continue
						}
						ip := str(m, "addr")
						ver := str(m, "version")
						if ip != "" && ver == "4" {
							if h.IpAddress == "" {
								h.IpAddress = ip
							}
							break
						}
					}
					if h.IpAddress != "" {
						break
					}
				}
			}
			if img, ok := srv["image"].(map[string]interface{}); ok {
				imgName := str(img, "name")
				imgID := str(img, "id")
				if imgName != "" || imgID != "" {
					h.OperatingSystem = normalizeOSName(imgName, imgID)
				}
			}
		}(&hosts[i])
	}
	wg.Wait()
}

func mapNovaStatus(st string) string {
	switch strings.ToUpper(st) {
	case "ACTIVE":
		return "running"
	case "BUILD":
		return "building"
	case "SHUTOFF":
		return "stopped"
	case "SUSPENDED":
		return "suspended"
	case "PAUSED":
		return "paused"
	case "ERROR":
		return "error"
	case "REBOOT", "HARD_REBOOT":
		return "rebooting"
	case "DELETED":
		return "deleted"
	case "", "UNKNOWN":
		return "unknown"
	default:
		return st
	}
}

func extractNovaIp(s map[string]interface{}) string {
	addr, ok := s["addresses"].(map[string]interface{})
	if !ok {
		return ""
	}
	for _, net := range addr {
		arr, ok := net.([]interface{})
		if !ok {
			continue
		}
		for _, ep := range arr {
			m, ok := ep.(map[string]interface{})
			if !ok {
				continue
			}
			ip := str(m, "addr")
			ver := str(m, "version")
			if ip != "" && (ver == "" || ver == "4") {
				return ip
			}
		}
	}
	return ""
}

func str(m map[string]interface{}, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			if s, ok := v.(string); ok {
				return s
			}
		}
	}
	return ""
}

func toInt(m map[string]interface{}, keys ...string) int {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			switch n := v.(type) {
			case float64:
				return int(n)
			case int:
				return n
			case string:
				if i, err := strconv.Atoi(n); err == nil {
					return i
				}
			}
		}
	}
	return 0
}

func toF64(m map[string]interface{}, keys ...string) float64 {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			switch n := v.(type) {
			case float64:
				return n
			case int:
				return float64(n)
			case string:
				if f, err := strconv.ParseFloat(n, 64); err == nil {
					return f
				}
			}
		}
	}
	return 0
}
