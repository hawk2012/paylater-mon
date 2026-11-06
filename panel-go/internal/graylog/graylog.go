// Package graylog — интеграция с Graylog REST API (PROD/TEST).
package graylog

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"paylater-mon/internal/config"
	"paylater-mon/internal/models"
	"paylater-mon/internal/servercore"
)

// Service — Graylog REST API клиент.
type Service struct {
	cfg        *config.Config
	serverCore *servercore.Service
	http       *http.Client
}

// New создаёт сервис Graylog.
func New(cfg *config.Config, sc *servercore.Service) *Service {
	return &Service{cfg: cfg, serverCore: sc, http: &http.Client{Timeout: 30 * time.Second}}
}

// ApplyConfig обновляет конфигурацию на лету (без перезапуска).
func (s *Service) ApplyConfig(cfg *config.Config) {
	s.cfg = cfg
}

// GetClusterNodes получает состояние нод кластера (GET /api/system/cluster/nodes).
func (s *Service) GetClusterNodes(ctx context.Context, env string) ([]models.GraylogClusterNode, error) {
	url, auth, err := s.apiEndpoint(env)
	if err != nil {
		return []models.GraylogClusterNode{}, nil
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url+"system/cluster/nodes", nil)
	req.Header.Set("Authorization", auth)
	req.Header.Set("Accept", "application/json")
	resp, err := s.http.Do(req)
	if err != nil {
		return []models.GraylogClusterNode{}, err
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return []models.GraylogClusterNode{}, nil
	}
	var nodes []models.GraylogClusterNode
	var doc struct {
		Nodes        []map[string]interface{} `json:"nodes"`
		ClusterNodes []map[string]interface{} `json:"cluster_nodes"`
	}
	json.Unmarshal(body, &doc)
	arr := doc.Nodes
	if len(arr) == 0 {
		arr = doc.ClusterNodes
	}
	for _, m := range arr {
		nodes = append(nodes, models.GraylogClusterNode{
			NodeID:             str(m, "node_id"),
			ShortNodeID:        str(m, "short_node_id"),
			Hostname:           str(m, "hostname"),
			IsMaster:           toBool(m, "is_master"),
			ProcessingMessages: toInt64(m, "processing_message_count"),
			LastStatusUpdate:   str(m, "last_status_report"),
			Throughput:         toInt64(m, "throughput"),
			Lifecycle:          str(m, "lifecycle"),
			Type:               str(m, "type"),
		})
	}
	return nodes, nil
}

// SearchLogs ищет логи (POST /api/search/universal/relative).
func (s *Service) SearchLogs(ctx context.Context, env, query string, rangeSec, limit int, streamID string) (models.GraylogSearchResult, error) {
	result := models.GraylogSearchResult{}
	if query == "" {
		query = "*"
	}
	url, auth, err := s.apiEndpoint(env)
	if err != nil {
		result.Error = "Graylog credentials not configured"
		return result, nil
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"query":  query,
		"range":  rangeSec,
		"limit":  limit,
		"sort":   "timestamp:desc",
		"fields": []string{"timestamp", "source", "level", "message"},
	})
	searchURL := url + "search/universal/relative"
	if streamID != "" {
		searchURL += "?streamId=" + streamID
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, searchURL, bytes.NewReader(payload))
	req.Header.Set("Authorization", auth)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.http.Do(req)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		result.Error = fmt.Sprintf("HTTP %d: %s", resp.StatusCode, truncate(string(body), 300))
		return result, nil
	}
	var doc struct {
		Messages []struct {
			Index   string                 `json:"index_name"`
			Message map[string]interface{} `json:"message"`
		} `json:"messages"`
		Total int64 `json:"total_results"`
	}
	json.Unmarshal(body, &doc)
	result.Total = doc.Total
	for _, m := range doc.Messages {
		inner := m.Message
		if inner == nil {
			inner = map[string]interface{}{}
		}
		result.Messages = append(result.Messages, models.GraylogMessage{
			Timestamp: str(inner, "timestamp"),
			Source:    str(inner, "source"),
			Level:     str(inner, "level"),
			Message:   str(inner, "message"),
			Index:     m.Index,
		})
	}
	return result, nil
}

// GetStreams получает список streams (GET /api/streams).
func (s *Service) GetStreams(ctx context.Context, env string) ([]models.GraylogStream, error) {
	url, auth, err := s.apiEndpoint(env)
	if err != nil {
		return []models.GraylogStream{}, nil
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url+"streams", nil)
	req.Header.Set("Authorization", auth)
	req.Header.Set("Accept", "application/json")
	resp, err := s.http.Do(req)
	if err != nil {
		return []models.GraylogStream{}, err
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return []models.GraylogStream{}, nil
	}
	var doc struct {
		Streams []map[string]interface{} `json:"streams"`
	}
	json.Unmarshal(body, &doc)
	var list []models.GraylogStream
	for _, m := range doc.Streams {
		list = append(list, models.GraylogStream{
			ID:          str(m, "id"),
			Title:       str(m, "title"),
			Description: str(m, "description"),
			Disabled:    toBool(m, "disabled"),
		})
	}
	return list, nil
}

// apiEndpoint возвращает URL Graylog API и Basic auth по окружению.
// IP берётся через ServerCore IAM по шаблону uz-{env}-graylog.
func (s *Service) apiEndpoint(env string) (string, string, error) {
	e := strings.ToLower(strings.TrimSpace(env))
	var user, pass string
	switch e {
	case "prod", "production":
		user, pass = s.cfg.Graylog.Prod.Username, s.cfg.Graylog.Prod.Password
	case "test", "testing":
		user, pass = s.cfg.Graylog.Test.Username, s.cfg.Graylog.Test.Password
	default:
		return "", "", fmt.Errorf("unknown env: %s", env)
	}
	if user == "" {
		return "", "", fmt.Errorf("graylog credentials not configured for %s", e)
	}
	serverName, err := s.serverCore.FindServerName(context.Background(), e, "graylog")
	if err != nil || serverName == "" {
		return "", "", fmt.Errorf("graylog server not found for %s", e)
	}
	servers, _ := s.serverCore.GetServers(context.Background())
	for _, sv := range servers {
		if strings.EqualFold(sv.Name, serverName) && sv.IpAddress != "" {
			port := s.cfg.Graylog.ApiPort
			if port == 0 {
				port = 9000
			}
			baseURL := fmt.Sprintf("http://%s:%d/api/", sv.IpAddress, port)
			token := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
			return baseURL, "Basic " + token, nil
		}
	}
	return "", "", fmt.Errorf("graylog server %s has no IP", serverName)
}

func str(m map[string]interface{}, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k].(string); ok {
			return v
		}
	}
	return ""
}
func toBool(m map[string]interface{}, k string) bool {
	v, ok := m[k]
	return ok && v == true
}
func toInt64(m map[string]interface{}, k string) int64 {
	if v, ok := m[k]; ok {
		switch n := v.(type) {
		case float64:
			return int64(n)
		case int64:
			return n
		case int:
			return int64(n)
		}
	}
	return 0
}
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
