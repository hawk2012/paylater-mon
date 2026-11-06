// Package vault — работа с HashiCorp Vault (KV v1/v2, эфемерные ключи).
package vault

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
)

// Service — клиент HashiCorp Vault.
type Service struct {
	cfg  *config.Config
	http *http.Client

	mu    sync.Mutex
	cache map[string]cacheEntry

	// Активные эфемерные ключи (пункт 11 IMPROVEMENTS.md).
	keysMu     sync.Mutex
	activeKeys []ActiveKey
}

// ActiveKey — активный эфемерный ключ.
type ActiveKey struct {
	LeaseID      string                 `json:"lease_id"`
	TemplateName string                 `json:"template_name"`
	CreatedAt    time.Time              `json:"created_at"`
	ExpiresAt    time.Time              `json:"expires_at"`
	Data         map[string]interface{} `json:"data"`
}

type cacheEntry struct {
	expires time.Time
	value   interface{}
}

// SecretEntry — секрет из Vault.
type SecretEntry struct {
	Path       string
	Data       map[string]string
	Version    int
	EngineType string
}

// Catalog — каталог путей.
type Catalog struct {
	Kv1Paths []string
	Kv2Paths []string
}

// New создаёт сервис Vault.
func New(cfg *config.Config) *Service {
	return &Service{cfg: cfg, http: &http.Client{Timeout: 30 * time.Second}, cache: map[string]cacheEntry{}}
}

// ApplyConfig обновляет конфигурацию на лету (без перезапуска).
func (s *Service) ApplyConfig(cfg *config.Config) {
	s.mu.Lock()
	s.cfg = cfg
	s.mu.Unlock()
	s.InvalidateCache()
}

func (s *Service) apiBase() string {
	return strings.TrimRight(s.cfg.Vault.ApiBase, "/")
}

// Enabled — включён ли Vault.
func (s *Service) Enabled() bool {
	return s.cfg.Vault.Enabled && s.cfg.Vault.ApiBase != ""
}

func (s *Service) cacheGet(key string) (interface{}, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.cache[key]
	if !ok || time.Now().After(e.expires) {
		return nil, false
	}
	return e.value, true
}

func (s *Service) cacheSet(key string, v interface{}) {
	ttl := s.cfg.Vault.CacheTtlMinutes
	if ttl <= 0 {
		ttl = 5
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cache[key] = cacheEntry{expires: time.Now().Add(time.Duration(ttl) * time.Minute), value: v}
}

func (s *Service) do(ctx context.Context, method, path string, body []byte) (*http.Response, error) {
	url := s.apiBase() + "/v1/" + path
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, rd)
	if err != nil {
		return nil, err
	}
	if s.cfg.Vault.UseRootToken && s.cfg.Vault.RootToken != "" {
		req.Header.Set("X-Vault-Token", s.cfg.Vault.RootToken)
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return s.http.Do(req)
}

// CheckConnection проверяет подключение к Vault.
func (s *Service) CheckConnection(ctx context.Context) (bool, string, string) {
	if !s.Enabled() {
		return false, "Vault disabled in config", ""
	}
	if s.cfg.Vault.ApiBase == "" {
		return false, "Vault ApiBase not configured", ""
	}
	resp, err := s.do(ctx, http.MethodGet, "sys/health", nil)
	if err != nil {
		return false, err.Error(), ""
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	version := ""
	var doc map[string]interface{}
	if json.Unmarshal(body, &doc) == nil {
		if v, ok := doc["version"].(string); ok {
			version = v
		}
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 500 {
		return true, "Connected", version
	}
	return false, fmt.Sprintf("HTTP %d", resp.StatusCode), version
}

// GetCatalog собирает каталог путей KV v1 и KV v2.
func (s *Service) GetCatalog(ctx context.Context) *Catalog {
	if v, ok := s.cacheGet("vault_catalog"); ok {
		return v.(*Catalog)
	}
	c := &Catalog{}
	s.collectPaths(ctx, s.cfg.Vault.Kv1Path, "kv_v1", &c.Kv1Paths, 0)
	s.collectPaths(ctx, s.cfg.Vault.Kv2Path, "kv_v2", &c.Kv2Paths, 0)
	s.cacheSet("vault_catalog", c)
	return c
}

func (s *Service) collectPaths(ctx context.Context, basePath, engine string, result *[]string, depth int) {
	if depth > 5 || basePath == "" {
		return
	}
	resp, err := s.do(ctx, http.MethodGet, basePath+"?list=true", nil)
	if err != nil {
		return
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return
	}
	var doc struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &doc) != nil {
		return
	}
	for _, name := range doc.Data.Keys {
		isDir := strings.HasSuffix(name, "/")
		clean := strings.TrimSuffix(name, "/")
		full := basePath + "/" + clean
		if engine == "kv_v2" {
			*result = append(*result, "kv_v2|"+full)
		} else {
			*result = append(*result, "kv_v1|"+full)
		}
		if isDir {
			s.collectPaths(ctx, full, engine, result, depth+1)
		}
	}
}

// GetSecret получает секрет по пути (автоопределение типа движка).
func (s *Service) GetSecret(ctx context.Context, path, engineType string) *SecretEntry {
	if engineType == "" {
		engineType = detectEngineType(s.cfg, path)
	}
	cacheKey := "vault_secret_" + path + "_" + engineType
	if v, ok := s.cacheGet(cacheKey); ok {
		return v.(*SecretEntry)
	}
	entry := s.getSecretInternal(ctx, path, engineType)
	if entry != nil {
		s.cacheSet(cacheKey, entry)
	}
	return entry
}

func detectEngineType(cfg *config.Config, path string) string {
	if strings.Contains(path, "/data/") || strings.HasPrefix(path, cfg.Vault.Kv2Path) {
		return "kv_v2"
	}
	return "kv_v1"
}

func (s *Service) getSecretInternal(ctx context.Context, path, engine string) *SecretEntry {
	vaultPath := path
	if engine == "kv_v2" && !strings.Contains(path, "/version/") {
		vaultPath = path + "/latest"
	}
	resp, err := s.do(ctx, http.MethodGet, vaultPath, nil)
	if err != nil {
		return nil
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	var doc map[string]interface{}
	if json.Unmarshal(body, &doc) != nil {
		return nil
	}
	entry := &SecretEntry{Path: path, Data: map[string]string{}, EngineType: engine}
	if engine == "kv_v2" {
		if data, ok := doc["data"].(map[string]interface{}); ok {
			if kv, ok := data["data"].(map[string]interface{}); ok {
				for k, v := range kv {
					entry.Data[k] = stringify(v)
				}
			}
			if meta, ok := data["metadata"].(map[string]interface{}); ok {
				if v, ok := meta["version"].(float64); ok {
					entry.Version = int(v)
				}
			}
		}
	} else {
		if data, ok := doc["data"].(map[string]interface{}); ok {
			for k, v := range data {
				entry.Data[k] = stringify(v)
			}
		}
	}
	if len(entry.Data) == 0 {
		return nil
	}
	return entry
}

// WriteSecret записывает секрет в KV v2.
func (s *Service) WriteSecret(ctx context.Context, path string, data map[string]interface{}, mount string) (bool, error) {
	if mount == "" {
		mount = "secret"
	}
	payload, _ := json.Marshal(map[string]interface{}{"data": data})
	resp, err := s.do(ctx, http.MethodPost, mount+"/data/"+strings.TrimPrefix(path, "/"), payload)
	if err != nil {
		return false, err
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 300, nil
}

// DeleteSecret удаляет секрет из KV v2.
func (s *Service) DeleteSecret(ctx context.Context, path, mount string) (bool, error) {
	if mount == "" {
		mount = "secret"
	}
	resp, err := s.do(ctx, http.MethodDelete, mount+"/metadata/"+strings.TrimPrefix(path, "/"), nil)
	if err != nil {
		return false, err
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 300, nil
}

// CreateEphemeralKey создаёт эфемерный ключ через Vault Ephemeral Secret Engine.
func (s *Service) CreateEphemeralKey(ctx context.Context, templateName string, leaseDurationSec int) (map[string]interface{}, bool, string) {
	if !s.Enabled() {
		return nil, false, "Vault не настроен"
	}
	mp := s.cfg.Vault.Kv1Path
	if mp == "" {
		mp = "ephemeral"
	}
	var payload []byte
	if leaseDurationSec > 0 {
		payload, _ = json.Marshal(map[string]int{"lease_duration": leaseDurationSec})
	}
	resp, err := s.do(ctx, http.MethodPost, mp+"/creds/"+templateName, payload)
	if err != nil {
		return nil, false, err.Error()
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent {
		return nil, false, fmt.Sprintf("HTTP %d: %s", resp.StatusCode, truncate(string(body), 300))
	}
	var doc map[string]interface{}
	json.Unmarshal(body, &doc)

	// Отслеживаем активный ключ (пункт 11).
	leaseID, _ := doc["lease_id"].(string)
	if leaseID == "" {
		leaseID, _ = doc["leaseId"].(string)
	}
	duration := time.Duration(leaseDurationSec) * time.Second
	if duration <= 0 {
		duration = time.Hour
	}
	s.keysMu.Lock()
	s.activeKeys = append(s.activeKeys, ActiveKey{
		LeaseID:      leaseID,
		TemplateName: templateName,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(duration),
		Data:         doc,
	})
	s.keysMu.Unlock()

	return doc, true, ""
}

// RevokeEphemeralKey отзывает эфемерный ключ по lease ID.
func (s *Service) RevokeEphemeralKey(ctx context.Context, leaseID string) (bool, string) {
	if !s.Enabled() || leaseID == "" {
		return false, "Vault не настроен"
	}
	resp, err := s.do(ctx, http.MethodPost, "sys/revoke/"+leaseID, nil)
	if err != nil {
		return false, err.Error()
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()
	ok := resp.StatusCode >= 200 && resp.StatusCode < 300

	// Удаляем из активных (пункт 11).
	if ok {
		s.keysMu.Lock()
		for i, k := range s.activeKeys {
			if k.LeaseID == leaseID {
				s.activeKeys = append(s.activeKeys[:i], s.activeKeys[i+1:]...)
				break
			}
		}
		s.keysMu.Unlock()
	}
	return ok, ""
}

// GetActiveKeys возвращает список активных эфемерных ключей (пункт 11).
func (s *Service) GetActiveKeys() []ActiveKey {
	s.keysMu.Lock()
	defer s.keysMu.Unlock()
	// Фильтруем истёкшие.
	var active []ActiveKey
	for _, k := range s.activeKeys {
		if time.Now().Before(k.ExpiresAt) {
			active = append(active, k)
		}
	}
	s.activeKeys = active
	return active
}

// InvalidateCache сбрасывает кэш.
func (s *Service) InvalidateCache() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cache = map[string]cacheEntry{}
}

// ── VaultBackend для users.Store (пункт 20) ──

// UsersMount — путь в Vault для хранения пользователей.
const UsersMount = "kv"
const UsersPath = "paylater-mon/users"

// ReadUsers читает JSON пользователей из Vault.
func (s *Service) ReadUsers(ctx context.Context) ([]byte, error) {
	if !s.Enabled() {
		return nil, fmt.Errorf("vault disabled")
	}
	resp, err := s.do(ctx, http.MethodGet, UsersMount+"/data/"+UsersPath, nil)
	if err != nil {
		return nil, err
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("vault: HTTP %d", resp.StatusCode)
	}
	var doc struct {
		Data struct {
			Data map[string]interface{} `json:"data"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &doc) != nil {
		return nil, fmt.Errorf("vault: invalid response")
	}
	if raw, ok := doc.Data.Data["users_json"]; ok {
		if str, ok := raw.(string); ok {
			return []byte(str), nil
		}
	}
	return nil, nil
}

// WriteUsers записывает JSON пользователей в Vault.
func (s *Service) WriteUsers(ctx context.Context, data []byte) error {
	if !s.Enabled() {
		return fmt.Errorf("vault disabled")
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"data": map[string]interface{}{
			"users_json": string(data),
		},
	})
	resp, err := s.do(ctx, http.MethodPost, UsersMount+"/data/"+UsersPath, payload)
	if err != nil {
		return err
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("vault: HTTP %d", resp.StatusCode)
	}
	return nil
}

// ── Secret references (пункт 22: шифрование секретов) ──

// ReadSecretRef читает секрет из Vault по пути вида "kv/data/paylater-mon/config/servercore_iam_password".
// Возвращает значение поля "value" из данных секрета.
func (s *Service) ReadSecretRef(ctx context.Context, path string) (string, error) {
	if !s.Enabled() {
		return "", fmt.Errorf("vault disabled")
	}
	resp, err := s.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return "", err
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("vault: HTTP %d", resp.StatusCode)
	}
	var doc struct {
		Data struct {
			Data map[string]interface{} `json:"data"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &doc) != nil {
		return "", fmt.Errorf("vault: invalid response")
	}
	if v, ok := doc.Data.Data["value"].(string); ok {
		return v, nil
	}
	return "", fmt.Errorf("vault: no 'value' field at %s", path)
}

// WriteSecretRef записывает единичное значение в Vault (для миграции секретов из YAML).
func (s *Service) WriteSecretRef(ctx context.Context, path, value string) error {
	if !s.Enabled() {
		return fmt.Errorf("vault disabled")
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"data": map[string]interface{}{"value": value},
	})
	resp, err := s.do(ctx, http.MethodPost, path, payload)
	if err != nil {
		return err
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("vault: HTTP %d", resp.StatusCode)
	}
	return nil
}

func stringify(v interface{}) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return fmt.Sprintf("%v", t)
	case bool:
		return fmt.Sprintf("%v", t)
	default:
		b, _ := json.Marshal(t)
		return string(b)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
