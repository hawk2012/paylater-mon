// Package aidiag — ИИ-диагностика серверов (ChatGPT/OpenAI + Koda CLI).
package aidiag

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"paylater-mon/internal/config"
)

// Diagnosis — результат диагностики от LLM.
type Diagnosis struct {
	Diagnosis      string               `json:"diagnosis"`
	Severity       string               `json:"severity"`
	Remediation    []RemediationCommand `json:"remediation"`
	Recommendation string               `json:"recommendation"`
}

// RemediationCommand — команда исправления.
type RemediationCommand struct {
	Command     string `json:"command"`
	Description string `json:"description"`
	Safe        bool   `json:"safe"`
}

// Detection — обнаруженная проблема.
type Detection struct {
	ServerName  string
	ServerIP    string
	Env         string
	Type        string
	Severity    string
	Title       string
	Description string
	Context     string
}

// SafeCommandPrefixes — whitelist безопасных команд.
var SafeCommandPrefixes = []string{
	"docker restart ", "docker start ", "docker stop ",
	"docker logs ", "docker inspect ", "docker ps",
	"systemctl restart ", "systemctl status ", "systemctl start ",
	"free ", "sync; echo 3 > /proc/sys/vm/drop_caches",
	"df -h", "top -bn1", "journalctl ", "du -sh ",
}

// IsCommandSafe проверяет команду на whitelist.
func IsCommandSafe(command string) bool {
	c := strings.TrimSpace(command)
	for _, p := range SafeCommandPrefixes {
		if strings.HasPrefix(strings.ToLower(c), strings.ToLower(p)) {
			return true
		}
	}
	return false
}

// Provider — LLM-провайдер.
type Provider interface {
	ProviderID() string
	Enabled() bool
	DefaultModel() string
	Models() []string
	Diagnose(ctx context.Context, system, user, model string) (*Diagnosis, error)
}

// Service — ИИ-диагностика.
type Service struct {
	cfg    *config.Config
	http   *http.Client
	openai *OpenAIProvider
	koda   *KodaProvider
}

// New создаёт сервис ИИ-диагностики.
func New(cfg *config.Config) *Service {
	return &Service{
		cfg:    cfg,
		http:   &http.Client{Timeout: 120 * time.Second},
		openai: &OpenAIProvider{cfg: cfg, http: &http.Client{Timeout: 120 * time.Second}},
		koda:   &KodaProvider{cfg: cfg},
	}
}

// ApplyConfig обновляет конфигурацию на лету (без перезапуска).
func (s *Service) ApplyConfig(cfg *config.Config) {
	s.cfg = cfg
	s.openai.cfg = cfg
	s.koda.cfg = cfg
}

// Enabled — включена ли диагностика (хотя бы один провайдер).
func (s *Service) Enabled() bool {
	return s.openai.Enabled() || s.koda.Enabled()
}

// AutoResolve — включено ли авто-применение.
func (s *Service) AutoResolve() bool {
	return s.cfg.AiDiagnostics.AutoResolve
}

// Providers возвращает список провайдеров.
func (s *Service) Providers() []Provider {
	var list []Provider
	list = append(list, s.openai, s.koda)
	return list
}

func (s *Service) selectedProvider() Provider {
	selected := s.cfg.AiDiagnostics.SelectedProvider
	for _, p := range s.Providers() {
		if p.ProviderID() == selected && p.Enabled() {
			return p
		}
	}
	for _, p := range s.Providers() {
		if p.Enabled() {
			return p
		}
	}
	return nil
}

func (s *Service) selectedModel(p Provider) string {
	if s.cfg.AiDiagnostics.SelectedModel != "" {
		return s.cfg.AiDiagnostics.SelectedModel
	}
	return p.DefaultModel()
}

// Diagnose диагностирует конкретную проблему.
func (s *Service) Diagnose(ctx context.Context, d Detection) (*Diagnosis, error) {
	p := s.selectedProvider()
	if p == nil {
		return nil, fmt.Errorf("нет доступного ИИ-провайдера")
	}
	user := buildProblemPrompt(d)
	return p.Diagnose(ctx, systemPrompt(), user, s.selectedModel(p))
}

// DiagnoseManual выполняет произвольный запрос к ИИ.
func (s *Service) DiagnoseManual(ctx context.Context, query, serverContext string) (*Diagnosis, error) {
	p := s.selectedProvider()
	if p == nil {
		return nil, fmt.Errorf("нет доступного ИИ-провайдера")
	}
	var sb strings.Builder
	sb.WriteString("Запрос администратора:\n")
	sb.WriteString(query)
	if serverContext != "" {
		sb.WriteString("\n\n=== КОНТЕКСТ СЕРВЕРА ===\n")
		sb.WriteString(serverContext)
	}
	sb.WriteString("\n\nДай развёрнутый ответ с диагнозом и remediation-командами в JSON-формате.")
	return p.Diagnose(ctx, systemPrompt(), sb.String(), s.selectedModel(p))
}

func systemPrompt() string {
	return `Ты — DevOps-инженер и эксперт по диагностике серверов (Linux/Windows, Docker,
Camunda 8, Graylog, PostgreSQL, Nginx и др.). Твоя задача — проанализировать
проблему сервера и дать точный диагноз + конкретные команды для исправления.

Отвечай СТРОГО в формате JSON (без markdown-обёрток, без пояснений вне JSON):
{
  "diagnosis": "краткий диагноз: что произошло и почему",
  "severity": "critical | warning | info",
  "remediation": [
    {
      "command": "конкретная shell-команда для исправления",
      "description": "что делает команда",
      "safe": true
    }
  ],
  "recommendation": "дополнительные рекомендации (мониторинг, превентивные меры)"
}

Правила:
- Команды должны быть безопасными и целевыми. Не предлагай rm -rf, dd, mkfs,
  перезагрузку продакшн-сервера без необходимости.
- safe=true только для non-destructive команд (docker restart, systemctl status,
  очистка кэша, проверка логов).
- Если проблема в контейнере — предлагай docker restart/logs/inspect.
- Если high CPU/RAM — предлагай диагностику процессов (top, docker stats).
- Если мало места на диске — предлагай очистку логов/docker prune/du.
- Отвечай на русском языке.`
}

func buildProblemPrompt(d Detection) string {
	var sb strings.Builder
	sb.WriteString("=== ПРОБЛЕМА ===\n")
	sb.WriteString("Тип: " + d.Type + "\n")
	sb.WriteString("Серьёзность: " + d.Severity + "\n")
	sb.WriteString("Сервер: " + d.ServerName + "\n")
	if d.ServerIP != "" {
		sb.WriteString("IP: " + d.ServerIP + "\n")
	}
	if d.Env != "" {
		sb.WriteString("Окружение: " + d.Env + "\n")
	}
	sb.WriteString("Заголовок: " + d.Title + "\n")
	sb.WriteString("Описание: " + d.Description + "\n\n")
	sb.WriteString("=== МЕТРИКИ / КОНТЕКСТ ===\n")
	if d.Context == "" {
		sb.WriteString("(нет данных)\n")
	} else {
		sb.WriteString(d.Context + "\n")
	}
	sb.WriteString("\nДай диагноз и remediation-команды в JSON-формате.")
	return sb.String()
}

// ── OpenAI провайдер ──

// OpenAIProvider — ChatGPT/OpenAI-compatible провайдер.
type OpenAIProvider struct {
	cfg  *config.Config
	http *http.Client
}

func (p *OpenAIProvider) ProviderID() string { return "chatgpt" }
func (p *OpenAIProvider) Enabled() bool {
	return p.cfg.AiDiagnostics.ChatGptEnabled && p.cfg.AiDiagnostics.ChatGptApiKey != ""
}
func (p *OpenAIProvider) DefaultModel() string {
	if p.cfg.AiDiagnostics.SelectedModel != "" {
		return p.cfg.AiDiagnostics.SelectedModel
	}
	return "gpt-4o"
}
func (p *OpenAIProvider) Models() []string {
	return []string{"gpt-4o", "gpt-4o-mini", "gpt-4", "gpt-3.5-turbo"}
}

func (p *OpenAIProvider) Diagnose(ctx context.Context, system, user, model string) (*Diagnosis, error) {
	base := p.cfg.AiDiagnostics.ChatGptApiBase
	if base == "" {
		base = "https://api.openai.com"
	}
	base = strings.TrimRight(base, "/")
	payload, _ := json.Marshal(map[string]interface{}{
		"model": model,
		"messages": []map[string]string{
			{"role": "system", "content": system},
			{"role": "user", "content": user},
		},
		"temperature": 0.3,
	})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, base+"/v1/chat/completions", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+p.cfg.AiDiagnostics.ChatGptApiKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.http.Do(req)
	if err != nil {
		return nil, err
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("openai HTTP %d: %s", resp.StatusCode, truncate(string(body), 300))
	}
	var doc struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if json.Unmarshal(body, &doc) != nil || len(doc.Choices) == 0 {
		return nil, fmt.Errorf("openai: empty response")
	}
	return parseDiagnosis(doc.Choices[0].Message.Content)
}

// ── Koda CLI провайдер ──

// KodaProvider — локальный KodaCode CLI.
type KodaProvider struct {
	cfg *config.Config
}

func (p *KodaProvider) ProviderID() string { return "koda" }
func (p *KodaProvider) Enabled() bool {
	path := p.cfg.AiDiagnostics.CliPath
	if path == "" {
		return false
	}
	_, err := exec.LookPath(path)
	return err == nil
}
func (p *KodaProvider) DefaultModel() string { return "koda-pro" }
func (p *KodaProvider) Models() []string     { return []string{"koda-pro", "koda-pro-mini"} }

func (p *KodaProvider) Diagnose(ctx context.Context, system, user, model string) (*Diagnosis, error) {
	path := p.cfg.AiDiagnostics.CliPath
	cmd := exec.CommandContext(ctx, path, "chat", "-m", model, "--system", system, user)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("koda cli: %v", err)
	}
	return parseDiagnosis(string(out))
}

func parseDiagnosis(content string) (*Diagnosis, error) {
	content = strings.TrimSpace(content)
	// Убираем markdown-обёртки.
	content = strings.TrimPrefix(content, "```json")
	content = strings.TrimPrefix(content, "```")
	content = strings.TrimSuffix(content, "```")
	content = strings.TrimSpace(content)
	var d Diagnosis
	if err := json.Unmarshal([]byte(content), &d); err != nil {
		// Fallback: попытка найти JSON внутри текста.
		start := strings.Index(content, "{")
		end := strings.LastIndex(content, "}")
		if start >= 0 && end > start {
			if err2 := json.Unmarshal([]byte(content[start:end+1]), &d); err2 == nil {
				return &d, nil
			}
		}
		return nil, err
	}
	return &d, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
