// Package config — чтение и хранение конфигурации панели из YAML-файла.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"gopkg.in/yaml.v3"
)

// Config — корневая структура конфигурации (аналог AppSettings из settings.bin).
// JSON-теги соответствуют yaml-тегам — конфигурация сериализуется в JSON
// для графического редактора в панели (пункт 29 IMPROVEMENTS.md).
type Config struct {
	Zeebe         ZeebeConfig         `yaml:"zeebe" json:"zeebe"`
	MSTeams       MSTeamsConfig       `yaml:"msteams" json:"msteams"`
	Docker        DockerConfig        `yaml:"docker" json:"docker"`
	Disk          DiskConfig          `yaml:"disk" json:"disk"`
	Graylog       GraylogConfig       `yaml:"graylog" json:"graylog"`
	ServerCore    ServerCoreConfig    `yaml:"servercore" json:"servercore"`
	AiDiagnostics AiDiagConfig        `yaml:"ai_diagnostics" json:"ai_diagnostics"`
	Ephemeral     EphemeralConfig     `yaml:"ephemeral_access" json:"ephemeral_access"`
	Vault         VaultConfig         `yaml:"vault" json:"vault"`
	ContainerDiag ContainerDiagConfig `yaml:"container_diagnostics" json:"container_diagnostics"`
	Automation    AutomationConfig    `yaml:"automation" json:"automation"`
	Auth          AuthConfig          `yaml:"auth" json:"auth"`
	SecretRefs    SecretRefConfig     `yaml:"secret_refs" json:"secret_refs"`
	Server        ServerConfig        `yaml:"server" json:"server"`
	StagingTLS    StagingTLSConfig    `yaml:"staging_tls" json:"staging_tls"`
}

type ZeebeConfig struct {
	URL                 string `yaml:"url" json:"url"`
	OperatePort         int    `yaml:"operate_port" json:"operate_port"`
	StuckThresholdHours int    `yaml:"stuck_threshold_hours" json:"stuck_threshold_hours"`
	// Multi-окружение: раздельные URL для PROD и TEST (пункт 23).
	ProdURL string `yaml:"prod_url" json:"prod_url"`
	TestURL string `yaml:"test_url" json:"test_url"`
	// ServerName — SSH-сервер (имя ВМ), через который ходит SSH-туннель Zeebe.
	// Если пусто — сервер определяется по IP из URL окружения (надёжнее, чем
	// поиск по шаблону имени "uz-{env}-camunda", т.к. в PROD используется
	// например uz-prod-camunda87-1, а uz-prod-camunda-1 выведен из эксплуатации).
	ServerName string `yaml:"server_name" json:"server_name"`
}

type MSTeamsConfig struct {
	WebhookURL string `yaml:"webhook_url" json:"webhook_url"`
}

type DockerConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
}

type DiskConfig struct {
	RootPath string `yaml:"root_path" json:"root_path"`
	RootName string `yaml:"root_name" json:"root_name"`
}

type GraylogEnvConfig struct {
	URL      string `yaml:"url" json:"url"`
	Username string `yaml:"username" json:"username"`
	Password string `yaml:"password" json:"password"`
}

type GraylogConfig struct {
	ApiPort int              `yaml:"api_port" json:"api_port"`
	Prod    GraylogEnvConfig `yaml:"prod" json:"prod"`
	Test    GraylogEnvConfig `yaml:"test" json:"test"`
}

type ServerCoreConfig struct {
	ApiBase           string `yaml:"api_base" json:"api_base"`
	ApiToken          string `yaml:"api_token" json:"api_token"`
	IamUsername       string `yaml:"iam_username" json:"iam_username"`
	IamDomainName     string `yaml:"iam_domain_name" json:"iam_domain_name"`
	IamPassword       string `yaml:"iam_password" json:"iam_password"`
	IamProjectID      string `yaml:"iam_project_id" json:"iam_project_id"`
	SshPort           int    `yaml:"ssh_port" json:"ssh_port"`
	SshUsername       string `yaml:"ssh_username" json:"ssh_username"`
	SshPrivateKeyPath string `yaml:"ssh_private_key_path" json:"ssh_private_key_path"`
	Enabled           bool   `yaml:"enabled" json:"enabled"`
	// ExcludedServers — серверы (имя или IP), которые исключаются из мониторинга,
	// списков контейнеров, метрик и TLS-аудита (например, выведенные из эксплуатации).
	ExcludedServers []string `yaml:"excluded_servers" json:"excluded_servers"`
	// ServerGroups — правила группировки серверов по имени (regex/substring).
	// Серверы из групп с monitored=false не опрашиваются по SSH.
	ServerGroups []ServerGroupConfig `yaml:"server_groups" json:"server_groups"`
}

// ServerGroupConfig — правило группировки серверов.
type ServerGroupConfig struct {
	Name      string `yaml:"name" json:"name"`           // отображаемое имя группы
	Pattern   string `yaml:"pattern" json:"pattern"`     // substring/regex для поиска в имени сервера
	Monitored bool   `yaml:"monitored" json:"monitored"` // опрашивать по SSH
}

type AiDiagConfig struct {
	CliPath          string `yaml:"cli_path" json:"cli_path"`
	Enabled          bool   `yaml:"enabled" json:"enabled"`
	AutoResolve      bool   `yaml:"auto_resolve" json:"auto_resolve"`
	ChatGptEnabled   bool   `yaml:"chatgpt_enabled" json:"chatgpt_enabled"`
	ChatGptApiKey    string `yaml:"chatgpt_api_key" json:"chatgpt_api_key"`
	ChatGptApiBase   string `yaml:"chatgpt_api_base" json:"chatgpt_api_base"`
	SelectedProvider string `yaml:"selected_provider" json:"selected_provider"`
	SelectedModel    string `yaml:"selected_model" json:"selected_model"`
}

type EphemeralConfig struct {
	Enabled                bool `yaml:"enabled" json:"enabled"`
	DefaultDurationMinutes int  `yaml:"default_duration_minutes" json:"default_duration_minutes"`
	MaxDurationMinutes     int  `yaml:"max_duration_minutes" json:"max_duration_minutes"`
	MaxActiveKeysPerServer int  `yaml:"max_active_keys_per_server" json:"max_active_keys_per_server"`
	AutoCleanupExpired     bool `yaml:"auto_cleanup_expired" json:"auto_cleanup_expired"`
}

type VaultConfig struct {
	ApiBase         string `yaml:"api_base" json:"api_base"`
	RootToken       string `yaml:"root_token" json:"root_token"`
	UseRootToken    bool   `yaml:"use_root_token" json:"use_root_token"`
	Enabled         bool   `yaml:"enabled" json:"enabled"`
	Kv1Path         string `yaml:"kv1_path" json:"kv1_path"`
	Kv2Path         string `yaml:"kv2_path" json:"kv2_path"`
	CacheTtlMinutes int    `yaml:"cache_ttl_minutes" json:"cache_ttl_minutes"`
}

type ContainerDiagConfig struct {
	WarnCpuPercent        float64 `yaml:"warn_cpu_percent" json:"warn_cpu_percent"`
	WarnMemoryPercent     float64 `yaml:"warn_memory_percent" json:"warn_memory_percent"`
	CriticalServerPercent float64 `yaml:"critical_server_percent" json:"critical_server_percent"`
	RestartCountThreshold int     `yaml:"restart_count_threshold" json:"restart_count_threshold"`
	StaleDaysThreshold    int     `yaml:"stale_days_threshold" json:"stale_days_threshold"`
	MemoryLeakPercent     float64 `yaml:"memory_leak_percent" json:"memory_leak_percent"`
}

type ServerConfig struct {
	ListenAddr string `yaml:"listen_addr" json:"listen_addr"`
}

type AutomationConfig struct {
	GitLabApiBase   string `yaml:"gitlab_api_base" json:"gitlab_api_base"`
	GitLabToken     string `yaml:"gitlab_token" json:"gitlab_token"`
	RepoProjectPath string `yaml:"repo_project_path" json:"repo_project_path"`
	RepoBranch      string `yaml:"repo_branch" json:"repo_branch"`
	ExecServerHost  string `yaml:"exec_server_host" json:"exec_server_host"`
}

type AuthConfig struct {
	Enabled  bool   `yaml:"enabled" json:"enabled"`
	Username string `yaml:"username" json:"username"`
	Password string `yaml:"password" json:"password"`
}

// SecretRefConfig — настройки шифрования секретов через Vault (пункт 22).
type SecretRefConfig struct {
	Enabled     bool   `yaml:"enabled" json:"enabled"`
	VaultPrefix string `yaml:"vault_prefix" json:"vault_prefix"` // например "kv/data/paylater-mon/config"
}

// StagingTLSConfig — настройки раздела проверки готовности PROD к TLS 1.3.
type StagingTLSConfig struct {
	Enabled             bool `yaml:"enabled" json:"enabled"`
	LoadTestConnections int  `yaml:"load_test_connections" json:"load_test_connections"`
	LoadTestConcurrency int  `yaml:"load_test_concurrency" json:"load_test_concurrency"`
	MaxProdScan         int  `yaml:"max_prod_scan" json:"max_prod_scan"`                 // макс. PROD-серверов для проверки
	LoadTestTargetPort  int  `yaml:"load_test_target_port" json:"load_test_target_port"` // порт для нагрузочного теста (0 — все TLS-порты)
	LoadTestTimeoutSec  int  `yaml:"load_test_timeout_sec" json:"load_test_timeout_sec"`
	ScanConcurrency     int  `yaml:"scan_concurrency" json:"scan_concurrency"` // параллельных SSH/TLS сканов (0 = 4)
	NginxFronted        bool `yaml:"nginx_fronted" json:"nginx_fronted"`       // всё за NAT + nginx (TLS 1.2/1.3) — внутренние сервисы не помечаются
}

// Default возвращает конфигурацию со значениями по умолчанию.
func Default() *Config {
	return &Config{
		Zeebe:   ZeebeConfig{URL: "", OperatePort: 8080, StuckThresholdHours: 24},
		MSTeams: MSTeamsConfig{},
		Docker:  DockerConfig{Enabled: true},
		Disk:    DiskConfig{RootPath: "/", RootName: "Корневой раздел /"},
		Graylog: GraylogConfig{ApiPort: 9000},
		ServerCore: ServerCoreConfig{
			ApiBase: "https://cloud.api.servercore.com", IamUsername: "paylater-iam",
			IamDomainName: "608542", IamProjectID: "ca09f8486a0f46799ead80fec64ab962",
			SshPort: 22, SshUsername: "root", Enabled: true,
			ServerGroups: []ServerGroupConfig{
				{Name: "Mikrotik", Pattern: "mkrt", Monitored: false},
				{Name: "Администрация", Pattern: "adm", Monitored: false},
				{Name: "Мобилка", Pattern: "mob", Monitored: true},
				{Name: "Тестовые", Pattern: "test", Monitored: true},
				{Name: "Боевые", Pattern: "prod", Monitored: true},
			},
		},
		AiDiagnostics: AiDiagConfig{
			Enabled: true, ChatGptEnabled: true, ChatGptApiBase: "https://api.openai.com",
			SelectedProvider: "chatgpt", SelectedModel: "gpt-4o",
		},
		Ephemeral:     EphemeralConfig{Enabled: true, DefaultDurationMinutes: 60, MaxDurationMinutes: 480, MaxActiveKeysPerServer: 5, AutoCleanupExpired: true},
		Vault:         VaultConfig{UseRootToken: true, Enabled: true, Kv1Path: "ephemeral", Kv2Path: "ephemeral/data", CacheTtlMinutes: 5},
		ContainerDiag: ContainerDiagConfig{WarnCpuPercent: 80, WarnMemoryPercent: 80, CriticalServerPercent: 90, RestartCountThreshold: 5, StaleDaysThreshold: 30, MemoryLeakPercent: 90},
		Automation:    AutomationConfig{GitLabApiBase: "https://gl-01.paylater.uz", RepoBranch: "main", ExecServerHost: "uz-adm-nuget-1"},
		Auth:          AuthConfig{Enabled: false, Username: "admin", Password: "admin"},
		SecretRefs:    SecretRefConfig{Enabled: false, VaultPrefix: "kv/data/paylater-mon/config"},
		Server:        ServerConfig{ListenAddr: "0.0.0.0:9090"},
		StagingTLS:    StagingTLSConfig{Enabled: true, LoadTestConnections: 20, LoadTestConcurrency: 5, MaxProdScan: 20, LoadTestTimeoutSec: 60, NginxFronted: true},
	}
}

// Load читает YAML-файл конфигурации, создаёт дефолтную при отсутствии.
func Load(path string) (*Config, error) {
	cfg := Default()
	if path == "" {
		return cfg, nil
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		if os.IsNotExist(err) {
			// Создаём дефолтный файл, чтобы его можно было заполнить.
			_ = Save(abs, cfg)
			return cfg, nil
		}
		return nil, err
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", abs, err)
	}
	return cfg, nil
}

// Save записывает конфигурацию в YAML-файл.
func Save(path string, cfg *Config) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// Store — потокобезопасная обёртка над *Config для динамического обновления.
type Store struct {
	mu   sync.RWMutex
	path string
	cfg  *Config
}

func NewStore(path string) (*Store, error) {
	cfg, err := Load(path)
	if err != nil {
		return nil, err
	}
	return &Store{path: path, cfg: cfg}, nil
}

func (s *Store) Get() *Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg
}

// Path возвращает путь к файлу конфигурации.
func (s *Store) Path() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.path
}

func (s *Store) Set(cfg *Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := Save(s.path, cfg); err != nil {
		return err
	}
	s.cfg = cfg
	return nil
}
