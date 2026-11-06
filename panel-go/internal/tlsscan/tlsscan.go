// Package tlsscan — комплексная проверка TLS/HTTP-конфигурации серверов.
//
// Что проверяется (комплексно, по всем возможным параметрам):
//   - версии TLS (1.0..1.3) и cipher suites на КАЖДОМ обнаруженном порту,
//     а не только на стандартных: для Linux список слушающих портов
//     собирается через `ss`/`netstat` + порты Docker, затем объединяется
//     с расширенным списком DefaultPorts;
//   - протокол на порту: TLS / HTTPS / HTTP (plaintext) / TCP / закрыт —
//     делается GET-запрос, чтобы понять, что именно работает на порту;
//   - nginx (Linux): установлен ли, запущен ли, ssl_protocols, listen ... ssl,
//     проблемы конфигурации;
//   - Docker (Linux): опубликованные (проброшенные) порты контейнеров;
//   - ОС определяется БЕЗ SSH для Windows/MikroTik: по имени образа ОС из
//     ServerCore (Nova), только если ОС неизвестна — один запрос `uname -a`.
//
// Движки:
//   - Linux: OpenSSL через SSH (полная детекция версий TLS и cipher suites)
//   - HTTP-детектор через SSH-туннель + анализ nginx и Docker;
//   - Windows: встроенный сканер (crypto/tls) ПРЯМЫМ соединением IP:порт,
//     SSH НЕ используется;
//   - MikroTik/RouterOS: встроенный сканер прямым соединением IP:порт,
//     SSH НЕ используется (на RouterOS нет openssl s_client);
//   - неизвестная ОС: встроенный сканер прямым соединением.
//
// По результатам формируются рекомендации по усилению TLS и включению HTTPS.
package tlsscan

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"paylater-mon/internal/servercore"
	"paylater-mon/internal/sshclient"
)

// EngineName — название встроенного движка сканирования.
const EngineName = "встроенный сканер (crypto/tls)"

// EngineOpenSSL — название движка OpenSSL (Linux).
const EngineOpenSSL = "openssl (SSH)"

// Операционные системы (определяются по Nova, без SSH).
const (
	OSUnknown  = "unknown"
	OSLinux    = "Linux"
	OSWindows  = "Windows"
	OSMikrotik = "MikroTik (RouterOS)"
	OSMacOS    = "macOS"
	OSFreeBSD  = "FreeBSD"
)

// Протоколы, обнаруживаемые на порту.
const (
	ProtoClosed   = "closed" // порт не отвечает
	ProtoPlainTCP = "tcp"    // TCP есть, но ни TLS, ни HTTP
	ProtoHTTP     = "http"   // plaintext HTTP
	ProtoTLS      = "tls"    // TLS-рукопожатие успешно
	ProtoHTTPS    = "https"  // TLS + HTTP поверх
)

// Таймауты на одну попытку (dial + рукопожатие).
const (
	connectTimeout    = 3 * time.Second
	handshakeTimeout  = 3 * time.Second
	attemptTimeout    = 6 * time.Second
	serverScanTimeout = 90 * time.Second
)

// Версии TLS в порядке убывания важности (проверяются на портах).
const (
	TLS10 = "TLS 1.0"
	TLS11 = "TLS 1.1"
	TLS12 = "TLS 1.2"
	TLS13 = "TLS 1.3"
)

// tlsVersions — порядок проверки версий.
var tlsVersions = []string{TLS10, TLS11, TLS12, TLS13}

// DefaultPorts — расширенный список портов (обычные + популярные сервисные:
// панели, метрики, Camunda/Zeebe, Graylog, Elasticsearch, RabbitMQ, k8s, прокси).
var DefaultPorts = []int{
	80, 443, 4433, 4443, 5000, 5432, 5601, 6443, 8000, 8008, 8009, 8065,
	8070, 8071, 8072, 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089,
	8090, 8140, 8280, 8403, 8443, 8500, 8800, 8880, 8888, 9000, 9001, 9042, 9090,
	9092, 9093, 9100, 9200, 9300, 9443, 9600, 10000, 15672, 17000, 17001, 18080,
	19090, 20000, 30000, 31400,
}

// CertInfo — информация о TLS-сертификате порта (пункт 46 IMPROVEMENTS.md).
type CertInfo struct {
	Subject        string    `json:"subject"`
	Issuer         string    `json:"issuer"`
	SANs           []string  `json:"sans,omitempty"`
	NotBefore      time.Time `json:"not_before"`
	NotAfter       time.Time `json:"not_after"`
	SerialNumber   string    `json:"serial_number"`
	SigAlgorithm   string    `json:"sig_algorithm"`
	HostnameMatch  bool      `json:"hostname_match"`  // CN/SAN соответствует имени сервера
	SelfSigned     bool      `json:"self_signed"`     // самоподписанный
	AutoRenew      string    `json:"auto_renew"`      // механизм автопродления: Let's Encrypt / Vault PKI / нет
	ExpiresInDays  int       `json:"expires_in_days"` // дней до истечения (отрицательное — истёк)
	IsExpired      bool      `json:"is_expired"`
	IsExpiringSoon bool      `json:"is_expiring_soon"` // меньше 30 дней
}

// DaysLeft возвращает строку «осталось N дней» / «истёк».
func (c *CertInfo) DaysLeft() string {
	if c == nil {
		return ""
	}
	if c.IsExpired {
		return "истёк"
	}
	if c.ExpiresInDays <= 30 {
		return fmt.Sprintf("%d дн.", c.ExpiresInDays)
	}
	return fmt.Sprintf("%d дн.", c.ExpiresInDays)
}

// PortResult — результат проверки одного порта.
type PortResult struct {
	Port        int
	Versions    map[string]bool // TLS 1.0..1.3 → поддерживается ли
	Protocol    string          // closed / tcp / http / tls / https
	Service     string          // nginx / docker / app / unknown
	Ciphers     []string        // рабочие cipher suites (Linux/openssl)
	WeakCiphers []string        // слабые: RC4, 3DES, CBC-SHA1
	// Пункт 47: HTTP/2 (ALPN) и 0-RTT.
	ALPN  []string // согласованные протоколы ALPN: h2, http/1.1, h3
	HTTP2 bool     // поддерживается HTTP/2 (h2)
	HTTP3 bool     // поддерживается HTTP/3 (h3) — определяется по Alt-Svc
	// Пункт 46: сертификат.
	Cert *CertInfo `json:"cert,omitempty"`
	// Редирект HTTP→HTTPS (301/308), если порт отдаёт HTTP.
	HTTPRedirect string `json:"http_redirect,omitempty"`
	Error        string
}

// NginxInfo — результат анализа nginx (Linux).
type NginxInfo struct {
	Installed    bool
	Running      bool
	ConfigPath   string
	SSLProtocols []string
	ListenSSL    []int
	Issues       []string
}

// ServerTLS — результат комплексной проверки одного сервера.
type ServerTLS struct {
	ServerName      string
	IP              string
	OS              string
	Engine          string
	Ports           []PortResult
	Nginx           NginxInfo
	DockerPorts     []int
	HTTPPorts       []int
	Recommendations []string
	Error           string
}

// SupportedPorts возвращает порты, на которых обнаружен хотя бы один TLS.
func (s ServerTLS) SupportedPorts() []PortResult {
	var out []PortResult
	for _, p := range s.Ports {
		if portSupported(p) {
			out = append(out, p)
		}
	}
	return out
}

// portSupported — есть ли хотя бы одна поддерживаемая версия TLS на порту.
func portSupported(pr PortResult) bool {
	for _, ok := range pr.Versions {
		if ok {
			return true
		}
	}
	return false
}

// tlsDialer — абстракция открытия TCP-соединения (через SSH-туннель или напрямую).
type tlsDialer func(ctx context.Context, addr string) (net.Conn, error)

// Scanner — встроенный TLS-сканер через SSH-туннель.
type Scanner struct {
	sc    *servercore.Service
	ports []int
}

// New создаёт сканер. Если ports пуст — используются DefaultPorts.
func New(sc *servercore.Service, ports []int) *Scanner {
	if len(ports) == 0 {
		ports = DefaultPorts
	}
	return &Scanner{sc: sc, ports: ports}
}

// Scan — комплексная проверка одного сервера: TLS, HTTP, nginx, Docker.
func (s *Scanner) Scan(ctx context.Context, serverName string) ServerTLS {
	res := ServerTLS{ServerName: serverName, Ports: []PortResult{}, Engine: EngineName}

	// Защитный таймаут на сканирование одного сервера — всегда.
	// Даже если родительский контекст имеет дедлайн (например, staging scan
	// с общим таймаутом 10 мин), один сервер не должен занимать больше
	// serverScanTimeout (90с). Без этого один зависший сервер блокирует
	// всю параллельную проверку.
	ctx, cancel := context.WithTimeout(ctx, serverScanTimeout)
	defer cancel()

	// Находим IP и ОС сервера в ServerCore (Nova).
	servers, _ := s.sc.GetServers(ctx)
	novaOS := ""
	for _, sv := range servers {
		if strings.EqualFold(sv.Name, serverName) {
			res.IP = sv.IpAddress
			novaOS = sv.OperatingSystem
			break
		}
	}
	if res.IP == "" {
		res.Error = "сервер не найден в ServerCore"
		return res
	}

	// ОС определяется БЕЗ SSH для Windows/MikroTik (по имени образа Nova).
	res.OS = detectOS(ctx, s.sc, serverName, novaOS)

	switch res.OS {
	case OSLinux:
		// Linux: OpenSSL через SSH + полный список портов + nginx + docker.
		res.Engine = EngineOpenSSL + " + nginx + docker"
		s.scanLinux(ctx, &res)
	case OSWindows:
		// Windows: встроенный сканер, SSH НЕ используется вообще.
		res.Engine = EngineName + " (без SSH)"
		s.scanDirect(ctx, &res, s.ports)
	case OSMikrotik:
		// MikroTik: встроенный сканер прямым соединением (нет openssl s_client).
		res.Engine = EngineName + " (прямое соединение)"
		s.scanDirect(ctx, &res, s.ports)
	default:
		// Неизвестная ОС — встроенный сканер прямым соединением, без SSH.
		res.Engine = EngineName + " (прямое соединение)"
		s.scanDirect(ctx, &res, s.ports)
	}

	res.Recommendations = buildRecommendations(res)
	return res
}

// detectOS определяет ОС. Windows/MikroTik распознаются по имени образа ОС
// из ServerCore (Nova) БЕЗ SSH. Если ОС в Nova не указана — один запрос
// `uname -a` (Windows-серверы через OpenSSH на него просто не отвечают).
func detectOS(ctx context.Context, sc *servercore.Service, serverName, novaOS string) string {
	lo := strings.ToLower(strings.TrimSpace(novaOS))
	switch {
	case strings.Contains(lo, "windows") || strings.HasPrefix(lo, "win"):
		return OSWindows
	case strings.Contains(lo, "mikrotik") || strings.Contains(lo, "routeros"):
		return OSMikrotik
	case strings.Contains(lo, "linux"):
		return OSLinux
	case strings.Contains(lo, "freebsd"):
		return OSFreeBSD
	case strings.Contains(lo, "darwin") || strings.Contains(lo, "macos"):
		return OSMacOS
	}
	// SSH — только для неустановленной ОС.
	if out, err := sc.RunSSHCommand(ctx, serverName, "uname -a"); err == nil {
		l := strings.ToLower(out)
		switch {
		case strings.Contains(l, "mikrotik") || strings.Contains(l, "routeros"):
			return OSMikrotik
		case strings.Contains(l, "linux"):
			return OSLinux
		case strings.Contains(l, "darwin"):
			return OSMacOS
		case strings.Contains(l, "freebsd"):
			return OSFreeBSD
		}
	}
	return OSUnknown
}

// ── Встроенный скан портов (прямое соединение, без SSH) ──

// scanDirect сканирует порты ПРЯМЫМ соединением IP:порт. Используется для
// Windows, MikroTik и неизвестных ОС — SSH к таким серверам не выполняется.
func (s *Scanner) scanDirect(ctx context.Context, res *ServerTLS, ports []int) {
	dial := makeDirectDialer()
	connectFailed := 0
	for _, p := range ports {
		pr := probePort(ctx, dial, net.JoinHostPort(res.IP, fmt.Sprint(p)), res.ServerName, p)
		if pr.Error != "" {
			connectFailed++
		}
		if pr.Protocol == ProtoHTTP {
			res.HTTPPorts = append(res.HTTPPorts, p)
		}
		res.Ports = append(res.Ports, pr)
	}
	if connectFailed == len(ports) {
		res.Error = "сервисные порты не отвечают по прямому соединению"
	}
}

// makeDirectDialer — прямое TCP-соединение к IP:порт.
func makeDirectDialer() tlsDialer {
	d := &net.Dialer{Timeout: connectTimeout}
	return func(ctx context.Context, addr string) (net.Conn, error) {
		return d.DialContext(ctx, "tcp", addr)
	}
}

// makeDialer возвращает функцию открытия соединения: через SSH-туннель
// (если клиент есть) или напрямую net.Dialer.
func makeDialer(client *sshclient.Client) tlsDialer {
	if client != nil {
		return func(ctx context.Context, addr string) (net.Conn, error) {
			return client.DialContext(ctx, "tcp", addr)
		}
	}
	return makeDirectDialer()
}

// probePort проверяет все версии TLS на одном порту и определяет протокол
// (TLS / HTTPS / HTTP / TCP / закрыт).
func probePort(ctx context.Context, dial tlsDialer, addr, serverName string, port int) PortResult {
	pr := PortResult{Port: port, Versions: map[string]bool{}, Protocol: ProtoClosed}

	// Быстрая проверка: слушает ли порт вообще (один короткий dial вместо 4).
	checkCtx, cancel := context.WithTimeout(ctx, attemptTimeout)
	conn, err := dial(checkCtx, addr)
	cancel()
	if err != nil {
		pr.Error = "порт недоступен: " + err.Error()
		return pr
	}
	_ = conn.Close()
	pr.Protocol = ProtoPlainTCP

	for _, ver := range tlsVersions {
		ok, verr := probeVersion(ctx, dial, addr, serverName, ver)
		if verr != nil {
			pr.Error = "ошибка проверки: " + verr.Error()
			pr.Versions[ver] = false
			continue
		}
		pr.Versions[ver] = ok
	}
	if portSupported(pr) {
		pr.Protocol = ProtoTLS
		if probeHTTPOverTLS(ctx, dial, addr, serverName) {
			pr.Protocol = ProtoHTTPS
		}
		// Пункты 46-47: сертификат, ALPN (h2/http2), HTTP/3 по Alt-Svc.
		cert, alpn, h3 := probeCertALPN(ctx, dial, addr, serverName)
		if cert != nil {
			pr.Cert = cert
		}
		if len(alpn) > 0 {
			pr.ALPN = alpn
			for _, p := range alpn {
				if p == "h2" {
					pr.HTTP2 = true
				}
			}
		}
		pr.HTTP3 = h3
	} else if probeHTTP(ctx, dial, addr) {
		pr.Protocol = ProtoHTTP
		// Пункт 47: редирект HTTP→HTTPS (301/308).
		pr.HTTPRedirect = checkHTTPRedirect(ctx, dial, addr)
	}
	return pr
}

// probeCertALPN выполняет одно TLS-рукопожатие (TLS 1.2+) и извлекает:
//   - цепочку сертификатов (пункт 46): subject/issuer/SAN/срок действия,
//     соответствие hostname, автопродление (Let's Encrypt / Vault PKI);
//   - согласованный ALPN (пункт 47): h2, http/1.1;
//   - признак HTTP/3 по заголовку Alt-Svc в ответе HTTP/2.
func probeCertALPN(ctx context.Context, dial tlsDialer, addr, serverName string) (*CertInfo, []string, bool) {
	attemptCtx, cancel := context.WithTimeout(ctx, attemptTimeout)
	defer cancel()

	conn, err := dial(attemptCtx, addr)
	if err != nil {
		return nil, nil, false
	}
	defer conn.Close()

	tconn := tls.Client(conn, &tls.Config{
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS13,
		ServerName:         serverName,
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
	})
	_ = tconn.SetDeadline(time.Now().Add(handshakeTimeout))
	if err := tconn.HandshakeContext(attemptCtx); err != nil {
		return nil, nil, false
	}

	state := tconn.ConnectionState()
	var alpn []string
	if state.NegotiatedProtocol != "" {
		alpn = append(alpn, state.NegotiatedProtocol)
	}

	h3 := false
	// HTTP/3 определяется по заголовку Alt-Svc (quic) в ответе HTTP/2.
	if state.NegotiatedProtocol == "h2" {
		req := "GET / HTTP/1.1\r\nHost: " + serverName + "\r\nAccept: */*\r\nConnection: close\r\n\r\n"
		_ = tconn.SetDeadline(time.Now().Add(handshakeTimeout))
		if _, err := io.WriteString(tconn, req); err == nil {
			br := bufio.NewReader(tconn)
			for {
				line, err := br.ReadString('\n')
				if err != nil {
					break
				}
				lt := strings.ToLower(strings.TrimSpace(line))
				if strings.HasPrefix(lt, "alt-svc:") && (strings.Contains(lt, "h3") || strings.Contains(lt, "quic")) {
					h3 = true
				}
				if strings.TrimSpace(line) == "" {
					break
				}
			}
		}
	}

	var cert *CertInfo
	if len(state.PeerCertificates) > 0 {
		c := state.PeerCertificates[0]
		days := int(time.Until(c.NotAfter).Hours() / 24)
		cert = &CertInfo{
			Subject:        c.Subject.CommonName,
			Issuer:         c.Issuer.CommonName,
			SANs:           append([]string{}, c.DNSNames...),
			NotBefore:      c.NotBefore,
			NotAfter:       c.NotAfter,
			SerialNumber:   c.SerialNumber.String(),
			SigAlgorithm:   c.SignatureAlgorithm.String(),
			SelfSigned:     c.Subject.String() == c.Issuer.String() || len(state.PeerCertificates) == 1,
			ExpiresInDays:  days,
			IsExpired:      days < 0,
			IsExpiringSoon: days >= 0 && days <= 30,
		}
		cert.HostnameMatch = c.VerifyHostname(serverName) == nil
		cert.AutoRenew = detectAutoRenew(c, state.PeerCertificates)
	}
	return cert, alpn, h3
}

// detectAutoRenew определяет механизм автопродления сертификата по издателю
// и цепочке: Let's Encrypt (certbot), Vault PKI, иначе — не обнаружено.
func detectAutoRenew(leaf *x509.Certificate, chain []*x509.Certificate) string {
	issuer := strings.ToLower(leaf.Issuer.String())
	if strings.Contains(issuer, "let's encrypt") || strings.Contains(issuer, "letsencrypt") {
		return "Let's Encrypt (certbot, автопродление)"
	}
	if strings.Contains(issuer, "r3") || strings.Contains(issuer, "e5") || strings.Contains(issuer, "isrg root") {
		return "Let's Encrypt (автопродление)"
	}
	if strings.Contains(issuer, "vault") || strings.Contains(issuer, "pki") {
		return "Vault PKI (автопродление)"
	}
	if len(chain) > 1 {
		return "CA-подписан (ручное продление)"
	}
	return "не обнаружено (проверьте вручную)"
}

// checkHTTPRedirect проверяет, отвечает ли HTTP-порт редиректом HTTP→HTTPS
// (301/308 с Location на https://). Возвращает целевой URL или "".
func checkHTTPRedirect(ctx context.Context, dial tlsDialer, addr string) string {
	attemptCtx, cancel := context.WithTimeout(ctx, attemptTimeout)
	defer cancel()

	conn, err := dial(attemptCtx, addr)
	if err != nil {
		return ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))

	req := "GET / HTTP/1.0\r\nHost: x\r\nAccept: */*\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		return ""
	}
	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		return ""
	}
	if !strings.Contains(statusLine, "301") && !strings.Contains(statusLine, "308") && !strings.Contains(statusLine, "302") {
		return ""
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return ""
		}
		line = strings.TrimSpace(line)
		if line == "" {
			break
		}
		if strings.HasPrefix(strings.ToLower(line), "location:") {
			loc := strings.TrimSpace(line[len("Location:"):])
			if strings.HasPrefix(loc, "https://") || strings.HasPrefix(loc, "//") {
				return loc
			}
		}
	}
	return ""
}

// probeVersion выполняет TLS-рукопожатие конкретной версией протокола.
// ok=true — сервер ответил успешным рукопожатием этой версией.
func probeVersion(ctx context.Context, dial tlsDialer, addr, serverName, ver string) (bool, error) {
	attemptCtx, cancel := context.WithTimeout(ctx, attemptTimeout)
	defer cancel()

	conn, err := dial(attemptCtx, addr)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	tconn := tls.Client(conn, &tls.Config{
		MinVersion:         versionID(ver),
		MaxVersion:         versionID(ver),
		ServerName:         serverName,
		InsecureSkipVerify: true,
	})
	_ = tconn.SetDeadline(time.Now().Add(handshakeTimeout))
	if err := tconn.HandshakeContext(attemptCtx); err != nil {
		// Рукопожатие не удалось — сервер не поддерживает эту версию
		// (либо порт говорит не по TLS).
		return false, nil
	}
	return true, nil
}

// versionID сопоставляет название версии с константой crypto/tls.
func versionID(ver string) uint16 {
	switch ver {
	case TLS10:
		return tls.VersionTLS10
	case TLS11:
		return tls.VersionTLS11
	case TLS12:
		return tls.VersionTLS12
	case TLS13:
		return tls.VersionTLS13
	}
	return 0
}

// ── Linux: OpenSSL через SSH ──

// opensslFlag — флаг версии для openssl s_client.
func opensslFlag(ver string) string {
	switch ver {
	case TLS10:
		return "-tls1"
	case TLS11:
		return "-tls1_1"
	case TLS12:
		return "-tls1_2"
	case TLS13:
		return "-tls1_3"
	}
	return ""
}

// flagVersion — обратное сопоставление флага openssl с названием версии.
func flagVersion(flag string) string {
	switch strings.TrimSpace(flag) {
	case "tls1":
		return TLS10
	case "tls1_1":
		return TLS11
	case "tls1_2":
		return TLS12
	case "tls1_3":
		return TLS13
	}
	return ""
}

// opensslScript возвращает bash-скрипт, проверяющий все версии TLS на порту
// через openssl s_client (по одной команде на каждую версию). Выход:
// "tls1_2=YES <cipher>", "tls1_3=NO" и т.д. по строкам.
func opensslScript(port int) string {
	lines := make([]string, 0, len(tlsVersions))
	for _, ver := range tlsVersions {
		lines = append(lines, fmt.Sprintf(
			`r=$(timeout 3 openssl s_client -connect 127.0.0.1:%d %s </dev/null 2>&1); if echo "$r" | grep -qE 'BEGIN CERTIFICATE|SSL-Session'; then c=$(echo "$r" | grep -iE '^ *Cipher *:' | head -1 | sed 's/.*: *//'); echo "%s=YES $c"; else echo "%s=NO"; fi`,
			port, opensslFlag(ver), opensslFlag(ver), opensslFlag(ver)))
	}
	return "timeout 20 bash -c \"" + strings.Join(lines, "; ") + "\""
}

// perPortTimeout — таймаут на проверку одного порта в scanLinux.
const perPortTimeout = 15 * time.Second

// scanLinux — комплексная проверка Linux-сервера через SSH:
// OpenSSL (версии TLS и cipher suites), полный список портов (ss/netstat + Docker),
// HTTP-детекция, анализ nginx и проброшенных портов контейнеров.
// Одно SSH-соединение переиспользуется на всё.
func (s *Scanner) scanLinux(ctx context.Context, res *ServerTLS) {
	client, err := s.sc.GetSSHClient(ctx, res.ServerName)
	if err != nil || client == nil {
		res.Error = "SSH недоступен: " + err.Error()
		// Fallback на встроенный сканер (прямое соединение).
		s.scanDirect(ctx, res, s.ports)
		return
	}
	defer client.Close()

	// Проверяем наличие openssl на сервере.
	out, err := client.RunContext(ctx, "command -v openssl")
	hasOpenSSL := err == nil && strings.TrimSpace(out) != ""
	if !hasOpenSSL {
		res.Error = "openssl не установлен на сервере — используются встроенный сканер и HTTP-детектор"
	}

	// Docker: опубликованные порты контейнеров.
	dockerPorts := s.scanDockerPorts(ctx, client)
	res.DockerPorts = dockerPorts

	// Nginx: конфигурация и проблемы.
	res.Nginx = s.scanNginx(ctx, client)

	// Полный список портов: DefaultPorts + Docker + слушающие (ss/netstat).
	ports := s.collectPorts(ctx, client, dockerPorts)

	tunnelDial := makeDialer(client)
	for _, p := range ports {
		// Проверяем контекст перед каждым портом — если время вышло, выходим.
		if ctx.Err() != nil {
			break
		}
		// Per-port таймаут: один порт не должен занимать больше perPortTimeout.
		portCtx, portCancel := context.WithTimeout(ctx, perPortTimeout)

		pr := PortResult{Port: p, Versions: map[string]bool{}, Protocol: ProtoClosed}
		addr := net.JoinHostPort("127.0.0.1", fmt.Sprint(p))

		if hasOpenSSL {
			out, err := client.RunContext(portCtx, opensslScript(p))
			if err != nil && strings.TrimSpace(out) == "" {
				pr.Error = "ошибка openssl: " + err.Error()
			}
			mergeOpenSSLOut(&pr, out)
			if portSupported(pr) {
				pr.Ciphers = extractCiphers(pr)
				pr.WeakCiphers = weakCipherList(pr.Ciphers)
			}
		} else {
			// Без openssl — встроенные TLS-пробы через SSH-туннель.
			for _, ver := range tlsVersions {
				ok, _ := probeVersion(portCtx, tunnelDial, addr, res.ServerName, ver)
				pr.Versions[ver] = ok
			}
		}

		finalizeProto(&pr, portCtx, tunnelDial, addr, res.ServerName)
		portCancel()
		// Пункты 46-47: для Linux сертификат/ALPN/редирект тоже снимаются
		// через SSH-туннель (один Go TLS-handshake, не зависит от openssl).
		if portSupported(pr) {
			cert, alpn, h3 := probeCertALPN(ctx, tunnelDial, addr, res.ServerName)
			if cert != nil {
				pr.Cert = cert
			}
			if len(alpn) > 0 {
				pr.ALPN = alpn
				for _, a := range alpn {
					if a == "h2" {
						pr.HTTP2 = true
					}
				}
			}
			pr.HTTP3 = h3
		} else if pr.Protocol == ProtoHTTP {
			pr.HTTPRedirect = checkHTTPRedirect(ctx, tunnelDial, addr)
		}
		if pr.Protocol == ProtoHTTP {
			res.HTTPPorts = append(res.HTTPPorts, p)
		}
		res.Ports = append(res.Ports, pr)
	}
}

// collectPorts собирает полный список портов для проверки:
// сконфигурированные + Docker + слушающие (ss -tln / netstat -tln).
func (s *Scanner) collectPorts(ctx context.Context, client *sshclient.Client, extra []int) []int {
	seen := map[int]bool{}
	var out []int
	add := func(ps []int) {
		for _, p := range ps {
			if p > 0 && p < 65536 && !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	add(s.ports)
	add(extra)

	listCmd := `ss -tln 2>/dev/null | awk 'NR>1{split($4,a,":"); p=a[length(a)]; if(p ~ /^[0-9]+$/) print p}' | sort -un`
	if lout, err := client.RunContext(ctx, listCmd); err == nil && strings.TrimSpace(lout) != "" {
		for _, ln := range strings.Split(lout, "\n") {
			if n, aerr := strconv.Atoi(strings.TrimSpace(ln)); aerr == nil {
				add([]int{n})
			}
		}
		return out
	}
	// Fallback на netstat.
	lout, _ := client.RunContext(ctx, `netstat -tln 2>/dev/null | awk 'NR>2{split($4,a,":"); p=a[length(a)]; if(p ~ /^[0-9]+$/) print p}' | sort -un`)
	for _, ln := range strings.Split(lout, "\n") {
		if n, aerr := strconv.Atoi(strings.TrimSpace(ln)); aerr == nil {
			add([]int{n})
		}
	}
	return out
}

// scanDockerPorts возвращает хост-порты, опубликованные контейнерами Docker.
func (s *Scanner) scanDockerPorts(ctx context.Context, client *sshclient.Client) []int {
	out, err := client.RunContext(ctx, `docker ps --format '{{.Ports}}'`)
	if err != nil {
		return nil
	}
	return parseDockerPortsOutput(out)
}

// parseDockerPortsOutput извлекает опубликованные хост-порты из вывода
// `docker ps --format '{{.Ports}}'` ("0.0.0.0:8080->80/tcp", ":::8443->8443/tcp").
func parseDockerPortsOutput(out string) []int {
	seen := map[int]bool{}
	var ports []int
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line == "<no value>" || line == "null" {
			continue
		}
		for _, entry := range strings.Split(line, ",") {
			entry = strings.TrimSpace(entry)
			if entry == "" {
				continue
			}
			// Формат: "0.0.0.0:8080->80/tcp" или ":::8443->8443/tcp".
			if i := strings.Index(entry, "->"); i >= 0 {
				host := entry[:i]
				j := strings.LastIndex(host, ":")
				if j >= 0 {
					host = host[j+1:]
				}
				if n, aerr := strconv.Atoi(strings.TrimSpace(host)); aerr == nil && n > 0 {
					if !seen[n] {
						seen[n] = true
						ports = append(ports, n)
					}
				}
			}
		}
	}
	return ports
}

// scanNginx анализирует nginx на сервере: установлен, запущен, ssl_protocols,
// listen ... ssl, проблемы конфигурации.
func (s *Scanner) scanNginx(ctx context.Context, client *sshclient.Client) NginxInfo {
	var n NginxInfo
	out, err := client.RunContext(ctx, "command -v nginx")
	if err != nil || strings.TrimSpace(out) == "" {
		return n
	}
	n.Installed = true
	if cpath, err := client.RunContext(ctx, "nginx -t 2>&1"); err == nil && strings.Contains(cpath, "configuration file") {
		// "nginx: configuration file /etc/nginx/nginx.conf test failed" / "syntax is ok"
		for _, ln := range strings.Split(cpath, "\n") {
			if i := strings.Index(ln, "configuration file"); i >= 0 {
				rest := ln[i+len("configuration file"):]
				fields := strings.Fields(rest)
				if len(fields) > 0 {
					n.ConfigPath = fields[0]
				}
			}
		}
	} else if cpath, err := client.RunContext(ctx, "nginx -v 2>&1"); err == nil {
		_ = cpath
	}
	if up, err := client.RunContext(ctx, "pgrep -x nginx >/dev/null 2>&1 && echo up || echo down"); err == nil && strings.Contains(up, "up") {
		n.Running = true
	}
	// Полный конфиг: ssl_protocols и listen ... ssl.
	cfgOut, err := client.RunContext(ctx, "nginx -T 2>&1")
	if err != nil && cfgOut == "" {
		return n
	}
	for _, ln := range strings.Split(cfgOut, "\n") {
		t := strings.TrimSpace(ln)
		lt := strings.ToLower(t)
		switch {
		case strings.HasPrefix(lt, "ssl_protocols"):
			proto := strings.TrimSpace(strings.TrimPrefix(t, "ssl_protocols"))
			n.SSLProtocols = append(n.SSLProtocols, proto)
		case strings.Contains(lt, "listen") && strings.Contains(lt, "ssl"):
			// listen 443 ssl; / listen [::]:8443 ssl;
			fields := strings.Fields(t)
			if len(fields) >= 2 {
				addr := strings.TrimSuffix(fields[1], ";")
				addr = strings.TrimPrefix(addr, "[::]:")
				addr = strings.TrimPrefix(addr, "0.0.0.0:")
				if nPort, aerr := strconv.Atoi(addr); aerr == nil {
					n.ListenSSL = append(n.ListenSSL, nPort)
				}
			}
		}
	}
	// Проблемы.
	for _, sp := range n.SSLProtocols {
		low := strings.ToLower(sp)
		if strings.Contains(low, "tlsv1") && !strings.Contains(low, "tlsv1.2") && !strings.Contains(low, "tlsv1.3") {
			n.Issues = append(n.Issues, "nginx ssl_protocols включает устаревшие TLS 1.0/1.1: "+sp)
		}
		if strings.Contains(low, "tlsv1.2") && !strings.Contains(low, "tlsv1.3") {
			n.Issues = append(n.Issues, "nginx ssl_protocols не включает TLS 1.3: "+sp)
		}
		if strings.Contains(low, "rc4") {
			n.Issues = append(n.Issues, "nginx разрешает слабый шифр RC4")
		}
	}
	return n
}

// finalizeProto определяет протокол порта после проверки TLS-версий.
func finalizeProto(pr *PortResult, ctx context.Context, dial tlsDialer, addr, serverName string) {
	if portSupported(*pr) {
		pr.Protocol = ProtoTLS
		if probeHTTPOverTLS(ctx, dial, addr, serverName) {
			pr.Protocol = ProtoHTTPS
		}
		return
	}
	if probeHTTP(ctx, dial, addr) {
		pr.Protocol = ProtoHTTP
		return
	}
	conn, err := dial(ctx, addr)
	if err != nil {
		pr.Protocol = ProtoClosed
		if pr.Error == "" {
			pr.Error = "порт недоступен: " + err.Error()
		}
		return
	}
	_ = conn.Close()
	pr.Protocol = ProtoPlainTCP
}

// probeHTTP — проверяет, что на порту отвечает plaintext HTTP.
func probeHTTP(ctx context.Context, dial tlsDialer, addr string) bool {
	return probeHTTPConn(ctx, dial, addr, nil)
}

// probeHTTPOverTLS — проверяет, что поверх TLS отвечает HTTP (HTTPS).
func probeHTTPOverTLS(ctx context.Context, dial tlsDialer, addr, serverName string) bool {
	return probeHTTPConn(ctx, dial, addr, &tls.Config{
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS13,
		ServerName:         serverName,
		InsecureSkipVerify: true,
	})
}

// probeHTTPConn делает GET / и определяет, отвечает ли порт HTTP.
// tlsCfg != nil — рукопожатие TLS перед HTTP.
func probeHTTPConn(ctx context.Context, dial tlsDialer, addr string, tlsCfg *tls.Config) bool {
	attemptCtx, cancel := context.WithTimeout(ctx, attemptTimeout)
	defer cancel()

	conn, err := dial(attemptCtx, addr)
	if err != nil {
		return false
	}
	defer conn.Close()

	var rw io.ReadWriter = conn
	if tlsCfg != nil {
		tconn := tls.Client(conn, tlsCfg)
		_ = tconn.SetDeadline(time.Now().Add(handshakeTimeout))
		if err := tconn.HandshakeContext(attemptCtx); err != nil {
			return false
		}
		rw = tconn
	}
	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))
	req := "GET / HTTP/1.0\r\nHost: x\r\nAccept: */*\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(rw, req); err != nil {
		return false
	}
	br := bufio.NewReader(rw)
	line, err := br.ReadString('\n')
	if err != nil && err != io.EOF {
		return false
	}
	return strings.HasPrefix(strings.ToUpper(strings.TrimSpace(line)), "HTTP/")
}

// extractCiphers извлекает cipher suites из ключей "TLS x.y → <suite>".
func extractCiphers(pr PortResult) []string {
	seen := map[string]bool{}
	var out []string
	for k, ok := range pr.Versions {
		if !ok {
			continue
		}
		if i := strings.Index(k, "→"); i >= 0 {
			c := strings.TrimSpace(k[i+len("→"):])
			if c != "" && !seen[c] {
				seen[c] = true
				out = append(out, c)
			}
		}
	}
	sort.Strings(out)
	return out
}

// weakCipherList выделяет слабые cipher suites (RC4, 3DES, CBC-SHA1).
func weakCipherList(ciphers []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, suite := range ciphers {
		u := strings.ToUpper(suite)
		weak := ""
		switch {
		case strings.Contains(u, "RC4"):
			weak = "RC4"
		case strings.Contains(u, "3DES") || strings.Contains(u, "DES-CBC3"):
			weak = "3DES"
		case strings.Contains(u, "CBC") && strings.Contains(u, "SHA1"):
			weak = "CBC-SHA1"
		}
		if weak != "" && !seen[weak] {
			seen[weak] = true
			out = append(out, weak)
		}
	}
	return out
}

// mergeOpenSSLOut разбирает вывод opensslScript в PortResult.
func mergeOpenSSLOut(pr *PortResult, out string) {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		kv := strings.SplitN(line, "=", 2)
		if len(kv) != 2 {
			continue
		}
		ver := flagVersion(kv[0])
		if ver == "" {
			continue
		}
		rest := strings.TrimSpace(kv[1])
		if strings.HasPrefix(rest, "YES") {
			pr.Versions[ver] = true
			if suite := strings.TrimSpace(strings.TrimPrefix(rest, "YES")); suite != "" {
				pr.Versions[ver+" → "+suite] = true
			}
		} else {
			pr.Versions[ver] = false
		}
	}
}

// ── Рекомендации ──

// baseVersion выделяет имя протокола из ключа (отрезает суффиксы
// "→ cipher suite" и "(default)" из SChannel).
func baseVersion(key string) string {
	if i := strings.Index(key, "→"); i >= 0 {
		key = key[:i]
	}
	if i := strings.Index(key, "(default)"); i >= 0 {
		key = key[:i]
	}
	return strings.TrimSpace(key)
}

// findWeakCiphers ищет слабые cipher suites (RC4, 3DES, CBC-SHA1) в ключах
// вида "TLS 1.2 → <cipher>" из вывода openssl.
func findWeakCiphers(res ServerTLS) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range res.Ports {
		for _, w := range p.WeakCiphers {
			if !seen[w] {
				seen[w] = true
				out = append(out, w)
			}
		}
		for key, ok := range p.Versions {
			if !ok {
				continue
			}
			i := strings.Index(key, "→")
			if i < 0 {
				continue
			}
			suite := strings.ToUpper(strings.TrimSpace(key[i+len("→"):]))
			weak := ""
			switch {
			case strings.Contains(suite, "RC4"):
				weak = "RC4"
			case strings.Contains(suite, "3DES") || strings.Contains(suite, "DES-CBC3"):
				weak = "3DES"
			case strings.Contains(suite, "CBC") && strings.Contains(suite, "SHA1"):
				weak = "CBC-SHA1"
			}
			if weak != "" && !seen[weak] {
				seen[weak] = true
				out = append(out, weak)
			}
		}
	}
	return out
}

func buildRecommendations(res ServerTLS) []string {
	var recs []string
	for _, p := range res.Ports {
		for ver, ok := range p.Versions {
			if !ok {
				continue
			}
			switch baseVersion(ver) {
			case TLS10:
				recs = append(recs, fmt.Sprintf("TLS 1.0 включён на порту %d — протокол устарел (RFC 8996), рекомендуется отключить.", p.Port))
			case TLS11:
				recs = append(recs, fmt.Sprintf("TLS 1.1 включён на порту %d — протокол устарел (RFC 8996), рекомендуется отключить.", p.Port))
			case TLS13:
				recs = append(recs, fmt.Sprintf("TLS 1.3 поддерживается на порту %d — отлично.", p.Port))
			}
		}
		// HTTP без TLS.
		if p.Protocol == ProtoHTTP {
			recs = append(recs, fmt.Sprintf("Порт %d отвечает по HTTP без TLS — рекомендуется включить HTTPS/TLS.", p.Port))
			if p.HTTPRedirect != "" {
				recs = append(recs, fmt.Sprintf("Порт %d корректно редиректит HTTP→HTTPS: %s.", p.Port, p.HTTPRedirect))
			} else {
				recs = append(recs, fmt.Sprintf("Порт %d не редиректит на HTTPS — настройте 301/308 на https.", p.Port))
			}
		}
		if len(p.WeakCiphers) > 0 {
			recs = append(recs, fmt.Sprintf("Порт %d: слабые cipher suites (%s) — исключите RC4, 3DES, CBC-SHA1.", p.Port, strings.Join(p.WeakCiphers, ", ")))
		}
		// Пункт 47: HTTP/2 / HTTP/3.
		if p.HTTP2 {
			recs = append(recs, fmt.Sprintf("Порт %d: поддерживается HTTP/2 (ALPN h2) — отлично.", p.Port))
		} else if portSupported(p) {
			recs = append(recs, fmt.Sprintf("Порт %d: HTTP/2 не согласуется (нет ALPN h2) — включите ALPN в TLS-конфигурации.", p.Port))
		}
		if p.HTTP3 {
			recs = append(recs, fmt.Sprintf("Порт %d: объявлен HTTP/3 (Alt-Svc h3) — отлично.", p.Port))
		}
		// Пункт 46: сертификат.
		if p.Cert != nil {
			c := p.Cert
			switch {
			case c.IsExpired:
				recs = append(recs, fmt.Sprintf("Порт %d: сертификат ИСТЁК %s (subject=%s) — срочно продлите!", p.Port, c.NotAfter.Format("2006-01-02"), c.Subject))
			case c.IsExpiringSoon:
				recs = append(recs, fmt.Sprintf("Порт %d: сертификат истекает через %d дн. (%s) — продлите в течение 30 дней.", p.Port, c.ExpiresInDays, c.NotAfter.Format("2006-01-02")))
			}
			if !c.HostnameMatch {
				recs = append(recs, fmt.Sprintf("Порт %d: сертификат не соответствует hostname %s (SAN: %s).", p.Port, res.ServerName, strings.Join(c.SANs, ", ")))
			}
			if c.SelfSigned {
				recs = append(recs, fmt.Sprintf("Порт %d: самоподписанный сертификат (issuer=%s) — замените на CA-подписанный.", p.Port, c.Issuer))
			}
		}
	}
	hasTLS13 := false
	anySupported := false
	for _, p := range res.Ports {
		if portSupported(p) {
			anySupported = true
		}
		for ver, ok := range p.Versions {
			if ok && baseVersion(ver) == TLS13 {
				hasTLS13 = true
			}
		}
	}
	// nginx.
	if res.Nginx.Installed {
		if !res.Nginx.Running {
			recs = append(recs, "nginx установлен, но не запущен (pgrep nginx пуст).")
		}
		for _, issue := range res.Nginx.Issues {
			recs = append(recs, "nginx: "+issue)
		}
		if len(res.Nginx.ListenSSL) == 0 && res.Nginx.Running {
			recs = append(recs, "nginx: не найдено listen ... ssl — HTTPS не настроен.")
		}
	}
	// Docker.
	if len(res.DockerPorts) > 0 {
		recs = append(recs, fmt.Sprintf("Docker: опубликованы порты %v — проверьте TLS на каждом.", res.DockerPorts))
	}
	if res.OS == OSWindows {
		recs = append(recs, `Windows: убедитесь, что TLS 1.2 и 1.3 включены в SChannel, а TLS 1.0/1.1 отключены (HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols).`)
		recs = append(recs, `Windows/.NET: установите SchUseStrongCrypto=1 в HKLM\SOFTWARE\Microsoft\.NETFramework\v4.0.30319 и Wow6432Node.`)
	}
	if res.OS == OSMikrotik {
		recs = append(recs, "MikroTik: проверьте /ip service — включите tls-version=1.2-only и отключите legacy protocols.")
	}
	// Слабые cipher suites (агрегированно).
	if weak := findWeakCiphers(res); len(weak) > 0 {
		recs = append(recs, "Обнаружены слабые cipher suites ("+strings.Join(weak, ", ")+") — исключите RC4, 3DES и CBC-SHA1 в настройках сервиса.")
	}
	if !anySupported && res.Error == "" {
		recs = append(recs, "На проверяемых портах не найден ни один TLS-сервис. Убедитесь, что сервисы слушают локально и порты в списке сканирования.")
	}
	if !hasTLS13 && res.Error == "" {
		recs = append(recs, "TLS 1.3 не обнаружен — обновите сервисы/прокси для поддержки TLS 1.3.")
	}
	// Пункт 46: общие рекомендации по сертификатам.
	for _, p := range res.Ports {
		if p.Cert != nil {
			if p.Cert.IsExpired || p.Cert.IsExpiringSoon {
				recs = append(recs, fmt.Sprintf("Порт %d: автопродление: %s.", p.Port, p.Cert.AutoRenew))
			}
			break
		}
	}
	return recs
}
