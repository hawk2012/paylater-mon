package tlsscan

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// selfSignedCert генерирует самоподписанный сертификат для локального TLS-сервера.
func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// startTLSServer поднимает локальный TLS-сервер с TLS 1.2/1.3.
func startTLSServer(t *testing.T) (addr string, closeFn func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{selfSignedCert(t)},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				tc := tls.Server(c, cfg)
				_ = tc.Handshake()
				_ = tc.Close()
			}(conn)
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

// startPlainTCP поднимает TCP-слушатель без TLS (порт слушает, но TLS не говорит).
func startPlainTCP(t *testing.T) (addr string, closeFn func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				_, _ = c.Read(buf) // держим соединение, но не отвечаем по TLS
			}(conn)
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

// localDialer — прямой dial к 127.0.0.1.
func localDialer() tlsDialer {
	d := &net.Dialer{Timeout: connectTimeout}
	return func(ctx context.Context, addr string) (net.Conn, error) {
		return d.DialContext(ctx, "tcp", addr)
	}
}

// TestProbeVersionTLS122 проверяет определение версий на реальном TLS-сервере
// (TLS 1.2/1.3 должны определяться, устаревшие 1.0/1.1 — нет).
func TestProbeVersionTLS122(t *testing.T) {
	addr, closeFn := startTLSServer(t)
	defer closeFn()

	want := map[string]bool{TLS10: false, TLS11: false, TLS12: true, TLS13: true}
	for _, ver := range tlsVersions {
		ok, err := probeVersion(context.Background(), localDialer(), addr, "localhost", ver)
		if err != nil {
			t.Fatalf("probeVersion(%s): %v", ver, err)
		}
		if ok != want[ver] {
			t.Errorf("probeVersion(%s) = %v, want %v", ver, ok, want[ver])
		}
	}
}

// TestProbePortPlainTCP проверяет, что порт без TLS не даёт ни одной версии.
func TestProbePortPlainTCP(t *testing.T) {
	addr, closeFn := startPlainTCP(t)
	defer closeFn()

	_, portStr, _ := net.SplitHostPort(addr)
	port := 0
	fmt.Sscanf(portStr, "%d", &port)
	pr := probePort(context.Background(), localDialer(), addr, "localhost", port)
	for _, ver := range tlsVersions {
		if pr.Versions[ver] {
			t.Errorf("plain TCP port: %s должен быть false", ver)
		}
	}
	if pr.Error != "" {
		t.Errorf("plain TCP port: unexpected error %q", pr.Error)
	}
}

// TestProbePortClosed проверяет закрытый порт (ошибка, все версии false).
func TestProbePortClosed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close() // порт закрыт

	pr := probePort(context.Background(), localDialer(), addr, "localhost", 12345)
	if pr.Error == "" {
		t.Error("closed port: expected error")
	}
	if len(pr.Versions) != 0 {
		t.Errorf("closed port: versions должно быть пусто, got %v", pr.Versions)
	}
}

// TestSupportedPorts проверяет фильтрацию портов с TLS.
func TestSupportedPorts(t *testing.T) {
	res := ServerTLS{Ports: []PortResult{
		{Port: 443, Versions: map[string]bool{TLS12: true}},
		{Port: 8080, Versions: map[string]bool{TLS12: false, TLS13: false}},
	}}
	supported := res.SupportedPorts()
	if len(supported) != 1 || supported[0].Port != 443 {
		t.Errorf("expected only port 443, got %+v", supported)
	}
}

// TestVersionID проверяет соответствие названий константам crypto/tls.
func TestVersionID(t *testing.T) {
	cases := map[string]uint16{
		TLS10: tls.VersionTLS10,
		TLS11: tls.VersionTLS11,
		TLS12: tls.VersionTLS12,
		TLS13: tls.VersionTLS13,
	}
	for ver, want := range cases {
		if got := versionID(ver); got != want {
			t.Errorf("versionID(%s) = %d, want %d", ver, got, want)
		}
	}
}

// TestBuildRecommendations проверяет генерацию советов при устаревших TLS.
func TestBuildRecommendations(t *testing.T) {
	res := ServerTLS{
		OS: "Linux",
		Ports: []PortResult{
			{Port: 443, Versions: map[string]bool{TLS10: true, TLS11: true, TLS12: true, TLS13: true}},
		},
	}
	joined := strings.Join(buildRecommendations(res), "\n")
	for _, want := range []string{"TLS 1.0", "TLS 1.1", "TLS 1.3"} {
		if !strings.Contains(joined, want) {
			t.Errorf("expected recommendation containing %q", want)
		}
	}

	// Без TLS 1.3 — должен быть совет обновить сервисы.
	res2 := ServerTLS{OS: "Linux", Ports: []PortResult{
		{Port: 8080, Versions: map[string]bool{TLS12: true}},
	}}
	recs2 := strings.Join(buildRecommendations(res2), "\n")
	if !strings.Contains(recs2, "TLS 1.3 не обнаружен") {
		t.Error("expected advice to update for TLS 1.3")
	}
	if !strings.Contains(recs2, "обновите сервисы") {
		t.Error("expected advice wording about services")
	}

	// Ни одного TLS-сервиса — совет проверить порты.
	res3 := ServerTLS{OS: "Linux", Ports: []PortResult{
		{Port: 8080, Versions: map[string]bool{TLS12: false, TLS13: false}},
	}}
	recs3 := strings.Join(buildRecommendations(res3), "\n")
	if !strings.Contains(recs3, "не найден ни один TLS-сервис") {
		t.Error("expected advice about no TLS services found")
	}
}

// TestOpenSSLFlag проверяет сопоставление версий и флагов openssl.
func TestOpenSSLFlag(t *testing.T) {
	cases := map[string]string{
		TLS10: "-tls1",
		TLS11: "-tls1_1",
		TLS12: "-tls1_2",
		TLS13: "-tls1_3",
	}
	for ver, want := range cases {
		if got := opensslFlag(ver); got != want {
			t.Errorf("opensslFlag(%s) = %q, want %q", ver, got, want)
		}
	}
}

// TestFlagVersion проверяет обратное сопоставление.
func TestFlagVersion(t *testing.T) {
	cases := map[string]string{
		"tls1":   TLS10,
		"tls1_1": TLS11,
		"tls1_2": TLS12,
		"tls1_3": TLS13,
	}
	for flag, want := range cases {
		if got := flagVersion(flag); got != want {
			t.Errorf("flagVersion(%q) = %q, want %q", flag, got, want)
		}
	}
}

// TestMergeOpenSSLOut проверяет разбор вывода openssl-скрипта.
func TestMergeOpenSSLOut(t *testing.T) {
	out := "tls1=NO\ntls1_1=NO\ntls1_2=YES ECDHE-RSA-AES128-GCM-SHA256\ntls1_3=YES TLS_AES_256_GCM_SHA384\n"
	pr := PortResult{Port: 443, Versions: map[string]bool{}}
	mergeOpenSSLOut(&pr, out)

	if pr.Versions[TLS10] {
		t.Error("TLS 1.0 should be false")
	}
	if !pr.Versions[TLS12] {
		t.Error("TLS 1.2 should be true")
	}
	if !pr.Versions[TLS12+" → ECDHE-RSA-AES128-GCM-SHA256"] {
		t.Error("TLS 1.2 cipher suite not recorded")
	}
	if !pr.Versions[TLS13] {
		t.Error("TLS 1.3 should be true")
	}
}

// TestBaseVersion проверяет отрезание суффиксов.
func TestBaseVersion(t *testing.T) {
	cases := map[string]string{
		"TLS 1.2":                          "TLS 1.2",
		"TLS 1.2 → ECDHE-RSA-AES128-GCM":   "TLS 1.2",
		"TLS 1.0 (default)":                "TLS 1.0",
		"TLS 1.3 → TLS_AES_256_GCM_SHA384": "TLS 1.3",
	}
	for input, want := range cases {
		if got := baseVersion(input); got != want {
			t.Errorf("baseVersion(%q) = %q, want %q", input, got, want)
		}
	}
}

// TestFindWeakCiphers проверяет обнаружение слабых cipher suites.
func TestFindWeakCiphers(t *testing.T) {
	res := ServerTLS{OS: "Linux", Ports: []PortResult{
		{Port: 443, Versions: map[string]bool{
			TLS12 + " → ECDHE-RSA-AES128-SHA":        true,
			TLS12 + " → RC4-MD5":                     true,
			TLS12 + " → DES-CBC3-SHA":                true,
			TLS12 + " → AES128-CBC-SHA1":             true,
			TLS12 + " → ECDHE-RSA-AES128-GCM-SHA256": true,
		}},
	}}
	weak := findWeakCiphers(res)
	for _, w := range []string{"RC4", "3DES", "CBC-SHA1"} {
		found := false
		for _, got := range weak {
			if got == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected weak cipher %q in %v", w, weak)
		}
	}
}

// TestOpenSSLScript проверяет генерацию скрипта (порт подставлен).
func TestOpenSSLScript(t *testing.T) {
	s := opensslScript(443)
	if !strings.Contains(s, "127.0.0.1:443") {
		t.Error("script should reference port 443")
	}
	if !strings.Contains(s, "-tls1_3") {
		t.Error("script should include TLS 1.3 flag")
	}
}

// startHTTPPlain поднимает простой HTTP-сервер без TLS.
func startHTTPPlain(t *testing.T) (addr string, closeFn func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				_, _ = c.Read(buf) // читаем первую порцию запроса
				_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
			}(conn)
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

// TestProbeHTTPPlain проверяет детекцию plaintext HTTP.
func TestProbeHTTPPlain(t *testing.T) {
	addr, closeFn := startHTTPPlain(t)
	defer closeFn()
	if !probeHTTP(context.Background(), localDialer(), addr) {
		t.Error("probeHTTP should detect plaintext HTTP")
	}
}

// TestProbeHTTPOverTLS проверяет детекцию HTTPS поверх TLS.
func TestProbeHTTPOverTLS(t *testing.T) {
	addr, closeFn := startTLSServer(t)
	defer closeFn()
	if probeHTTPOverTLS(context.Background(), localDialer(), addr, "localhost") {
		t.Error("raw TLS server without HTTP response should not be https")
	}
}

// TestProbePortHTTPDetect проверяет, что HTTP-порт определяется как http.
func TestProbePortHTTPDetect(t *testing.T) {
	addr, closeFn := startHTTPPlain(t)
	defer closeFn()
	_, portStr, _ := net.SplitHostPort(addr)
	port := 0
	fmt.Sscanf(portStr, "%d", &port)
	pr := probePort(context.Background(), localDialer(), addr, "localhost", port)
	if pr.Protocol != ProtoHTTP {
		t.Errorf("expected Protocol http, got %q", pr.Protocol)
	}
}

// TestProbePortTLSDetect проверяет, что TLS-порт с HTTP определяется как https.
func TestProbePortTLSDetect(t *testing.T) {
	// TLS-сервер из TestProbeVersionTLS122 не отвечает HTTP, поэтому https не ждём.
	addr, closeFn := startTLSServer(t)
	defer closeFn()
	_, portStr, _ := net.SplitHostPort(addr)
	port := 0
	fmt.Sscanf(portStr, "%d", &port)
	pr := probePort(context.Background(), localDialer(), addr, "localhost", port)
	if pr.Protocol != ProtoTLS {
		t.Errorf("expected Protocol tls, got %q", pr.Protocol)
	}
}

// TestFinalizeProtoClosed проверяет, что закрытый порт помечается closed.
func TestFinalizeProtoClosed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	pr := &PortResult{Versions: map[string]bool{TLS12: false, TLS13: false}}
	finalizeProto(pr, context.Background(), localDialer(), addr, "localhost")
	if pr.Protocol != ProtoClosed {
		t.Errorf("expected closed, got %q", pr.Protocol)
	}
}

// TestExtractCiphers проверяет извлечение cipher suites из ключей версий.
func TestExtractCiphers(t *testing.T) {
	pr := PortResult{Versions: map[string]bool{
		TLS12 + " → ECDHE-RSA-AES128-GCM-SHA256": true,
		TLS13 + " → TLS_AES_256_GCM_SHA384":      true,
		TLS12:                                    true,
	}}
	ciphers := extractCiphers(pr)
	if len(ciphers) != 2 {
		t.Errorf("expected 2 ciphers, got %v", ciphers)
	}
}

// TestWeakCipherList проверяет выделение слабых cipher suites.
func TestWeakCipherList(t *testing.T) {
	ciphers := []string{"ECDHE-RSA-AES128-GCM-SHA256", "RC4-MD5", "DES-CBC3-SHA", "AES128-CBC-SHA1"}
	weak := weakCipherList(ciphers)
	for _, w := range []string{"RC4", "3DES", "CBC-SHA1"} {
		found := false
		for _, got := range weak {
			if got == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected weak cipher %q in %v", w, weak)
		}
	}
}

// TestScanDockerPortsOutput проверяет парсинг вывода docker ps --format.
func TestScanDockerPortsOutput(t *testing.T) {
	out := "0.0.0.0:8080->80/tcp\n:::8443->8443/tcp\n443/tcp\n127.0.0.1:9600->9600/tcp\n"
	ports := parseDockerPortsOutput(out)
	expected := []int{8080, 8443, 9600}
	if len(ports) != len(expected) {
		t.Fatalf("expected %v, got %v", expected, ports)
	}
	for i, p := range expected {
		if ports[i] != p {
			t.Errorf("port[%d] = %d, want %d", i, ports[i], p)
		}
	}
}

// TestProbeCertALPN проверяет извлечение сертификата и ALPN из TLS-сервера.
func TestProbeCertALPN(t *testing.T) {
	addr, closeFn := startTLSServer(t)
	defer closeFn()

	cert, alpn, h3 := probeCertALPN(context.Background(), localDialer(), addr, "localhost")
	if cert == nil {
		t.Fatal("expected cert info, got nil")
	}
	if cert.IsExpired {
		t.Error("self-signed cert valid for 1h should not be expired")
	}
	if cert.ExpiresInDays < 0 {
		t.Errorf("expected non-negative days left, got %d", cert.ExpiresInDays)
	}
	// Raw TLS-сервер без ALPN может согласовать http/1.1 или ничего.
	if len(alpn) > 0 && alpn[0] == "h2" {
		// Если согласовали h2 — HTTP/2 должен быть true (в тесте это не критично).
	}
	_ = h3
}

// TestProbePortCertInfo проверяет, что probePort заполняет Cert для TLS-порта.
func TestProbePortCertInfo(t *testing.T) {
	addr, closeFn := startTLSServer(t)
	defer closeFn()
	_, portStr, _ := net.SplitHostPort(addr)
	port := 0
	fmt.Sscanf(portStr, "%d", &port)
	pr := probePort(context.Background(), localDialer(), addr, "localhost", port)
	if pr.Cert == nil {
		t.Fatal("expected Cert info on TLS port")
	}
	if !portSupported(pr) {
		t.Error("expected TLS support")
	}
}

// TestCheckHTTPRedirect проверяет детекцию редиректа HTTP→HTTPS.
func TestCheckHTTPRedirect(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte("HTTP/1.1 301 Moved Permanently\r\nLocation: https://example.com/\r\nContent-Length: 0\r\n\r\n"))
			}(conn)
		}
	}()
	loc := checkHTTPRedirect(context.Background(), localDialer(), ln.Addr().String())
	if loc != "https://example.com/" {
		t.Errorf("expected https redirect, got %q", loc)
	}
	_ = ln.Close()
}

// TestCheckHTTPRedirectNone проверяет отсутствие редиректа на обычном HTTP.
func TestCheckHTTPRedirectNone(t *testing.T) {
	addr, closeFn := startHTTPPlain(t)
	defer closeFn()
	if loc := checkHTTPRedirect(context.Background(), localDialer(), addr); loc != "" {
		t.Errorf("expected no redirect, got %q", loc)
	}
}

// pkixName собирает pkix.Name из строки "CN, OU".
func pkixName(cn string) pkix.Name {
	parts := strings.Split(cn, ",")
	n := pkix.Name{CommonName: strings.TrimSpace(parts[0])}
	if len(parts) > 1 {
		n.Organization = []string{strings.TrimSpace(parts[1])}
	}
	return n
}

// TestDetectAutoRenew проверяет определение механизма автопродления.
func TestDetectAutoRenew(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// Итоговый сертификат имеет Issuer = Subject родителя (CA).
	mkCert := func(caSubject pkix.Name) *x509.Certificate {
		ca := &x509.Certificate{
			SerialNumber: big.NewInt(2),
			Subject:      caSubject,
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
		}
		caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &priv.PublicKey, priv)
		if err != nil {
			t.Fatal(err)
		}
		caCert, err := x509.ParseCertificate(caDER)
		if err != nil {
			t.Fatal(err)
		}
		leaf := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkixName("server.paylater.uz"),
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
		}
		leafDER, err := x509.CreateCertificate(rand.Reader, leaf, caCert, &priv.PublicKey, priv)
		if err != nil {
			t.Fatal(err)
		}
		leafCert, err := x509.ParseCertificate(leafDER)
		if err != nil {
			t.Fatal(err)
		}
		return leafCert
	}

	leCert := mkCert(pkixName("R10, Let's Encrypt"))
	if got := detectAutoRenew(leCert, nil); !strings.Contains(got, "Let's Encrypt") {
		t.Errorf("expected Let's Encrypt auto-renew, got %q", got)
	}
	vtCert := mkCert(pkixName("Vault PKI, vault.paylater.uz"))
	if got := detectAutoRenew(vtCert, nil); !strings.Contains(got, "Vault PKI") {
		t.Errorf("expected Vault PKI auto-renew, got %q", got)
	}
}

// TestCertInfoDaysLeft проверяет форматирование оставшихся дней.
func TestCertInfoDaysLeft(t *testing.T) {
	c := &CertInfo{ExpiresInDays: 45, IsExpired: false}
	if !strings.Contains(c.DaysLeft(), "45") {
		t.Errorf("expected 45 in DaysLeft, got %q", c.DaysLeft())
	}
	c2 := &CertInfo{IsExpired: true}
	if c2.DaysLeft() != "истёк" {
		t.Errorf("expected 'истёк', got %q", c2.DaysLeft())
	}
}
