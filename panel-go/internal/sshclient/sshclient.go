// Package sshclient — обёртка над golang.org/x/crypto/ssh для выполнения команд.
package sshclient

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
)

// Client — SSH-клиент для выполнения команд на удалённом сервере.
type Client struct {
	client *ssh.Client
}

// Connect устанавливает соединение по паролю, доверяя любому host key.
func Connect(host string, port int, user, password string, timeout time.Duration) (*Client, error) {
	return ConnectContext(context.Background(), host, port, user, password, timeout)
}

// ConnectContext — как Connect, но уважает отмену/дедлайн контекста.
// Если контекст отменён во время TCP-соединения, DialContext прерывается.
// SSH handshake (NewClientConn) не принимает context, поэтому запускаем
// его в горутине с hard timeout — если handshake висит, возвращаем ошибку.
//
// Аутентификация: password + keyboard-interactive (многие sshd принимают
// только keyboard-interactive, хотя пароль тот же). Если privateKeyPath
// непустой — добавляется и public key.
func ConnectContext(ctx context.Context, host string, port int, user, password string, timeout time.Duration) (*Client, error) {
	return ConnectContextWithKey(ctx, host, port, user, password, "", timeout)
}

// ConnectContextWithKey — как ConnectContext, но с опциональным приватным ключом.
func ConnectContextWithKey(ctx context.Context, host string, port int, user, password, privateKeyPath string, timeout time.Duration) (*Client, error) {
	if port <= 0 {
		port = 22
	}
	var authMethods []ssh.AuthMethod
	if password != "" {
		authMethods = append(authMethods, ssh.Password(password))
		// keyboard-interactive: многие sshd ( hardened ) принимают только
		// этот метод, хотя пароль тот же.
		authMethods = append(authMethods, ssh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) ([]string, error) {
			answers := make([]string, len(questions))
			for i := range answers {
				answers[i] = password
			}
			return answers, nil
		}))
	}
	if privateKeyPath != "" {
		if signer := loadSigner(privateKeyPath); signer != nil {
			authMethods = append(authMethods, ssh.PublicKeys(signer))
		}
	}
	if len(authMethods) == 0 {
		return nil, fmt.Errorf("sshclient: no auth methods (empty password and no key)")
	}
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         timeout,
	}
	addr := net.JoinHostPort(host, fmt.Sprint(port))

	// TCP-соединение — context-aware.
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	// SSH handshake — не context-aware, поэтому с hard timeout.
	type handshakeResult struct {
		client *ssh.Client
		err    error
	}
	hrCh := make(chan handshakeResult, 1)
	go func() {
		sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
		if err != nil {
			_ = conn.Close()
			hrCh <- handshakeResult{nil, err}
			return
		}
		hrCh <- handshakeResult{ssh.NewClient(sshConn, chans, reqs), nil}
	}()

	select {
	case hr := <-hrCh:
		if hr.err != nil {
			return nil, hr.err
		}
		return &Client{client: hr.client}, nil
	case <-ctx.Done():
		_ = conn.Close()
		return nil, ctx.Err()
	}
}

// defaultCommandTimeout — таймаут на выполнение одной SSH-команды.
// Если сервер не отвечает (например, docker stats завис), команда прерывается
// и цикл мониторинга продолжает работу со следующего сервера.
const defaultCommandTimeout = 30 * time.Second

// Run выполняет команду и возвращает вывод с таймаутом по умолчанию.
func (c *Client) Run(command string) (string, error) {
	return c.RunWithTimeout(command, defaultCommandTimeout)
}

// RunContext выполняет команду, уважая отмену/дедлайн контекста.
// Таймаут — минимум из defaultCommandTimeout и оставшегося времени ctx.
// При таймауте/отмене сессия принудительно закрывается (с защитой от зависания
// самого Close — не блокирует дольше 3 секунд).
func (c *Client) RunContext(ctx context.Context, command string) (string, error) {
	if c == nil || c.client == nil {
		return "", fmt.Errorf("sshclient: client is closed")
	}
	timeout := defaultCommandTimeout
	if dl, ok := ctx.Deadline(); ok {
		remaining := time.Until(dl)
		if remaining < timeout {
			timeout = remaining
		}
	}
	if timeout <= 0 {
		return "", ctx.Err()
	}
	sess, err := c.client.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()

	type result struct {
		out []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		out, err := sess.CombinedOutput(command)
		done <- result{out, err}
	}()
	select {
	case r := <-done:
		return string(r.out), r.err
	case <-time.After(timeout):
		killSession(sess)
		return "", fmt.Errorf("sshclient: command timed out after %s", timeout)
	case <-ctx.Done():
		killSession(sess)
		return "", ctx.Err()
	}
}

// RunWithTimeout выполняет команду и прерывает её по истечении timeout.
// Это предотвращает зависание цикла мониторинга на нереспонсивном сервере.
func (c *Client) RunWithTimeout(command string, timeout time.Duration) (string, error) {
	if c == nil || c.client == nil {
		return "", fmt.Errorf("sshclient: client is closed")
	}
	sess, err := c.client.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()

	type result struct {
		out []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		out, err := sess.CombinedOutput(command)
		done <- result{out, err}
	}()
	select {
	case r := <-done:
		// ssh.ExitError — команда завершилась с ненулевым кодом, но вывод может быть полезен.
		return string(r.out), r.err
	case <-time.After(timeout):
		// Принудительно завершаем сессию, чтобы разблокировать горутину.
		_ = sess.Signal(ssh.SIGKILL)
		sess.Close()
		return "", fmt.Errorf("sshclient: command timed out after %s", timeout)
	}
}

// killSession принудительно завершает SSH-сессию, не блокируя дольше 3 секунд.
// sess.Signal и sess.Close могут зависать на нереспонсивном SSH-сервере.
func killSession(sess *ssh.Session) {
	done := make(chan struct{}, 1)
	go func() {
		_ = sess.Signal(ssh.SIGKILL)
		_ = sess.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
	}
}

// Dial открывает TCP-соединение через SSH-туннель к удалённому хосту
// (например 127.0.0.1:порт на стороне сервера). Используется встроенным
// TLS-сканером панели вместо openssl на целевой машине.
func (c *Client) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if c == nil || c.client == nil {
		return nil, fmt.Errorf("sshclient: client is closed")
	}
	return c.client.DialContext(ctx, network, addr)
}

// Close закрывает соединение. Не блокирует дольше 5 секунд — если SSH-сервер
// не отвечает, close может зависнуть, и мы не хотим блокировать сканирование.
func (c *Client) Close() error {
	if c == nil || c.client == nil {
		return nil
	}
	done := make(chan error, 1)
	go func() {
		done <- c.client.Close()
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		return nil // timeout — соединение будет закрыто фоновой горутиной
	}
}

// loadSigner загружает приватный ключ для SSH public key auth.
func loadSigner(path string) ssh.Signer {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		return nil
	}
	return signer
}
