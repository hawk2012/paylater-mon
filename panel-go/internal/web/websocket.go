package web

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

// wsHub управляет WebSocket-клиентами и периодически пушит метрики.
type wsHub struct {
	mu      sync.Mutex
	clients map[*wsClient]bool
}

type wsClient struct {
	w   http.ResponseWriter
	fl  http.Flusher
	ctx context.Context
}

func newWSHub() *wsHub {
	return &wsHub{clients: map[*wsClient]bool{}}
}

// Run периодически пушит обновления всем клиентам (пункт 3 IMPROVEMENTS.md).
func (h *wsHub) Run(ctx context.Context, app *App) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			h.broadcast(app)
		}
	}
}

func (h *wsHub) broadcast(app *App) {
	// Собираем сводку.
	servers, _ := app.serverCore.GetServers(context.Background())
	totalContainers := 0
	downContainers := 0
	for _, sv := range servers {
		totalContainers += sv.TotalContainers
		downContainers += sv.TotalContainers - sv.RunningContainers
	}
	payload := map[string]interface{}{
		"timestamp":        time.Now().Format("15:04:05"),
		"server_count":     len(servers),
		"total_containers": totalContainers,
		"down_containers":  downContainers,
	}
	data, _ := json.Marshal(payload)

	h.mu.Lock()
	defer h.mu.Unlock()
	for c := range h.clients {
		select {
		case <-c.ctx.Done():
			delete(h.clients, c)
			continue
		default:
		}
		_, err := c.w.Write(data)
		if err != nil {
			delete(h.clients, c)
			continue
		}
		c.w.Write([]byte("\n"))
		if c.fl != nil {
			c.fl.Flush()
		}
	}
}

// handleWS — SSE (Server-Sent Events) endpoint как упрощённая альтернатива WebSocket.
// Использует SSE вместо WebSocket для совместимости без внешних зависимостей.
func (a *App) handleWS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	client := &wsClient{w: w, fl: fl, ctx: r.Context()}
	a.wsHub.mu.Lock()
	a.wsHub.clients[client] = true
	a.wsHub.mu.Unlock()

	// Отправляем начальное событие.
	_, _ = w.Write([]byte("event: connected\ndata: {\"status\":\"connected\"}\n\n"))
	fl.Flush()

	// Блокируем до отключения клиента.
	<-r.Context().Done()

	a.wsHub.mu.Lock()
	delete(a.wsHub.clients, client)
	a.wsHub.mu.Unlock()
}
