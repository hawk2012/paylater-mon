// Package msteams — отправка уведомлений в Microsoft Teams (Adaptive Cards).
package msteams

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"paylater-mon/internal/config"
)

// ThemeColor — цвет темы Adaptive Card.
type ThemeColor string

const (
	ColorDefault   ThemeColor = "default"
	ColorAccent    ThemeColor = "accent"
	ColorGood      ThemeColor = "good"
	ColorWarning   ThemeColor = "warning"
	ColorAttention ThemeColor = "attention"
)

// Service — отправка Adaptive Cards в MS Teams webhook.
type Service struct {
	cfg  *config.Config
	http *http.Client
}

// Card — Adaptive Card.
type Card struct {
	Schema  string        `json:"$schema"`
	Type    string        `json:"type"`
	Version string        `json:"version"`
	Body    []CardElement `json:"body"`
}

// CardElement — элемент тела карточки.
type CardElement struct {
	Type   string     `json:"type"`
	Text   string     `json:"text,omitempty"`
	Weight string     `json:"weight,omitempty"`
	Size   string     `json:"size,omitempty"`
	Color  ThemeColor `json:"color,omitempty"`
	Wrap   *bool      `json:"wrap,omitempty"`
}

// Message — обёртка сообщения Teams.
type Message struct {
	Type        string       `json:"type"`
	Attachments []Attachment `json:"attachments"`
}

type Attachment struct {
	ContentType string `json:"contentType"`
	Content     *Card  `json:"content,omitempty"`
}

// New создаёт сервис MS Teams.
func New(cfg *config.Config) *Service {
	return &Service{cfg: cfg, http: &http.Client{Timeout: 30 * time.Second}}
}

// ApplyConfig обновляет конфигурацию на лету (без перезапуска).
func (s *Service) ApplyConfig(cfg *config.Config) {
	s.cfg = cfg
}

// SendMessage отправляет простое сообщение с заголовком и текстом.
func (s *Service) SendMessage(title, message string, color ThemeColor) (bool, error) {
	wrap := true
	card := &Card{
		Schema:  "http://adaptivecards.io/schemas/adaptive-card.json",
		Type:    "AdaptiveCard",
		Version: "1.4",
		Body: []CardElement{
			{Type: "TextBlock", Text: title, Weight: "bolder", Size: "large", Color: color},
			{Type: "TextBlock", Text: message, Wrap: &wrap},
		},
	}
	return s.sendCard(card)
}

func (s *Service) sendCard(card *Card) (bool, error) {
	webhook := s.cfg.MSTeams.WebhookURL
	if webhook == "" {
		return false, fmt.Errorf("msteams: webhook URL not configured")
	}
	msg := &Message{
		Type: "Message",
		Attachments: []Attachment{{
			ContentType: "application/vnd.microsoft.card.adaptive",
			Content:     card,
		}},
	}
	body, _ := json.Marshal(msg)
	req, err := http.NewRequest(http.MethodPost, webhook, bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.http.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		// Teams может вернуть 200/202 с ошибкой в теле.
		low := strings.ToLower(string(respBody))
		if strings.Contains(low, "error") || strings.Contains(low, "not sent") || strings.Contains(low, "failed") {
			return false, fmt.Errorf("msteams: server error in body: %s", string(respBody))
		}
		return true, nil
	}
	return false, fmt.Errorf("msteams: HTTP %d: %s", resp.StatusCode, string(respBody))
}
