package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestWriteJSONError проверяет, что API-ошибки возвращаются как JSON,
// а не как plain text (иначе клиентский fetch().json() падает с
// "Unexpected token 'o'").
func TestWriteJSONError(t *testing.T) {
	rr := httptest.NewRecorder()
	writeJSONError(rr, http.StatusInternalServerError, "openai HTTP 401: bad key")

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("expected application/json, got %q", ct)
	}
	var m map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &m); err != nil {
		t.Fatalf("response is not valid JSON: %v (body=%q)", err, rr.Body.String())
	}
	if m["error"] == "" {
		t.Fatal("expected error message in JSON")
	}
}
