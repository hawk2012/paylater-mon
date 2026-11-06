package zeebe

import (
	"testing"
)

func TestExtractHost(t *testing.T) {
	cases := map[string]string{
		"http://172.31.32.69":              "172.31.32.69",
		"http://172.31.32.69/":             "172.31.32.69",
		"https://zeebe.example.com":        "zeebe.example.com",
		"http://172.31.32.69:8080":         "172.31.32.69",
		"http://[::1]:8080":                "::1",
		"https://[2001:db8::1]":            "2001:db8::1",
		"http://localhost:9600":            "localhost",
		"172.31.32.69":                     "172.31.32.69",
		"":                                 "",
	}
	for input, want := range cases {
		if got := extractHost(input); got != want {
			t.Errorf("extractHost(%q) = %q, want %q", input, got, want)
		}
	}
}
