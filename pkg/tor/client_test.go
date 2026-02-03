package tor

import (
	"testing"
)

func TestParseURL(t *testing.T) {
	tests := []struct {
		url    string
		host   string
		port   string
		path   string
		useTLS bool
	}{
		{"https://check.torproject.org/", "check.torproject.org", "443", "/", true},
		{"http://example.com/path", "example.com", "80", "/path", false},
		{"https://example.com:8443/api", "example.com", "8443", "/api", true},
		{"http://example.com", "example.com", "80", "/", false},
		{"https://example.com/a/b/c", "example.com", "443", "/a/b/c", true},
	}

	for _, tt := range tests {
		host, port, path, useTLS := parseURL(tt.url)
		if host != tt.host {
			t.Errorf("parseURL(%q): host = %q, want %q", tt.url, host, tt.host)
		}
		if port != tt.port {
			t.Errorf("parseURL(%q): port = %q, want %q", tt.url, port, tt.port)
		}
		if path != tt.path {
			t.Errorf("parseURL(%q): path = %q, want %q", tt.url, path, tt.path)
		}
		if useTLS != tt.useTLS {
			t.Errorf("parseURL(%q): useTLS = %v, want %v", tt.url, useTLS, tt.useTLS)
		}
	}
}
