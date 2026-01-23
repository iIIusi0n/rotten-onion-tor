package directory

import (
	"strings"
	"testing"
)

func TestDefaultAuthorities(t *testing.T) {
	if len(DefaultAuthorities) != 9 {
		t.Errorf("expected 9 authorities, got %d", len(DefaultAuthorities))
	}

	names := make(map[string]bool)
	for _, auth := range DefaultAuthorities {
		if auth.Name == "" {
			t.Error("authority has empty name")
		}
		if auth.Address == "" {
			t.Error("authority has empty address")
		}
		if auth.DirPort == 0 {
			t.Errorf("authority %s has zero DirPort", auth.Name)
		}
		if auth.ORPort == 0 {
			t.Errorf("authority %s has zero ORPort", auth.Name)
		}
		if len(auth.Fingerprint) != 40 {
			t.Errorf("authority %s fingerprint length = %d, want 40", auth.Name, len(auth.Fingerprint))
		}
		names[auth.Name] = true
	}

	// Check some known authority names.
	expectedNames := []string{"moria1", "tor26", "dizum", "gabelmoo", "dannenberg", "longclaw", "bastet", "faravahar"}
	for _, name := range expectedNames {
		if !names[name] {
			t.Errorf("missing authority: %s", name)
		}
	}
}

func TestParseConsensus(t *testing.T) {
	// Minimal consensus document for testing.
	consensus := `network-status-version 3
vote-status consensus
consensus-method 32
valid-after 2024-01-15 12:00:00
fresh-until 2024-01-15 13:00:00
valid-until 2024-01-15 15:00:00
r TestRelay1 AAAAAAAAAAAAAAAAAAAAAAAAAAAA BBBBBBBBBBBBBBBBBBBBBBBBBBBB 2024-01-15 11:00:00 1.2.3.4 9001 0
s Exit Fast Guard Running Stable Valid
w Bandwidth=5000
pr Cons=1-2 Desc=1-2 DirCache=2 HSDir=2 HSIntro=4-5 HSRend=1-2 Link=1-5 LinkAuth=1,3 Microdesc=1-2 Relay=1-4
r TestRelay2 CCCCCCCCCCCCCCCCCCCCCCCCCCCC DDDDDDDDDDDDDDDDDDDDDDDDDDDD 2024-01-15 11:00:00 5.6.7.8 443 80
s Fast Running Stable Valid
w Bandwidth=3000
directory-footer
`

	c, err := ParseConsensus(strings.NewReader(consensus))
	if err != nil {
		t.Fatalf("ParseConsensus: %v", err)
	}

	if c.ValidAfter.IsZero() {
		t.Error("ValidAfter is zero")
	}
	if c.FreshUntil.IsZero() {
		t.Error("FreshUntil is zero")
	}

	if len(c.Routers) != 2 {
		t.Fatalf("expected 2 routers, got %d", len(c.Routers))
	}

	r1 := c.Routers[0]
	if r1.Nickname != "TestRelay1" {
		t.Errorf("router 1 nickname = %q, want TestRelay1", r1.Nickname)
	}
	if r1.Address != "1.2.3.4" {
		t.Errorf("router 1 address = %q, want 1.2.3.4", r1.Address)
	}
	if r1.ORPort != 9001 {
		t.Errorf("router 1 ORPort = %d, want 9001", r1.ORPort)
	}
	if !r1.IsGuard() {
		t.Error("router 1 should be guard")
	}
	if !r1.IsExit() {
		t.Error("router 1 should be exit")
	}
	if r1.Bandwidth != 5000 {
		t.Errorf("router 1 bandwidth = %d, want 5000", r1.Bandwidth)
	}

	r2 := c.Routers[1]
	if r2.Nickname != "TestRelay2" {
		t.Errorf("router 2 nickname = %q, want TestRelay2", r2.Nickname)
	}
	if r2.ORPort != 443 {
		t.Errorf("router 2 ORPort = %d, want 443", r2.ORPort)
	}
	if r2.DirPort != 80 {
		t.Errorf("router 2 DirPort = %d, want 80", r2.DirPort)
	}
	if r2.IsGuard() {
		t.Error("router 2 should not be guard")
	}
	if r2.IsExit() {
		t.Error("router 2 should not be exit")
	}
}

func TestRouterFlags(t *testing.T) {
	r := &Router{
		Flags: []string{"Exit", "Fast", "Guard", "Running", "Stable", "Valid"},
	}

	if !r.IsExit() {
		t.Error("should be exit")
	}
	if !r.IsGuard() {
		t.Error("should be guard")
	}
	if !r.IsRunning() {
		t.Error("should be running")
	}
	if !r.IsStable() {
		t.Error("should be stable")
	}
	if !r.IsValid() {
		t.Error("should be valid")
	}
	if !r.IsFast() {
		t.Error("should be fast")
	}
	if r.HasFlag("BadExit") {
		t.Error("should not have BadExit")
	}
}

func TestParseProtocols(t *testing.T) {
	protos := parseProtocols("Cons=1-2 Desc=1-2 Link=1-5 Relay=1-4")

	if v, ok := protos["Link"]; !ok || len(v) != 5 {
		t.Errorf("Link protocols = %v, want [1,2,3,4,5]", v)
	}
	if v, ok := protos["Relay"]; !ok || len(v) != 4 {
		t.Errorf("Relay protocols = %v, want [1,2,3,4]", v)
	}
}

func TestParseBandwidth(t *testing.T) {
	bw := parseBandwidth("w Bandwidth=12345")
	if bw != 12345 {
		t.Errorf("bandwidth = %d, want 12345", bw)
	}

	bw = parseBandwidth("w Bandwidth=0 Unmeasured=1")
	if bw != 0 {
		t.Errorf("bandwidth = %d, want 0", bw)
	}
}

func TestParseConsensusEmpty(t *testing.T) {
	c, err := ParseConsensus(strings.NewReader(""))
	if err != nil {
		t.Fatalf("ParseConsensus: %v", err)
	}
	if len(c.Routers) != 0 {
		t.Errorf("expected 0 routers, got %d", len(c.Routers))
	}
}
