package directory

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// CachedConsensus is the JSON-serializable form of a Consensus.
type CachedConsensus struct {
	ValidAfter         time.Time      `json:"valid_after"`
	FreshUntil         time.Time      `json:"fresh_until"`
	ValidUntil         time.Time      `json:"valid_until"`
	Verified           bool           `json:"verified"`
	SharedRandCurrent  []byte         `json:"shared_rand_current,omitempty"`
	SharedRandPrevious []byte         `json:"shared_rand_previous,omitempty"`
	Routers            []CachedRouter `json:"routers"`
}

// CachedRouter is the JSON-serializable form of a Router.
type CachedRouter struct {
	Nickname        string           `json:"nickname"`
	Identity        string           `json:"identity"`
	Digest          string           `json:"digest,omitempty"`
	MicrodescDigest string           `json:"microdesc_digest,omitempty"`
	Address         string           `json:"address"`
	ORPort          uint16           `json:"or_port"`
	DirPort         uint16           `json:"dir_port"`
	Flags           []string         `json:"flags,omitempty"`
	NtorOnionKey    []byte           `json:"ntor_onion_key,omitempty"`
	Ed25519Identity []byte           `json:"ed25519_identity,omitempty"`
	Bandwidth       int              `json:"bandwidth"`
	Protocols       map[string][]int `json:"protocols,omitempty"`
	Family          []string         `json:"family,omitempty"`
}

// CacheDir returns the path to the cache directory (~/.rotten-tor-cache/),
// creating it if it doesn't exist.
func CacheDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	dir := filepath.Join(home, ".rotten-tor-cache")
	os.MkdirAll(dir, 0700)
	return dir
}

// SaveConsensus writes the consensus to disk as JSON.
func SaveConsensus(c *Consensus) error {
	cached := CachedConsensus{
		ValidAfter:         c.ValidAfter,
		FreshUntil:         c.FreshUntil,
		ValidUntil:         c.ValidUntil,
		Verified:           c.Verified,
		SharedRandCurrent:  c.SharedRandCurrent,
		SharedRandPrevious: c.SharedRandPrevious,
		Routers:            make([]CachedRouter, len(c.Routers)),
	}
	for i, r := range c.Routers {
		cached.Routers[i] = CachedRouter{
			Nickname:        r.Nickname,
			Identity:        r.Identity,
			Digest:          r.Digest,
			MicrodescDigest: r.MicrodescDigest,
			Address:         r.Address,
			ORPort:          r.ORPort,
			DirPort:         r.DirPort,
			Flags:           r.Flags,
			NtorOnionKey:    r.NtorOnionKey,
			Ed25519Identity: r.Ed25519Identity,
			Bandwidth:       r.Bandwidth,
			Protocols:       r.Protocols,
			Family:          r.Family,
		}
	}

	data, err := json.Marshal(cached)
	if err != nil {
		return fmt.Errorf("marshal consensus cache: %w", err)
	}

	path := filepath.Join(CacheDir(), "consensus.json")
	return os.WriteFile(path, data, 0600)
}

// LoadConsensus reads the cached consensus from disk.
// Returns an error if the file is missing or the consensus has expired.
func LoadConsensus() (*Consensus, error) {
	path := filepath.Join(CacheDir(), "consensus.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read consensus cache: %w", err)
	}

	var cached CachedConsensus
	if err := json.Unmarshal(data, &cached); err != nil {
		return nil, fmt.Errorf("unmarshal consensus cache: %w", err)
	}

	now := time.Now().UTC()
	if now.After(cached.ValidUntil) {
		return nil, fmt.Errorf("cached consensus expired (valid until %s)", cached.ValidUntil)
	}
	if !cached.ValidAfter.IsZero() && now.Before(cached.ValidAfter.Add(-10*time.Minute)) {
		return nil, fmt.Errorf("cached consensus not yet valid (valid after %s)", cached.ValidAfter)
	}
	if !cached.ValidAfter.IsZero() && !cached.ValidUntil.IsZero() && !cached.ValidUntil.After(cached.ValidAfter) {
		return nil, fmt.Errorf("cached consensus validity interval is invalid")
	}
	if !cached.Verified {
		return nil, fmt.Errorf("cached consensus is not marked as signature-verified")
	}

	c := &Consensus{
		ValidAfter:         cached.ValidAfter,
		FreshUntil:         cached.FreshUntil,
		ValidUntil:         cached.ValidUntil,
		Verified:           cached.Verified,
		SharedRandCurrent:  cached.SharedRandCurrent,
		SharedRandPrevious: cached.SharedRandPrevious,
		Routers:            make([]*Router, len(cached.Routers)),
	}
	for i, cr := range cached.Routers {
		c.Routers[i] = &Router{
			Nickname:        cr.Nickname,
			Identity:        cr.Identity,
			Digest:          cr.Digest,
			MicrodescDigest: cr.MicrodescDigest,
			Address:         cr.Address,
			ORPort:          cr.ORPort,
			DirPort:         cr.DirPort,
			Flags:           cr.Flags,
			NtorOnionKey:    cr.NtorOnionKey,
			Ed25519Identity: cr.Ed25519Identity,
			Bandwidth:       cr.Bandwidth,
			Protocols:       cr.Protocols,
			Family:          cr.Family,
		}
	}

	return c, nil
}
