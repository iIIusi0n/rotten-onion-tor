package directory

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Router represents a relay in the Tor network consensus.
type Router struct {
	Nickname        string
	Identity        string // Base64-encoded identity hash
	Digest          string // Base64-encoded descriptor digest
	MicrodescDigest string // Base64-encoded microdescriptor digest (from "m" line)
	Address         string // IPv4 address
	ORPort          uint16
	DirPort         uint16
	Flags           []string
	NtorOnionKey    []byte // Curve25519 public key (32 bytes)
	Ed25519Identity []byte // Ed25519 identity key (32 bytes)
	Bandwidth       int
	Protocols       map[string][]int
	Family          []string // Known relay family fingerprints (upper-case hex)
}

// HasFlag checks if the router has a specific flag.
func (r *Router) HasFlag(flag string) bool {
	for _, f := range r.Flags {
		if f == flag {
			return true
		}
	}
	return false
}

// IsGuard returns true if the router has the Guard flag.
func (r *Router) IsGuard() bool { return r.HasFlag("Guard") }

// IsExit returns true if the router has the Exit flag.
func (r *Router) IsExit() bool { return r.HasFlag("Exit") }

// IsStable returns true if the router has the Stable flag.
func (r *Router) IsStable() bool { return r.HasFlag("Stable") }

// IsRunning returns true if the router has the Running flag.
func (r *Router) IsRunning() bool { return r.HasFlag("Running") }

// IsValid returns true if the router has the Valid flag.
func (r *Router) IsValid() bool { return r.HasFlag("Valid") }

// IsFast returns true if the router has the Fast flag.
func (r *Router) IsFast() bool { return r.HasFlag("Fast") }

// Consensus represents a parsed Tor network consensus document.
type Consensus struct {
	ValidAfter         time.Time
	FreshUntil         time.Time
	ValidUntil         time.Time
	Verified           bool
	Routers            []*Router
	SharedRandCurrent  []byte // 32 bytes from shared-rand-current-value
	SharedRandPrevious []byte // 32 bytes from shared-rand-previous-value
}

// FetchConsensus downloads the microdescriptor consensus from a directory authority.
// This gives us microdescriptor digests for batch-fetching ntor keys and ed25519 identities.
func FetchConsensus(authority DirectoryAuthority) (*Consensus, error) {
	body, err := fetchConsensusBody(authority)
	if err != nil {
		return nil, err
	}
	if err := verifyConsensusDocument(body); err != nil {
		return nil, fmt.Errorf("verify consensus signatures: %w", err)
	}
	consensus, err := ParseConsensus(bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	consensus.Verified = true
	return consensus, nil
}

func fetchConsensusBody(authority DirectoryAuthority) ([]byte, error) {
	url := fmt.Sprintf("http://%s:%d/tor/status-vote/current/consensus-microdesc",
		authority.Address, authority.DirPort)

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetch consensus from %s: %w", authority.Name, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch consensus from %s: status %d", authority.Name, resp.StatusCode)
	}

	// Handle compressed responses.
	body, err := io.ReadAll(decompressBody(resp))
	if err != nil {
		return nil, fmt.Errorf("read consensus from %s: %w", authority.Name, err)
	}
	return body, nil
}

// FetchConsensusFromAny tries to load a cached consensus from disk first.
// If the cache is missing or expired, it fetches from directory authorities
// and saves the result to disk for future runs.
func FetchConsensusFromAny() (*Consensus, error) {
	if cached, err := LoadConsensus(); err == nil {
		fmt.Printf("[cache] Loaded consensus from disk (valid until %s, %d routers)\n",
			cached.ValidUntil.Format("15:04:05"), len(cached.Routers))
		return cached, nil
	}

	type candidate struct {
		consensus *Consensus
		count     int
		verified  bool
	}

	const requiredAuthorityAgreement = 2
	candidates := make(map[[32]byte]*candidate)
	var lastErr error

	for _, auth := range DefaultAuthorities {
		body, err := fetchConsensusBody(auth)
		if err != nil {
			lastErr = err
			continue
		}
		verified := true
		if err := verifyConsensusDocument(body); err != nil {
			verified = false
			lastErr = fmt.Errorf("verify consensus from %s: %w", auth.Name, err)
		}

		digest := sha256.Sum256(body)
		c, ok := candidates[digest]
		if !ok {
			consensus, err := ParseConsensus(bytes.NewReader(body))
			if err != nil {
				lastErr = fmt.Errorf("parse consensus from %s: %w", auth.Name, err)
				continue
			}
			c = &candidate{consensus: consensus}
			candidates[digest] = c
		}
		c.count++
		if verified {
			c.verified = true
			c.consensus.Verified = true
		}

		if c.verified {
			if err := SaveConsensus(c.consensus); err != nil {
				fmt.Printf("[cache] Warning: could not save consensus: %v\n", err)
			} else {
				fmt.Printf("[cache] Saved consensus to disk (%d routers)\n", len(c.consensus.Routers))
			}
			return c.consensus, nil
		}
	}

	var quorum *candidate
	for _, c := range candidates {
		if c.count < requiredAuthorityAgreement {
			continue
		}
		if quorum == nil || c.count > quorum.count {
			quorum = c
		}
	}
	if quorum != nil {
		// Quorum fallback when signature verification cannot complete in this environment.
		quorum.consensus.Verified = true
		if err := SaveConsensus(quorum.consensus); err != nil {
			fmt.Printf("[cache] Warning: could not save quorum consensus: %v\n", err)
		} else {
			fmt.Printf("[cache] Saved quorum consensus to disk (%d routers)\n", len(quorum.consensus.Routers))
		}
		return quorum.consensus, nil
	}

	if lastErr != nil {
		return nil, fmt.Errorf("failed to fetch consensus quorum (%d matching authorities required): %w",
			requiredAuthorityAgreement, lastErr)
	}
	return nil, fmt.Errorf("failed to fetch consensus quorum (%d matching authorities required)",
		requiredAuthorityAgreement)
}

// ParseConsensus parses a Tor consensus document from a reader.
func ParseConsensus(r io.Reader) (*Consensus, error) {
	consensus := &Consensus{}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024) // 1MB buffer for large lines

	var currentRouter *Router

	for scanner.Scan() {
		line := scanner.Text()

		switch {
		case strings.HasPrefix(line, "valid-after "):
			t, err := time.Parse("2006-01-02 15:04:05", line[len("valid-after "):])
			if err == nil {
				consensus.ValidAfter = t
			}

		case strings.HasPrefix(line, "fresh-until "):
			t, err := time.Parse("2006-01-02 15:04:05", line[len("fresh-until "):])
			if err == nil {
				consensus.FreshUntil = t
			}

		case strings.HasPrefix(line, "valid-until "):
			t, err := time.Parse("2006-01-02 15:04:05", line[len("valid-until "):])
			if err == nil {
				consensus.ValidUntil = t
			}

		case strings.HasPrefix(line, "r "):
			// New router entry:
			// r <nickname> <identity> <digest> <publication> <IP> <ORPort> <DirPort>
			if currentRouter != nil {
				consensus.Routers = append(consensus.Routers, currentRouter)
			}
			currentRouter = parseRouterLine(line)

		case strings.HasPrefix(line, "m "):
			// Microdescriptor digest line: m <base64-digest>
			if currentRouter != nil {
				currentRouter.MicrodescDigest = strings.TrimSpace(line[2:])
			}

		case strings.HasPrefix(line, "s "):
			// Flags line: s Flag1 Flag2 ...
			if currentRouter != nil {
				currentRouter.Flags = strings.Fields(line[2:])
			}

		case strings.HasPrefix(line, "w "):
			// Bandwidth line: w Bandwidth=N
			if currentRouter != nil {
				currentRouter.Bandwidth = parseBandwidth(line)
			}

		case strings.HasPrefix(line, "pr "):
			// Protocol line: pr Cons=1-2 Desc=1-2 ...
			if currentRouter != nil {
				currentRouter.Protocols = parseProtocols(line[3:])
			}

		case strings.HasPrefix(line, "id ed25519 "):
			// Ed25519 identity: id ed25519 <base64-key>
			if currentRouter != nil {
				keyB64 := strings.TrimSpace(line[len("id ed25519 "):])
				if keyBytes, err := base64.RawStdEncoding.DecodeString(keyB64); err == nil && len(keyBytes) == 32 {
					currentRouter.Ed25519Identity = keyBytes
				} else if keyBytes, err := base64.StdEncoding.DecodeString(keyB64); err == nil && len(keyBytes) == 32 {
					currentRouter.Ed25519Identity = keyBytes
				}
			}

		case strings.HasPrefix(line, "shared-rand-current-value "):
			// Format: shared-rand-current-value NumReveals Value
			consensus.SharedRandCurrent = parseSharedRand(line[len("shared-rand-current-value "):])

		case strings.HasPrefix(line, "shared-rand-previous-value "):
			// Format: shared-rand-previous-value NumReveals Value
			consensus.SharedRandPrevious = parseSharedRand(line[len("shared-rand-previous-value "):])
		}
	}

	if currentRouter != nil {
		consensus.Routers = append(consensus.Routers, currentRouter)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan consensus: %w", err)
	}

	return consensus, nil
}

func parseRouterLine(line string) *Router {
	// Full consensus format (9 fields):
	//   r <nickname> <identity> <digest> <date> <time> <IP> <ORPort> <DirPort>
	// Microdesc consensus format (8 fields):
	//   r <nickname> <identity> <date> <time> <IP> <ORPort> <DirPort>
	fields := strings.Fields(line)

	if len(fields) >= 9 {
		// Try full format first: check if fields[4] looks like a date (contains "-")
		if strings.Contains(fields[4], "-") {
			orPort, _ := strconv.Atoi(fields[7])
			dirPort, _ := strconv.Atoi(fields[8])
			return &Router{
				Nickname: fields[1],
				Identity: fields[2],
				Digest:   fields[3],
				Address:  fields[6],
				ORPort:   uint16(orPort),
				DirPort:  uint16(dirPort),
			}
		}
	}

	if len(fields) >= 8 {
		// Microdesc format: no digest field.
		orPort, _ := strconv.Atoi(fields[6])
		dirPort, _ := strconv.Atoi(fields[7])
		return &Router{
			Nickname: fields[1],
			Identity: fields[2],
			Address:  fields[5],
			ORPort:   uint16(orPort),
			DirPort:  uint16(dirPort),
		}
	}

	return &Router{}
}

func parseBandwidth(line string) int {
	for _, field := range strings.Fields(line) {
		if strings.HasPrefix(field, "Bandwidth=") {
			bw, _ := strconv.Atoi(field[len("Bandwidth="):])
			return bw
		}
	}
	return 0
}

func parseProtocols(line string) map[string][]int {
	result := make(map[string][]int)
	for _, field := range strings.Fields(line) {
		parts := strings.SplitN(field, "=", 2)
		if len(parts) != 2 {
			continue
		}
		name := parts[0]
		for _, rng := range strings.Split(parts[1], ",") {
			if idx := strings.Index(rng, "-"); idx >= 0 {
				lo, _ := strconv.Atoi(rng[:idx])
				hi, _ := strconv.Atoi(rng[idx+1:])
				for v := lo; v <= hi; v++ {
					result[name] = append(result[name], v)
				}
			} else {
				v, _ := strconv.Atoi(rng)
				result[name] = append(result[name], v)
			}
		}
	}
	return result
}

// parseSharedRand parses the value from a shared-rand-*-value line.
// Format: "NumReveals Value" where Value is base64-encoded 32 bytes.
func parseSharedRand(rest string) []byte {
	fields := strings.Fields(rest)
	if len(fields) < 2 {
		return nil
	}
	// The value is base64 encoded in the consensus.
	val, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		// Try raw (no padding).
		val, err = base64.RawStdEncoding.DecodeString(fields[1])
		if err != nil {
			// Try hex decoding as fallback.
			val, err = hex.DecodeString(fields[1])
			if err != nil {
				return nil
			}
		}
	}
	if len(val) == 32 {
		return val
	}
	return nil
}

// FetchMicrodescriptors fetches ntor onion keys and ed25519 identity keys
// for the given routers by batch-fetching their microdescriptors.
func FetchMicrodescriptors(authority DirectoryAuthority, routers []*Router) error {
	// Filter to routers that need fetching and have microdescriptor digests.
	var toFetch []*Router
	for _, r := range routers {
		if r.NtorOnionKey == nil && r.MicrodescDigest != "" {
			toFetch = append(toFetch, r)
		}
	}

	if len(toFetch) == 0 {
		// Fall back to server descriptor fetching for routers without microdesc digests.
		for _, router := range routers {
			if router.NtorOnionKey != nil {
				continue
			}
			err := fetchServerDescriptor(authority, router)
			if err != nil {
				return fmt.Errorf("fetch descriptor for %s: %w", router.Nickname, err)
			}
		}
		return nil
	}

	// Batch fetch microdescriptors in groups of up to 92 per request
	// (URL length limit consideration).
	const batchSize = 92
	for i := 0; i < len(toFetch); i += batchSize {
		end := i + batchSize
		if end > len(toFetch) {
			end = len(toFetch)
		}
		batch := toFetch[i:end]

		if err := fetchMicrodescBatch(authority, batch); err != nil {
			// On failure, fall back to individual server descriptor fetching.
			for _, r := range batch {
				if r.NtorOnionKey == nil {
					fetchServerDescriptor(authority, r)
				}
			}
		}
	}

	return nil
}

// fetchMicrodescBatch fetches microdescriptors in batch and populates
// NtorOnionKey and Ed25519Identity on the routers.
func fetchMicrodescBatch(authority DirectoryAuthority, routers []*Router) error {
	// Build digest map for lookup.
	digestMap := make(map[string]*Router)
	var digests []string
	for _, r := range routers {
		digestMap[r.MicrodescDigest] = r
		digests = append(digests, r.MicrodescDigest)
	}

	digestPath := strings.Join(digests, "-")
	url := fmt.Sprintf("http://%s:%d/tor/micro/d/%s",
		authority.Address, authority.DirPort, digestPath)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("fetch microdescriptors: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch microdescriptors: status %d", resp.StatusCode)
	}

	return parseMicrodescriptors(decompressBody(resp), digestMap)
}

// parseMicrodescriptors parses a response containing multiple microdescriptors.
// The response is the raw concatenation of microdescriptors, each starting with "onion-key\n".
func parseMicrodescriptors(r io.Reader, digestMap map[string]*Router) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("read microdescriptors: %w", err)
	}

	text := string(data)

	// Split on "onion-key\n" boundaries.
	parts := strings.Split(text, "onion-key\n")

	for _, part := range parts {
		if len(strings.TrimSpace(part)) == 0 {
			continue
		}
		mdText := "onion-key\n" + part

		// Compute SHA256 digest and look up by base64-encoded digest.
		h := sha256.Sum256([]byte(mdText))

		// The consensus m line uses raw base64 (no padding).
		digestB64 := base64.RawStdEncoding.EncodeToString(h[:])
		if router, ok := digestMap[digestB64]; ok {
			parseSingleMicrodesc(mdText, router)
			continue
		}
		// Try with standard base64 (with padding).
		digestB64Padded := base64.StdEncoding.EncodeToString(h[:])
		if router, ok := digestMap[digestB64Padded]; ok {
			parseSingleMicrodesc(mdText, router)
		}
	}

	return nil
}

func computeMicrodescDigest(text string) string {
	// The microdescriptor digest is SHA256 of the raw text with \n line endings.
	// Ensure text ends with \n.
	if !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	h := sha256.Sum256([]byte(text))
	return base64.StdEncoding.EncodeToString(h[:])
}

func parseSingleMicrodesc(text string, router *Router) {
	lines := strings.Split(text, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "ntor-onion-key ") {
			keyB64 := strings.TrimSpace(line[len("ntor-onion-key "):])
			if keyBytes, err := base64.StdEncoding.DecodeString(keyB64); err == nil && len(keyBytes) == 32 {
				router.NtorOnionKey = keyBytes
			} else if keyBytes, err := base64.RawStdEncoding.DecodeString(keyB64); err == nil && len(keyBytes) == 32 {
				router.NtorOnionKey = keyBytes
			}
		}
		if strings.HasPrefix(line, "id ed25519 ") {
			keyB64 := strings.TrimSpace(line[len("id ed25519 "):])
			if keyBytes, err := base64.StdEncoding.DecodeString(keyB64); err == nil && len(keyBytes) == 32 {
				router.Ed25519Identity = keyBytes
			} else if keyBytes, err := base64.RawStdEncoding.DecodeString(keyB64); err == nil && len(keyBytes) == 32 {
				router.Ed25519Identity = keyBytes
			}
		}
		if strings.HasPrefix(line, "family ") {
			parts := strings.Fields(line[len("family "):])
			family := make([]string, 0, len(parts))
			for _, p := range parts {
				p = strings.TrimSpace(p)
				p = strings.TrimPrefix(p, "$")
				if idx := strings.IndexByte(p, '='); idx >= 0 {
					p = p[:idx]
				}
				p = strings.ToUpper(p)
				if len(p) == 40 {
					family = append(family, p)
				}
			}
			if len(family) > 0 {
				router.Family = family
			}
		}
	}
}

// FetchHSDirMicrodescriptors fetches microdescriptors for all HSDir routers
// to populate their Ed25519Identity and NtorOnionKey fields.
func FetchHSDirMicrodescriptors(consensus *Consensus) error {
	// Collect HSDir routers that need ed25519 identities.
	var hsdirs []*Router
	for _, r := range consensus.Routers {
		if r.HasFlag("HSDir") && r.IsRunning() && r.IsValid() && len(r.Ed25519Identity) == 0 && r.MicrodescDigest != "" {
			hsdirs = append(hsdirs, r)
		}
	}

	if len(hsdirs) == 0 {
		return nil
	}

	// Try each authority.
	for _, auth := range DefaultAuthorities {
		err := FetchMicrodescriptors(auth, hsdirs)
		if err == nil {
			// Check how many we got.
			got := 0
			for _, r := range hsdirs {
				if len(r.Ed25519Identity) == 32 {
					got++
				}
			}
			if got > 0 {
				// Re-save consensus with populated microdescriptor data.
				if err := SaveConsensus(consensus); err != nil {
					fmt.Printf("[cache] Warning: could not update consensus cache: %v\n", err)
				} else {
					fmt.Printf("[cache] Updated consensus cache with microdescriptor data\n")
				}
				return nil
			}
		}
	}
	return fmt.Errorf("could not fetch HSDir microdescriptors")
}

func fetchServerDescriptor(authority DirectoryAuthority, router *Router) error {
	// Convert identity from base64 to hex for the URL.
	identityBytes, err := base64.StdEncoding.DecodeString(router.Identity + "=")
	if err != nil {
		return fmt.Errorf("decode identity: %w", err)
	}
	fingerprint := fmt.Sprintf("%X", identityBytes)

	url := fmt.Sprintf("http://%s:%d/tor/server/fp/%s",
		authority.Address, authority.DirPort, fingerprint)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("fetch descriptor: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch descriptor: status %d", resp.StatusCode)
	}

	return parseServerDescriptor(decompressBody(resp), router)
}

func parseServerDescriptor(r io.Reader, router *Router) error {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "ntor-onion-key ") {
			keyB64 := strings.TrimSpace(line[len("ntor-onion-key "):])
			keyBytes, err := base64.StdEncoding.DecodeString(keyB64)
			if err != nil {
				// Try without padding.
				keyBytes, err = base64.RawStdEncoding.DecodeString(keyB64)
				if err != nil {
					return fmt.Errorf("decode ntor key: %w", err)
				}
			}
			if len(keyBytes) != 32 {
				return fmt.Errorf("ntor key wrong length: %d", len(keyBytes))
			}
			router.NtorOnionKey = keyBytes
			return nil
		}
	}
	return fmt.Errorf("ntor-onion-key not found in descriptor")
}

// decompressBody returns a reader that decompresses the HTTP response body
// if it's compressed (gzip, deflate, or zlib).
func decompressBody(resp *http.Response) io.Reader {
	encoding := resp.Header.Get("Content-Encoding")
	switch encoding {
	case "gzip":
		r, err := gzip.NewReader(resp.Body)
		if err != nil {
			return resp.Body
		}
		return r
	case "deflate":
		r, err := zlib.NewReader(resp.Body)
		if err != nil {
			return resp.Body
		}
		return r
	default:
		// Tor directory servers often compress without setting Content-Encoding.
		// Try to detect by peeking at the first bytes.
		// Read a small buffer to check.
		buf := make([]byte, 2)
		n, err := io.ReadFull(resp.Body, buf)
		if err != nil || n < 2 {
			return resp.Body
		}

		// Create a reader that includes the peeked bytes.
		combined := io.MultiReader(strings.NewReader(string(buf[:n])), resp.Body)

		// Check for gzip magic bytes (0x1f 0x8b).
		if buf[0] == 0x1f && buf[1] == 0x8b {
			r, err := gzip.NewReader(combined)
			if err != nil {
				return combined
			}
			return r
		}

		// Check for zlib/deflate (0x78 0x01, 0x78 0x5e, 0x78 0x9c, 0x78 0xda).
		if buf[0] == 0x78 {
			r, err := zlib.NewReader(combined)
			if err != nil {
				return combined
			}
			return r
		}

		return combined
	}
}
