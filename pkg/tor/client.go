// Package tor provides a high-level Tor client that bootstraps the directory,
// builds circuits, and makes HTTP requests through the Tor network.
package tor

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"strings"
	"time"

	"rotten-onion-tor/pkg/channel"
	"rotten-onion-tor/pkg/circuit"
	"rotten-onion-tor/pkg/directory"
	"rotten-onion-tor/pkg/onion"
	"rotten-onion-tor/pkg/stream"
)

const ioTimeout = 90 * time.Second

// Client is a high-level Tor client.
type Client struct {
	consensus *directory.Consensus
	logger    *log.Logger
}

// NewClient creates a new Tor client by bootstrapping the directory.
func NewClient(logger *log.Logger) (*Client, error) {
	if logger == nil {
		logger = log.Default()
	}

	logger.Println("[*] Bootstrapping: fetching consensus from directory authorities...")
	consensus, err := directory.FetchConsensusFromAny()
	if err != nil {
		return nil, fmt.Errorf("bootstrap: %w", err)
	}

	logger.Printf("[+] Consensus fetched: %d routers", len(consensus.Routers))
	logger.Printf("    Valid after: %s", consensus.ValidAfter)
	logger.Printf("    Valid until: %s", consensus.ValidUntil)

	return &Client{
		consensus: consensus,
		logger:    logger,
	}, nil
}

// CircuitInfo holds information about a built circuit.
type CircuitInfo struct {
	Guard  *directory.Router
	Middle *directory.Router
	Exit   *directory.Router
}

// BuildCircuit creates a 3-hop Tor circuit (guard -> middle -> exit).
func (c *Client) BuildCircuit() (*circuit.Circuit, *stream.Manager, *CircuitInfo, error) {
	// Select path.
	c.logger.Println("[*] Selecting circuit path...")
	guard, middle, exit, err := directory.SelectCircuitPath(c.consensus)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("select path: %w", err)
	}

	info := &CircuitInfo{Guard: guard, Middle: middle, Exit: exit}
	c.logger.Printf("[+] Path: %s (%s:%d) -> %s (%s:%d) -> %s (%s:%d)",
		guard.Nickname, guard.Address, guard.ORPort,
		middle.Nickname, middle.Address, middle.ORPort,
		exit.Nickname, exit.Address, exit.ORPort)

	// Fetch server descriptors (ntor onion keys) for all three relays.
	c.logger.Println("[*] Fetching relay descriptors...")
	auth := directory.DefaultAuthorities[0]
	for _, router := range []*directory.Router{guard, middle, exit} {
		if router.NtorOnionKey == nil {
			if err := directory.FetchMicrodescriptors(auth, []*directory.Router{router}); err != nil {
				// Try next authority on failure.
				fetched := false
				for _, a := range directory.DefaultAuthorities[1:] {
					if err2 := directory.FetchMicrodescriptors(a, []*directory.Router{router}); err2 == nil {
						fetched = true
						break
					}
				}
				if !fetched {
					return nil, nil, nil, fmt.Errorf("fetch descriptor for %s: %w", router.Nickname, err)
				}
			}
		}
	}
	c.logger.Println("[+] Descriptors fetched successfully")

	// Connect to guard relay via TLS.
	addr := fmt.Sprintf("%s:%d", guard.Address, guard.ORPort)
	c.logger.Printf("[*] Connecting to guard relay %s at %s...", guard.Nickname, addr)
	ch, err := channel.DialWithIdentity(addr, 30*time.Second, guard.Identity)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("connect to guard: %w", err)
	}
	c.logger.Printf("[+] Channel established (link protocol v%d)", ch.Version())

	// Create circuit to guard.
	c.logger.Printf("[*] Creating circuit to %s...", guard.Nickname)
	circ, err := circuit.New(ch)
	if err != nil {
		ch.Close()
		return nil, nil, nil, fmt.Errorf("create circuit: %w", err)
	}

	if err := circ.Create(guard); err != nil {
		ch.Close()
		return nil, nil, nil, fmt.Errorf("CREATE to guard: %w", err)
	}
	c.logger.Printf("[+] Circuit created to %s (1 hop)", guard.Nickname)

	// Extend to middle relay.
	c.logger.Printf("[*] Extending circuit to %s...", middle.Nickname)
	if err := circ.Extend(middle); err != nil {
		circ.Destroy()
		ch.Close()
		return nil, nil, nil, fmt.Errorf("EXTEND to middle: %w", err)
	}
	c.logger.Printf("[+] Extended to %s (2 hops)", middle.Nickname)

	// Extend to exit relay.
	c.logger.Printf("[*] Extending circuit to %s...", exit.Nickname)
	if err := circ.Extend(exit); err != nil {
		circ.Destroy()
		ch.Close()
		return nil, nil, nil, fmt.Errorf("EXTEND to exit: %w", err)
	}
	c.logger.Printf("[+] Extended to %s (3 hops)", exit.Nickname)

	// Create stream manager.
	mgr := stream.NewManager(circ)

	return circ, mgr, info, nil
}

// HTTPGet makes an HTTP GET request through a Tor circuit.
func (c *Client) HTTPGet(url string) (string, error) {
	circ, mgr, info, err := c.BuildCircuit()
	if err != nil {
		return "", err
	}
	defer circ.Close()

	_ = info

	// Parse URL.
	host, port, path, useTLS := parseURL(url)

	c.logger.Printf("[*] Opening stream to %s:%s...", host, port)

	// Open stream.
	s, err := mgr.OpenStream(fmt.Sprintf("%s:%s", host, port))
	if err != nil {
		return "", fmt.Errorf("open stream: %w", err)
	}
	c.logger.Println("[+] Stream opened")

	if useTLS {
		return c.httpGetTLS(s, mgr, host, path)
	}
	return c.httpGetPlain(s, mgr, host, path)
}

func (c *Client) httpGetPlain(s *stream.Stream, mgr *stream.Manager, host, path string) (string, error) {
	// Send HTTP request.
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, host)
	c.logger.Printf("[*] Sending HTTP request...")
	if _, err := s.WriteWithDeadline(mgr, []byte(req), time.Now().Add(ioTimeout)); err != nil {
		return "", fmt.Errorf("write request: %w", err)
	}

	// Read response.
	return c.readHTTPResponse(s, mgr)
}

func (c *Client) httpGetTLS(s *stream.Stream, mgr *stream.Manager, host, path string) (string, error) {
	// For HTTPS, we need to do TLS over the Tor stream.
	// Create a net.Conn adapter for the stream.
	streamConn := NewStreamConn(s, mgr)

	tlsConfig := &tls.Config{
		ServerName: host,
	}
	tlsConn := tls.Client(streamConn, tlsConfig)
	_ = tlsConn.SetDeadline(time.Now().Add(ioTimeout))
	if err := tlsConn.Handshake(); err != nil {
		return "", fmt.Errorf("TLS handshake: %w", err)
	}
	defer tlsConn.Close()

	// Send HTTP request over TLS.
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, host)
	c.logger.Printf("[*] Sending HTTPS request...")
	_ = tlsConn.SetWriteDeadline(time.Now().Add(ioTimeout))
	if _, err := tlsConn.Write([]byte(req)); err != nil {
		return "", fmt.Errorf("write request: %w", err)
	}

	// Read response.
	var response strings.Builder
	buf := make([]byte, 4096)
	for {
		_ = tlsConn.SetReadDeadline(time.Now().Add(ioTimeout))
		n, err := tlsConn.Read(buf)
		if n > 0 {
			response.Write(buf[:n])
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			// TLS might return an error on close.
			break
		}
	}

	return response.String(), nil
}

func (c *Client) readHTTPResponse(s *stream.Stream, mgr *stream.Manager) (string, error) {
	var response strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := s.ReadWithDeadline(mgr, buf, time.Now().Add(ioTimeout))
		if n > 0 {
			response.Write(buf[:n])
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			return response.String(), err
		}
	}
	return response.String(), nil
}

func parseURL(url string) (host, port, path string, useTLS bool) {
	if strings.HasPrefix(url, "https://") {
		useTLS = true
		url = url[8:]
		port = "443"
	} else if strings.HasPrefix(url, "http://") {
		url = url[7:]
		port = "80"
	} else {
		port = "80"
	}

	// Split host and path.
	idx := strings.Index(url, "/")
	if idx >= 0 {
		host = url[:idx]
		path = url[idx:]
	} else {
		host = url
		path = "/"
	}

	// Check for port in host.
	if colonIdx := strings.LastIndex(host, ":"); colonIdx >= 0 {
		port = host[colonIdx+1:]
		host = host[:colonIdx]
	}

	return
}

// Consensus returns the consensus used by this client.
func (c *Client) Consensus() *directory.Consensus {
	return c.consensus
}

// HTTPGetOnion makes an HTTP GET request to a v3 .onion service.
func (c *Client) HTTPGetOnion(onionURL string) (string, error) {
	// Parse URL to extract host and path.
	host, port, path, useTLS := parseURL(onionURL)

	// Strip .onion suffix for the address.
	onionAddr := host

	c.logger.Printf("[*] Connecting to onion service: %s", onionAddr)

	circ, mgr, err := onion.ConnectOnion(c.consensus, onionAddr, c.logger)
	if err != nil {
		return "", fmt.Errorf("connect to onion: %w", err)
	}
	defer circ.Close()

	c.logger.Printf("[*] Opening stream to %s:%s...", host, port)

	// Onion rendezvous streams use an empty host target (":port").
	// Spec: rend-spec-v3 "Managing streams", step 2.
	s, err := mgr.OpenStream(":" + port)
	if err != nil {
		return "", fmt.Errorf("open stream: %w", err)
	}
	c.logger.Println("[+] Stream opened to onion service")

	if useTLS {
		return c.httpGetTLS(s, mgr, host, path)
	}
	return c.httpGetPlain(s, mgr, host, path)
}

// FetchTorCheck fetches https://check.torproject.org/ and returns the response
// along with whether the connection is confirmed to be over Tor.
func (c *Client) FetchTorCheck() (body string, isTor bool, err error) {
	body, err = c.HTTPGet("https://check.torproject.org/")
	if err != nil {
		return "", false, err
	}

	isTor = strings.Contains(body, "Congratulations") ||
		strings.Contains(body, "configured to use Tor") ||
		strings.Contains(body, "using Tor")

	return body, isTor, nil
}
