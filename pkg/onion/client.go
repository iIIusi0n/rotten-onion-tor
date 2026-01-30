package onion

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"log"
	"strings"
	"time"

	"rotten-onion-tor/pkg/cell"
	"rotten-onion-tor/pkg/channel"
	"rotten-onion-tor/pkg/circuit"
	torcrypto "rotten-onion-tor/pkg/crypto"
	"rotten-onion-tor/pkg/directory"
	"rotten-onion-tor/pkg/stream"
)

// ConnectOnion connects to a v3 onion service and returns a circuit and stream manager
// ready for opening streams.
func ConnectOnion(consensus *directory.Consensus, onionAddr string, logger *log.Logger) (*circuit.Circuit, *stream.Manager, error) {
	// Step 1: Parse .onion address.
	oa, err := ParseOnionAddress(onionAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("parse onion address: %w", err)
	}
	logger.Printf("[HS] Parsed .onion address, version %d", oa.Version)

	// Step 2: Compute blinded key for current time period.
	periodLength := uint64(TimePeriodLength)
	periodNum := ComputeTimePeriod(consensus.ValidAfter, periodLength)
	logger.Printf("[HS] Time period: %d (period length: %d)", periodNum, periodLength)

	blindedKey, err := ComputeBlindedKey(oa.PublicKey[:], periodNum, periodLength)
	if err != nil {
		return nil, nil, fmt.Errorf("compute blinded key: %w", err)
	}
	logger.Printf("[HS] Blinded key computed")

	// Step 3: Compute subcredential.
	subcredential := ComputeSubcredential(oa.PublicKey[:], blindedKey)

	// Step 4: Select SRV from consensus.
	srv := selectSRV(consensus)
	if srv == nil {
		return nil, nil, fmt.Errorf("no shared random value in consensus")
	}
	logger.Printf("[HS] Using SRV from consensus")

	// Step 4.5: Fetch microdescriptors for HSDir routers to get their Ed25519 identities.
	logger.Printf("[HS] Fetching HSDir microdescriptors for Ed25519 identities...")
	if err := directory.FetchHSDirMicrodescriptors(consensus); err != nil {
		logger.Printf("[HS] Warning: %v", err)
	}

	// Step 5: Locate HSDirs.
	hsdirs := SelectHSDirs(consensus, blindedKey, srv, periodNum, periodLength)
	if len(hsdirs) == 0 {
		return nil, nil, fmt.Errorf("no HSDirs found")
	}
	logger.Printf("[HS] Found %d HSDirs", len(hsdirs))

	// Step 6: Fetch descriptor from an HSDir.
	var descriptorBody string
	var fetchErr error
	for i, hsdir := range hsdirs {
		logger.Printf("[HS] Trying HSDir %d: %s (%s:%d)", i+1, hsdir.Nickname, hsdir.Address, hsdir.ORPort)
		descriptorBody, fetchErr = fetchDescriptorViaCircuit(consensus, hsdir, blindedKey, logger)
		if fetchErr == nil && len(descriptorBody) > 0 {
			break
		}
		logger.Printf("[HS] HSDir %s failed: %v", hsdir.Nickname, fetchErr)
	}
	if fetchErr != nil || len(descriptorBody) == 0 {
		return nil, nil, fmt.Errorf("fetch descriptor: %w", fetchErr)
	}
	logger.Printf("[HS] Descriptor fetched (%d bytes)", len(descriptorBody))

	// Step 7: Decrypt descriptor (2 layers) -> intro points.
	desc, err := ParseHSDescriptorOuter(descriptorBody)
	if err != nil {
		return nil, nil, fmt.Errorf("parse descriptor: %w", err)
	}
	logger.Printf("[HS] Revision counter: %d", desc.RevisionCounter)

	// Decrypt layer 1 (superencrypted).
	firstLayer, err := DecryptSuperencrypted(desc.Superencrypted, blindedKey, subcredential, desc.RevisionCounter)
	if err != nil {
		return nil, nil, fmt.Errorf("decrypt superencrypted layer: %w", err)
	}
	logger.Printf("[HS] First layer decrypted (%d bytes)", len(firstLayer))

	// Extract encrypted blob from first layer.
	encryptedBlob, err := ParseFirstLayerPlaintext(firstLayer)
	if err != nil {
		return nil, nil, fmt.Errorf("parse first layer: %w", err)
	}

	// Decrypt layer 2 (encrypted).
	secondLayer, err := DecryptEncrypted(encryptedBlob, blindedKey, subcredential, desc.RevisionCounter)
	if err != nil {
		return nil, nil, fmt.Errorf("decrypt encrypted layer: %w", err)
	}
	logger.Printf("[HS] Second layer decrypted (%d bytes)", len(secondLayer))

	// Parse intro points.
	introPoints, err := ParseIntroPoints(secondLayer)
	if err != nil {
		return nil, nil, fmt.Errorf("parse intro points: %w", err)
	}
	if len(introPoints) == 0 {
		return nil, nil, fmt.Errorf("no introduction points found")
	}
	logger.Printf("[HS] Found %d introduction points", len(introPoints))

	// Step 8: Build rendezvous circuit (3-hop to a random relay).
	logger.Printf("[HS] Building rendezvous circuit...")
	rendCirc, rendRouter, err := buildRendezvousCircuit(consensus, logger)
	if err != nil {
		return nil, nil, fmt.Errorf("build rendezvous circuit: %w", err)
	}

	// Step 9: Send ESTABLISH_RENDEZVOUS with 20-byte random cookie.
	var rendCookie [20]byte
	if _, err := rand.Read(rendCookie[:]); err != nil {
		rendCirc.Destroy()
		return nil, nil, fmt.Errorf("generate rendezvous cookie: %w", err)
	}
	logger.Printf("[HS] Sending ESTABLISH_RENDEZVOUS...")
	if err := rendCirc.SendRelayCell(cell.RelayEstablishRendezvous, 0, rendCookie[:], false); err != nil {
		rendCirc.Destroy()
		return nil, nil, fmt.Errorf("send ESTABLISH_RENDEZVOUS: %w", err)
	}

	// Step 10: Wait for RENDEZVOUS_ESTABLISHED.
	rc, err := rendCirc.RecvRelayCell()
	if err != nil {
		rendCirc.Destroy()
		return nil, nil, fmt.Errorf("recv RENDEZVOUS_ESTABLISHED: %w", err)
	}
	if rc.Command != cell.RelayRendezvousEstablished {
		rendCirc.Destroy()
		return nil, nil, fmt.Errorf("expected RENDEZVOUS_ESTABLISHED, got %d", rc.Command)
	}
	logger.Printf("[HS] Rendezvous point established")

	// Step 11-14: Try each intro point.
	var hsResult *HSNtorHandshakeResult
	var hsState *HSNtorClientState

	for i, ip := range introPoints {
		logger.Printf("[HS] Trying introduction point %d...", i+1)

		hsState, hsResult, err = doIntroduction(consensus, ip, rendRouter, rendCookie[:], rendCirc, subcredential, logger)
		if err != nil {
			logger.Printf("[HS] Intro point %d failed: %v", i+1, err)
			continue
		}
		break
	}
	if hsResult == nil {
		rendCirc.Destroy()
		return nil, nil, fmt.Errorf("all introduction points failed: %w", err)
	}

	// Step 15: Wait for RENDEZVOUS2 on rendezvous circuit.
	logger.Printf("[HS] Waiting for RENDEZVOUS2...")
	rc, err = rendCirc.RecvRelayCell()
	if err != nil {
		rendCirc.Destroy()
		return nil, nil, fmt.Errorf("recv RENDEZVOUS2: %w", err)
	}
	if rc.Command != cell.RelayRendezvous2 {
		rendCirc.Destroy()
		return nil, nil, fmt.Errorf("expected RENDEZVOUS2, got %d", rc.Command)
	}
	logger.Printf("[HS] Received RENDEZVOUS2 (%d bytes)", len(rc.Data))

	// Step 16: Complete hs-ntor handshake.
	result, err := hsState.CompleteRendezvous(rc.Data)
	if err != nil {
		rendCirc.Destroy()
		return nil, nil, fmt.Errorf("complete hs-ntor: %w", err)
	}
	logger.Printf("[HS] HS-ntor handshake completed")

	// Step 17: Derive HS circuit keys and add virtual hop.
	hsKeys := DeriveHSCircuitKeys(result.NtorKeySeed)
	err = rendCirc.AddHSHop(&circuit.HSCircuitKeys{
		ForwardDigest:  hsKeys.ForwardDigest,
		BackwardDigest: hsKeys.BackwardDigest,
		ForwardKey:     hsKeys.ForwardKey,
		BackwardKey:    hsKeys.BackwardKey,
	})
	if err != nil {
		rendCirc.Destroy()
		return nil, nil, fmt.Errorf("add HS hop: %w", err)
	}
	logger.Printf("[HS] Virtual HS hop added to circuit")

	// Step 18: Create stream manager and return.
	mgr := stream.NewManager(rendCirc)
	return rendCirc, mgr, nil
}

// selectSRV picks the shared random value from the consensus based on the time
// of day. Per rend-spec-v3 section 2.2.1:
//   - If valid_after is between 00:00 and 12:00 UTC: use previous SRV
//   - If valid_after is between 12:00 and 00:00 UTC: use current SRV
func selectSRV(consensus *directory.Consensus) []byte {
	hour := consensus.ValidAfter.Hour()
	if hour < 12 {
		// Use previous SRV.
		if len(consensus.SharedRandPrevious) == 32 {
			return consensus.SharedRandPrevious
		}
	}
	// Use current SRV.
	if len(consensus.SharedRandCurrent) == 32 {
		return consensus.SharedRandCurrent
	}
	// Fallback.
	if len(consensus.SharedRandPrevious) == 32 {
		return consensus.SharedRandPrevious
	}
	return nil
}

// buildRendezvousCircuit builds a 3-hop circuit for rendezvous.
func buildRendezvousCircuit(consensus *directory.Consensus, logger *log.Logger) (*circuit.Circuit, *directory.Router, error) {
	guard, middle, exit, err := directory.SelectCircuitPath(consensus)
	if err != nil {
		return nil, nil, fmt.Errorf("select path: %w", err)
	}

	// The "exit" here is actually our rendezvous point (doesn't need Exit flag).
	// For simplicity, we reuse SelectCircuitPath but the last hop just needs
	// to be a running, valid relay. In practice any relay can serve as RP.
	rendPoint := exit

	logger.Printf("[HS] RP path: %s -> %s -> %s",
		guard.Nickname, middle.Nickname, rendPoint.Nickname)

	// Fetch descriptors for ntor keys.
	auth := directory.DefaultAuthorities[0]
	for _, router := range []*directory.Router{guard, middle, rendPoint} {
		if router.NtorOnionKey == nil {
			if err := directory.FetchMicrodescriptors(auth, []*directory.Router{router}); err != nil {
				for _, a := range directory.DefaultAuthorities[1:] {
					if err2 := directory.FetchMicrodescriptors(a, []*directory.Router{router}); err2 == nil {
						break
					}
				}
			}
		}
	}

	// Connect and build circuit.
	addr := fmt.Sprintf("%s:%d", guard.Address, guard.ORPort)
	ch, err := channel.Dial(addr, 30*time.Second)
	if err != nil {
		return nil, nil, fmt.Errorf("connect to guard: %w", err)
	}

	circ, err := circuit.New(ch)
	if err != nil {
		ch.Close()
		return nil, nil, fmt.Errorf("create circuit: %w", err)
	}

	if err := circ.Create(guard); err != nil {
		ch.Close()
		return nil, nil, fmt.Errorf("CREATE to guard: %w", err)
	}

	if err := circ.Extend(middle); err != nil {
		circ.Destroy()
		ch.Close()
		return nil, nil, fmt.Errorf("EXTEND to middle: %w", err)
	}

	if err := circ.Extend(rendPoint); err != nil {
		circ.Destroy()
		ch.Close()
		return nil, nil, fmt.Errorf("EXTEND to rend point: %w", err)
	}

	logger.Printf("[HS] Rendezvous circuit built (3 hops)")
	return circ, rendPoint, nil
}

// doIntroduction builds an intro circuit, sends INTRODUCE1, and waits for ACK.
func doIntroduction(
	consensus *directory.Consensus,
	ip *IntroPoint,
	rendRouter *directory.Router,
	rendCookie []byte,
	rendCirc *circuit.Circuit,
	subcredential []byte,
	logger *log.Logger,
) (*HSNtorClientState, *HSNtorHandshakeResult, error) {
	// Build a 3-hop intro circuit where the last hop is the intro point.
	introCirc, err := buildIntroCircuit(consensus, ip, logger)
	if err != nil {
		return nil, nil, fmt.Errorf("build intro circuit: %w", err)
	}
	defer introCirc.Destroy()

	// Create hs-ntor state.
	hsState, err := NewHSNtorClient(ip.EncKey, ip.AuthKey, subcredential)
	if err != nil {
		return nil, nil, fmt.Errorf("create hs-ntor state: %w", err)
	}

	// Build INTRODUCE1 encrypted inner plaintext.
	// Plaintext: RENDEZVOUS_COOKIE(20) || N_EXTENSIONS(1) || ONION_KEY_TYPE(1) ||
	//   ONION_KEY_LEN(2) || ONION_KEY(32) || NSPEC(1) || link_specifiers || PAD
	rendNtorKey := rendRouter.NtorOnionKey
	rendLinkSpecs := buildRendLinkSpecs(rendRouter)

	innerPlaintext := make([]byte, 0, 256)
	innerPlaintext = append(innerPlaintext, rendCookie...) // 20 bytes
	innerPlaintext = append(innerPlaintext, 0x00)          // N_EXTENSIONS = 0
	innerPlaintext = append(innerPlaintext, 0x01)          // ONION_KEY_TYPE = ntor
	onionKeyLen := make([]byte, 2)
	binary.BigEndian.PutUint16(onionKeyLen, uint16(len(rendNtorKey)))
	innerPlaintext = append(innerPlaintext, onionKeyLen...)   // ONION_KEY_LEN
	innerPlaintext = append(innerPlaintext, rendNtorKey...)   // ONION_KEY
	innerPlaintext = append(innerPlaintext, rendLinkSpecs...) // NSPEC + link specifiers

	// Pad to at least 246 bytes of inner data per spec.
	// The minimum INTRODUCE1 cell must be padded.
	for len(innerPlaintext) < 246 {
		innerPlaintext = append(innerPlaintext, 0x00)
	}

	// Encrypt with hs-ntor.
	clientPK, encrypted, macKey, err := hsState.CreateIntroduce1Payload(innerPlaintext)
	if err != nil {
		return nil, nil, fmt.Errorf("create INTRODUCE1 payload: %w", err)
	}

	// Build the full INTRODUCE1 cell body.
	// Header: LEGACY_KEY_ID(20) || AUTH_KEY_TYPE(1) || AUTH_KEY_LEN(2) || AUTH_KEY(32) || N_EXTENSIONS(1)
	intro1Body := make([]byte, 0, 512)
	intro1Body = append(intro1Body, make([]byte, 20)...) // LEGACY_KEY_ID = zeros
	intro1Body = append(intro1Body, 0x02)                // AUTH_KEY_TYPE = ed25519
	authKeyLen := make([]byte, 2)
	binary.BigEndian.PutUint16(authKeyLen, uint16(len(ip.AuthKey)))
	intro1Body = append(intro1Body, authKeyLen...) // AUTH_KEY_LEN
	intro1Body = append(intro1Body, ip.AuthKey...) // AUTH_KEY
	intro1Body = append(intro1Body, 0x00)          // N_EXTENSIONS = 0

	// Encrypted part: CLIENT_PK(32) || ENCRYPTED_DATA || MAC(32)
	// First, build the part that gets MACed.
	encryptedPart := make([]byte, 0, 32+len(encrypted))
	encryptedPart = append(encryptedPart, clientPK...) // CLIENT_PK = X
	encryptedPart = append(encryptedPart, encrypted...)

	// MAC covers: intro1Body (from AUTH_KEY_TYPE onwards... actually the full cell from beginning)
	// Per spec: MAC = MAC(MAC_KEY, msg) where msg is everything in the cell up to MAC.
	macMsg := make([]byte, 0, len(intro1Body)+len(encryptedPart))
	macMsg = append(macMsg, intro1Body...)
	macMsg = append(macMsg, encryptedPart...)
	mac := torcrypto.HSMAC(macKey, macMsg)

	// Assemble full body.
	intro1Body = append(intro1Body, encryptedPart...)
	intro1Body = append(intro1Body, mac...)

	// Send INTRODUCE1.
	logger.Printf("[HS] Sending INTRODUCE1 (%d bytes)", len(intro1Body))
	if err := introCirc.SendRelayCell(cell.RelayIntroduce1, 0, intro1Body, false); err != nil {
		return nil, nil, fmt.Errorf("send INTRODUCE1: %w", err)
	}

	// Wait for INTRODUCE_ACK.
	rc, err := introCirc.RecvRelayCell()
	if err != nil {
		return nil, nil, fmt.Errorf("recv INTRODUCE_ACK: %w", err)
	}
	if rc.Command != cell.RelayIntroduceAck {
		return nil, nil, fmt.Errorf("expected INTRODUCE_ACK, got %d", rc.Command)
	}

	// Check ACK status (first 2 bytes, 0x0000 = success).
	if len(rc.Data) >= 2 {
		status := binary.BigEndian.Uint16(rc.Data[0:2])
		if status != 0 {
			return nil, nil, fmt.Errorf("INTRODUCE_ACK status: %d", status)
		}
	}
	logger.Printf("[HS] Introduction acknowledged (success)")

	return hsState, &HSNtorHandshakeResult{}, nil
}

// buildIntroCircuit builds a circuit to an introduction point.
// The intro point is the last hop; we build 2 hops before it.
func buildIntroCircuit(consensus *directory.Consensus, ip *IntroPoint, logger *log.Logger) (*circuit.Circuit, error) {
	// Select guard and middle.
	guard, middle, _, err := directory.SelectCircuitPath(consensus)
	if err != nil {
		return nil, fmt.Errorf("select path: %w", err)
	}

	// Fetch descriptors.
	auth := directory.DefaultAuthorities[0]
	for _, router := range []*directory.Router{guard, middle} {
		if router.NtorOnionKey == nil {
			if err := directory.FetchMicrodescriptors(auth, []*directory.Router{router}); err != nil {
				for _, a := range directory.DefaultAuthorities[1:] {
					if err2 := directory.FetchMicrodescriptors(a, []*directory.Router{router}); err2 == nil {
						break
					}
				}
			}
		}
	}

	addr := fmt.Sprintf("%s:%d", guard.Address, guard.ORPort)
	ch, err := channel.Dial(addr, 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connect to guard: %w", err)
	}

	circ, err := circuit.New(ch)
	if err != nil {
		ch.Close()
		return nil, fmt.Errorf("create circuit: %w", err)
	}

	if err := circ.Create(guard); err != nil {
		ch.Close()
		return nil, fmt.Errorf("CREATE to guard: %w", err)
	}

	if err := circ.Extend(middle); err != nil {
		circ.Destroy()
		ch.Close()
		return nil, fmt.Errorf("EXTEND to middle: %w", err)
	}

	// Extend to intro point using raw link specifiers.
	// We need to find the intro point's NodeID from link specifiers.
	nodeID := extractNodeID(ip.LinkSpecifiers)
	linkSpecBuf := EncodeLinkSpecifiers(ip.LinkSpecifiers)

	logger.Printf("[HS] Extending to intro point via link specifiers")
	if err := circ.ExtendRaw(linkSpecBuf, ip.OnionKey, nodeID); err != nil {
		circ.Destroy()
		ch.Close()
		return nil, fmt.Errorf("EXTEND to intro point: %w", err)
	}

	logger.Printf("[HS] Intro circuit built (3 hops)")
	return circ, nil
}

// extractNodeID extracts the legacy identity (type 0x02) from link specifiers.
func extractNodeID(specs []LinkSpecifier) torcrypto.NodeID {
	var id torcrypto.NodeID
	for _, s := range specs {
		if s.Type == 0x02 && len(s.Data) == 20 {
			copy(id[:], s.Data)
			return id
		}
	}
	return id
}

// buildRendLinkSpecs builds link specifiers for the rendezvous point.
func buildRendLinkSpecs(router *directory.Router) []byte {
	// Build link specifiers: IPv4 (type 0) + legacy identity (type 2).
	ip := parseIPv4(router.Address)

	specs := make([]byte, 0, 64)
	specs = append(specs, 2) // NSPEC = 2

	// IPv4 spec.
	specs = append(specs, 0x00, 6)
	specs = append(specs, ip...)
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, router.ORPort)
	specs = append(specs, portBuf...)

	// Legacy identity spec.
	identityHash := decodeIdentityHash(router.Identity)
	specs = append(specs, 0x02, 20)
	specs = append(specs, identityHash...)

	return specs
}

func parseIPv4(addr string) []byte {
	ip := make([]byte, 4)
	var a, b, c, d int
	fmt.Sscanf(addr, "%d.%d.%d.%d", &a, &b, &c, &d)
	ip[0] = byte(a)
	ip[1] = byte(b)
	ip[2] = byte(c)
	ip[3] = byte(d)
	return ip
}

func decodeIdentityHash(identity string) []byte {
	padded := identity
	for len(padded)%4 != 0 {
		padded += "="
	}
	decoded, err := base64.StdEncoding.DecodeString(padded)
	if err != nil {
		return make([]byte, 20)
	}
	return decoded
}

// fetchDescriptorViaCircuit builds a 3-hop circuit to an HSDir and fetches
// the descriptor using BEGIN_DIR. Tor relays reject single-hop HS v3 descriptor
// requests, so we must use a multi-hop circuit.
func fetchDescriptorViaCircuit(consensus *directory.Consensus, hsdir *directory.Router, blindedKey []byte, logger *log.Logger) (string, error) {
	// Fetch ntor key for the HSDir if needed.
	if hsdir.NtorOnionKey == nil {
		for _, auth := range directory.DefaultAuthorities {
			if err := directory.FetchMicrodescriptors(auth, []*directory.Router{hsdir}); err == nil && hsdir.NtorOnionKey != nil {
				break
			}
		}
		if hsdir.NtorOnionKey == nil {
			return "", fmt.Errorf("could not fetch ntor key for %s", hsdir.Nickname)
		}
	}

	// Select guard and middle relays.
	guard, middle, _, err := directory.SelectCircuitPath(consensus)
	if err != nil {
		return "", fmt.Errorf("select path: %w", err)
	}

	// Fetch ntor keys for guard and middle.
	for _, r := range []*directory.Router{guard, middle} {
		if r.NtorOnionKey == nil {
			for _, auth := range directory.DefaultAuthorities {
				if err := directory.FetchMicrodescriptors(auth, []*directory.Router{r}); err == nil && r.NtorOnionKey != nil {
					break
				}
			}
		}
	}

	// Build 3-hop circuit: guard -> middle -> HSDir.
	addr := fmt.Sprintf("%s:%d", guard.Address, guard.ORPort)
	ch, err := channel.Dial(addr, 30*time.Second)
	if err != nil {
		return "", fmt.Errorf("connect to guard: %w", err)
	}

	circ, err := circuit.New(ch)
	if err != nil {
		ch.Close()
		return "", fmt.Errorf("create circuit: %w", err)
	}
	defer circ.Destroy()
	defer ch.Close()

	if err := circ.Create(guard); err != nil {
		return "", fmt.Errorf("CREATE to guard: %w", err)
	}
	if err := circ.Extend(middle); err != nil {
		return "", fmt.Errorf("EXTEND to middle: %w", err)
	}
	if err := circ.Extend(hsdir); err != nil {
		return "", fmt.Errorf("EXTEND to HSDir: %w", err)
	}

	// Send BEGIN_DIR.
	if err := circ.SendRelayCell(cell.RelayBeginDir, 1, nil, false); err != nil {
		return "", fmt.Errorf("send BEGIN_DIR: %w", err)
	}

	// Wait for CONNECTED.
	rc, err := circ.RecvRelayCell()
	if err != nil {
		return "", fmt.Errorf("recv CONNECTED: %w", err)
	}
	if rc.Command != cell.RelayConnected {
		return "", fmt.Errorf("expected CONNECTED, got %d", rc.Command)
	}

	// Send HTTP GET request for descriptor.
	blindedKeyB64 := base64.RawStdEncoding.EncodeToString(blindedKey)
	httpReq := fmt.Sprintf("GET /tor/hs/3/%s HTTP/1.0\r\nHost: %s\r\n\r\n", blindedKeyB64, hsdir.Address)

	if err := circ.SendRelayData(1, []byte(httpReq)); err != nil {
		return "", fmt.Errorf("send HTTP request: %w", err)
	}

	// Read response.
	var response strings.Builder
	for {
		rc, err := circ.RecvRelayCell()
		if err != nil {
			if response.Len() > 0 {
				break
			}
			return "", fmt.Errorf("recv response: %w", err)
		}
		switch rc.Command {
		case cell.RelayData:
			response.Write(rc.Data)
		case cell.RelayEnd:
			goto done
		default:
			// Skip SENDMEs etc.
		}
	}
done:

	fullResponse := response.String()
	logger.Printf("[HS] HSDir raw response (%d bytes)", len(fullResponse))
	if len(fullResponse) > 0 && len(fullResponse) < 200 {
		logger.Printf("[HS] Response: %q", fullResponse)
	} else if len(fullResponse) >= 200 {
		logger.Printf("[HS] Response first 200: %q", fullResponse[:200])
	}

	// Check for HTTP error.
	if len(fullResponse) > 0 {
		firstLine := fullResponse
		if idx := strings.Index(firstLine, "\r\n"); idx >= 0 {
			firstLine = firstLine[:idx]
		}
		if strings.Contains(firstLine, "404") || strings.Contains(firstLine, "400") || strings.Contains(firstLine, "503") {
			return "", fmt.Errorf("HTTP error: %s", firstLine)
		}
	}

	// Strip HTTP headers.
	body := fullResponse
	if idx := strings.Index(body, "\r\n\r\n"); idx >= 0 {
		body = body[idx+4:]
	}

	return body, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
