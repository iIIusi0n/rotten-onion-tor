package directory

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	guardStateFile   = "guards.json"
	guardStateMaxAge = 45 * 24 * time.Hour
)

type persistentGuardState struct {
	PrimaryIdentity string    `json:"primary_identity"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// SelectCircuitPath selects 3 routers for a Tor circuit: guard, middle, exit.
// Selection uses bandwidth-weighted random selection with:
// - persistent guards (to avoid rapid guard rotation),
// - family isolation when family data is available,
// - subnet diversity to reduce correlated operators.
func SelectCircuitPath(consensus *Consensus) (guard, middle, exit *Router, err error) {
	var guards, middles, exits []*Router

	for _, r := range consensus.Routers {
		if !r.IsRunning() || !r.IsValid() || r.Bandwidth <= 0 {
			continue
		}
		if r.IsGuard() && r.IsFast() && r.IsStable() {
			guards = append(guards, r)
		}
		if r.IsFast() {
			middles = append(middles, r)
		}
		if r.IsExit() && r.IsFast() && !r.HasFlag("BadExit") {
			exits = append(exits, r)
		}
	}

	if len(guards) == 0 {
		return nil, nil, nil, errors.New("no suitable guard relays found")
	}
	if len(middles) == 0 {
		return nil, nil, nil, errors.New("no suitable middle relays found")
	}
	if len(exits) == 0 {
		return nil, nil, nil, errors.New("no suitable exit relays found")
	}

	guard, err = selectPersistentGuard(guards)
	if err != nil {
		return nil, nil, nil, err
	}

	exitCandidates := filterRouters(exits, []*Router{guard}, true)
	if len(exitCandidates) == 0 {
		exitCandidates = filterRouters(exits, []*Router{guard}, false)
	}
	exit, err = weightedRandomSelect(exitCandidates)
	if err != nil {
		return nil, nil, nil, err
	}

	middleCandidates := filterRouters(middles, []*Router{guard, exit}, true)
	if len(middleCandidates) == 0 {
		middleCandidates = filterRouters(middles, []*Router{guard, exit}, false)
	}
	middle, err = weightedRandomSelect(middleCandidates)
	if err != nil {
		return nil, nil, nil, err
	}

	return guard, middle, exit, nil
}

func filterRouters(routers []*Router, avoid []*Router, strict bool) []*Router {
	out := make([]*Router, 0, len(routers))
	for _, r := range routers {
		ok := true
		for _, a := range avoid {
			if a == nil {
				continue
			}
			if r.Identity == a.Identity {
				ok = false
				break
			}
			if strict {
				if sameFamily(r, a) || sameSubnet(r, a) {
					ok = false
					break
				}
			}
		}
		if ok {
			out = append(out, r)
		}
	}
	return out
}

func selectPersistentGuard(guards []*Router) (*Router, error) {
	state, _ := loadPersistentGuardState()
	if state != nil && state.PrimaryIdentity != "" {
		for _, g := range guards {
			if g.Identity == state.PrimaryIdentity {
				if time.Since(state.UpdatedAt) <= guardStateMaxAge {
					return g, nil
				}
				break
			}
		}
	}

	guard, err := weightedRandomSelect(guards)
	if err != nil {
		return nil, err
	}
	_ = savePersistentGuardState(&persistentGuardState{
		PrimaryIdentity: guard.Identity,
		UpdatedAt:       time.Now().UTC(),
	})
	return guard, nil
}

func loadPersistentGuardState() (*persistentGuardState, error) {
	path := filepath.Join(CacheDir(), guardStateFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var state persistentGuardState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	return &state, nil
}

func savePersistentGuardState(state *persistentGuardState) error {
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	path := filepath.Join(CacheDir(), guardStateFile)
	return os.WriteFile(path, data, 0600)
}

func sameSubnet(a, b *Router) bool {
	ipA := net.ParseIP(a.Address)
	ipB := net.ParseIP(b.Address)
	if ipA == nil || ipB == nil {
		return false
	}
	if a4 := ipA.To4(); a4 != nil {
		b4 := ipB.To4()
		if b4 == nil {
			return false
		}
		return a4[0] == b4[0] && a4[1] == b4[1] // IPv4 /16
	}
	a16 := ipA.To16()
	b16 := ipB.To16()
	if a16 == nil || b16 == nil {
		return false
	}
	return a16[0] == b16[0] && a16[1] == b16[1] && a16[2] == b16[2] && a16[3] == b16[3] // IPv6 /32
}

func sameFamily(a, b *Router) bool {
	idA := identityHex(a.Identity)
	idB := identityHex(b.Identity)
	if idA == "" || idB == "" {
		return false
	}
	for _, fam := range a.Family {
		if fam == idB {
			return true
		}
	}
	for _, fam := range b.Family {
		if fam == idA {
			return true
		}
	}
	return false
}

func identityHex(identity string) string {
	decoded, err := base64.RawStdEncoding.DecodeString(identity)
	if err != nil {
		decoded, err = base64.StdEncoding.DecodeString(identity)
		if err != nil {
			return ""
		}
	}
	if len(decoded) != 20 {
		return ""
	}
	return strings.ToUpper(hex.EncodeToString(decoded))
}

func weightedRandomSelect(routers []*Router) (*Router, error) {
	if len(routers) == 0 {
		return nil, errors.New("no routers available for selection")
	}
	totalBW := 0
	for _, r := range routers {
		totalBW += r.Bandwidth
	}
	if totalBW <= 0 {
		idx, err := cryptoRandInt(len(routers))
		if err != nil {
			return nil, err
		}
		return routers[idx], nil
	}

	target, err := cryptoRandInt(totalBW)
	if err != nil {
		return nil, err
	}

	cumulative := 0
	for _, r := range routers {
		cumulative += r.Bandwidth
		if cumulative > target {
			return r, nil
		}
	}
	return routers[len(routers)-1], nil
}

func cryptoRandInt(max int) (int, error) {
	if max <= 0 {
		return 0, errors.New("max must be positive")
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0, err
	}
	return int(n.Int64()), nil
}
