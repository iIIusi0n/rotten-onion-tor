package directory

import (
	"crypto/rand"
	"errors"
	"math/big"
)

// SelectCircuitPath selects 3 routers for a Tor circuit: guard, middle, exit.
// The selection uses bandwidth-weighted random selection and avoids
// choosing the same router twice.
func SelectCircuitPath(consensus *Consensus) (guard, middle, exit *Router, err error) {
	var guards, middles, exits []*Router

	for _, r := range consensus.Routers {
		if !r.IsRunning() || !r.IsValid() {
			continue
		}
		if r.Bandwidth <= 0 {
			continue
		}
		if r.IsGuard() && r.IsFast() && r.IsStable() {
			guards = append(guards, r)
		}
		if r.IsFast() {
			middles = append(middles, r)
		}
		if r.IsExit() && r.IsFast() {
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

	// Select exit first (most constrained).
	exit, err = weightedRandomSelect(exits)
	if err != nil {
		return nil, nil, nil, err
	}

	// Select guard (excluding exit).
	guard, err = weightedRandomSelectExcluding(guards, exit)
	if err != nil {
		return nil, nil, nil, err
	}

	// Select middle (excluding guard and exit).
	middle, err = weightedRandomSelectExcluding2(middles, guard, exit)
	if err != nil {
		return nil, nil, nil, err
	}

	return guard, middle, exit, nil
}

func weightedRandomSelect(routers []*Router) (*Router, error) {
	totalBW := 0
	for _, r := range routers {
		totalBW += r.Bandwidth
	}
	if totalBW == 0 {
		// Uniform random selection if no bandwidth info.
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

func weightedRandomSelectExcluding(routers []*Router, exclude *Router) (*Router, error) {
	filtered := make([]*Router, 0, len(routers))
	for _, r := range routers {
		if r.Identity != exclude.Identity {
			filtered = append(filtered, r)
		}
	}
	if len(filtered) == 0 {
		return nil, errors.New("no routers available after exclusion")
	}
	return weightedRandomSelect(filtered)
}

func weightedRandomSelectExcluding2(routers []*Router, ex1, ex2 *Router) (*Router, error) {
	filtered := make([]*Router, 0, len(routers))
	for _, r := range routers {
		if r.Identity != ex1.Identity && r.Identity != ex2.Identity {
			filtered = append(filtered, r)
		}
	}
	if len(filtered) == 0 {
		return nil, errors.New("no routers available after exclusion")
	}
	return weightedRandomSelect(filtered)
}

func cryptoRandInt(max int) (int, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0, err
	}
	return int(n.Int64()), nil
}
