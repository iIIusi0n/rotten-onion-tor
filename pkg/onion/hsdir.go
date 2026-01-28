package onion

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"

	torcrypto "rotten-onion-tor/pkg/crypto"
	"rotten-onion-tor/pkg/directory"
)

// HSDirSpreadFetch is the number of HSDirs to query per replica.
const HSDirSpreadFetch = 3

// HSDirNReplicas is the number of replicas for HS descriptors.
const HSDirNReplicas = 2

// ComputeHSServiceIndex computes the index where a descriptor is stored.
// Per rend-spec-v3:
//
//	hs_index(replicanum) = SHA3_256("store-at-idx" || blinded_public_key ||
//	    INT_8(replicanum) || INT_8(period_length) || INT_8(period_num))
func ComputeHSServiceIndex(blindedKey []byte, replicaNum int, periodLength, periodNum uint64) []byte {
	h := make([]byte, 0, 128)
	h = append(h, []byte("store-at-idx")...)
	h = append(h, blindedKey...)

	replicaBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(replicaBuf, uint64(replicaNum))
	h = append(h, replicaBuf...)

	periodLenBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(periodLenBuf, periodLength)
	h = append(h, periodLenBuf...)

	periodNumBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(periodNumBuf, periodNum)
	h = append(h, periodNumBuf...)

	return torcrypto.SHA3_256(h)
}

// ComputeHSRelayIndex computes the index for a relay in the HSDir ring.
// Per rend-spec-v3:
//
//	hsdir_index(node) = SHA3_256("node-idx" || node_identity ||
//	    shared_random_value || INT_8(period_num) || INT_8(period_length))
func ComputeHSRelayIndex(ed25519Identity, srv []byte, periodNum, periodLength uint64) []byte {
	h := make([]byte, 0, 128)
	h = append(h, []byte("node-idx")...)
	h = append(h, ed25519Identity...)
	h = append(h, srv...)

	periodNumBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(periodNumBuf, periodNum)
	h = append(h, periodNumBuf...)

	periodLenBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(periodLenBuf, periodLength)
	h = append(h, periodLenBuf...)

	return torcrypto.SHA3_256(h)
}

type indexedRelay struct {
	index  []byte
	router *directory.Router
}

// SelectHSDirs selects the HSDirs responsible for storing a given descriptor.
// Returns up to HSDirSpreadFetch * HSDirNReplicas relays.
func SelectHSDirs(consensus *directory.Consensus, blindedKey, srv []byte, periodNum, periodLength uint64) []*directory.Router {
	// Filter HSDirs with ed25519 identity and HSDir flag.
	var hsdirs []indexedRelay
	for _, r := range consensus.Routers {
		if !r.HasFlag("HSDir") || !r.IsRunning() || !r.IsValid() {
			continue
		}
		if len(r.Ed25519Identity) != 32 {
			continue
		}
		idx := ComputeHSRelayIndex(r.Ed25519Identity, srv, periodNum, periodLength)
		hsdirs = append(hsdirs, indexedRelay{index: idx, router: r})
	}

	if len(hsdirs) == 0 {
		return nil
	}

	// Sort by index.
	sort.Slice(hsdirs, func(i, j int) bool {
		return bytes.Compare(hsdirs[i].index, hsdirs[j].index) < 0
	})

	// For each replica, compute service index and find the next HSDirSpreadFetch relays.
	seen := make(map[string]bool)
	var result []*directory.Router

	for replica := 0; replica < HSDirNReplicas; replica++ {
		serviceIdx := ComputeHSServiceIndex(blindedKey, replica+1, periodLength, periodNum)

		// Find the first relay with index >= serviceIdx using binary search.
		startPos := sort.Search(len(hsdirs), func(i int) bool {
			return bytes.Compare(hsdirs[i].index, serviceIdx) >= 0
		})

		// Pick the next HSDirSpreadFetch relays (wrapping around).
		count := 0
		for i := 0; count < HSDirSpreadFetch && i < len(hsdirs); i++ {
			pos := (startPos + i) % len(hsdirs)
			identity := fmt.Sprintf("%x", hsdirs[pos].router.Ed25519Identity)
			if seen[identity] {
				continue
			}
			seen[identity] = true
			result = append(result, hsdirs[pos].router)
			count++
		}
	}

	return result
}
