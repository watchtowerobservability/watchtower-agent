// Package cluster is the Go side of Postgres-backed membership, leader leases and shuffle
// sharding. Behavior must match crates/wt-cluster (shard vectors are shared).
package cluster

import (
	"crypto/sha256"
	"encoding/binary"
	"sort"
)

// Subset returns the k highest-scoring nodes for the project (16 uuid bytes), best first.
// Score is the first 8 bytes (big endian) of sha256(project || node); ties break by node id.
func Subset(project [16]byte, nodes []string, k int) []string {
	type scored struct {
		s uint64
		n string
	}
	all := make([]scored, 0, len(nodes))
	for _, n := range nodes {
		h := sha256.New()
		h.Write(project[:])
		h.Write([]byte(n))
		all = append(all, scored{binary.BigEndian.Uint64(h.Sum(nil)[:8]), n})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].s != all[j].s {
			return all[i].s > all[j].s
		}
		return all[i].n < all[j].n
	})
	if k > len(all) {
		k = len(all)
	}
	out := make([]string, k)
	for i := range out {
		out[i] = all[i].n
	}
	return out
}
