// Package cluster is the Go side of Postgres-backed membership, leader leases and shuffle
// sharding. Behavior must match crates/wt-cluster (shard vectors are shared).
package cluster

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
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

// Node is a shard candidate with its zone ("" = no zone).
type Node struct{ ID, Zone string }

func score(project [16]byte, node string) uint64 {
	h := sha256.New()
	h.Write(project[:])
	h.Write([]byte(node))
	return binary.BigEndian.Uint64(h.Sum(nil)[:8])
}

// SubsetZoned is the zone-aware subset (Cortex zone-aware shuffle sharding): nodes ranked by
// score within their zone, taken round robin over the zones in name order. Without zones it
// equals Subset. Mirrors wt_cluster::subset_zoned.
func SubsetZoned(project [16]byte, nodes []Node, k int) []string {
	byZone := map[string][]string{}
	for _, n := range nodes {
		byZone[n.Zone] = append(byZone[n.Zone], n.ID)
	}
	zones := make([]string, 0, len(byZone))
	for z := range byZone {
		zones = append(zones, z)
	}
	sort.Strings(zones)
	lanes := make([][]string, len(zones))
	for i, z := range zones {
		ids := byZone[z]
		sort.Slice(ids, func(a, b int) bool {
			sa, sb := score(project, ids[a]), score(project, ids[b])
			if sa != sb {
				return sa > sb
			}
			return ids[a] < ids[b]
		})
		lanes[i] = ids
	}
	var out []string
	for r := 0; len(out) < k; r++ {
		before := len(out)
		for _, l := range lanes {
			if len(out) == k {
				break
			}
			if r < len(l) {
				out = append(out, l[r])
			}
		}
		if len(out) == before {
			break
		}
	}
	return out
}

// Plan is the shuffle-shard placement of tenants on a Kafka topic (PLT-016): a project's
// records go only to the partitions of its shard, and partition p is consumed by worker replica
// p % Workers, so one noisy project reaches at most Size workers. Mirrors wt_cluster::ShardPlan.
type Plan struct {
	Size      int              // default shard size; 0 = off
	Overrides map[[16]byte]int // per-project shard size
	Workers   int              // consumer replicas; 0 shards over the partitions themselves
	Zones     []string         // zone of node i (worker replica i, or the i-th partition)
}

// ParseProject reads a hyphenated or plain hex uuid.
func ParseProject(s string) ([16]byte, bool) {
	var p [16]byte
	b, err := hex.DecodeString(strings.ReplaceAll(strings.TrimSpace(s), "-", ""))
	if err != nil || len(b) != 16 {
		return p, false
	}
	copy(p[:], b)
	return p, true
}

// ParsePlan builds a plan from config values: overrides "uuid:size,...", zones "a,b,...".
// Bad override entries are skipped.
func ParsePlan(size int, overrides string, workers int, zones string) Plan {
	pl := Plan{Size: size, Workers: workers, Overrides: map[[16]byte]int{}}
	for _, e := range strings.Split(overrides, ",") {
		i := strings.LastIndex(e, ":")
		if i < 0 {
			continue
		}
		p, ok := ParseProject(e[:i])
		n, err := strconv.Atoi(strings.TrimSpace(e[i+1:]))
		if ok && err == nil {
			pl.Overrides[p] = n
		}
	}
	for _, z := range strings.Split(zones, ",") {
		if z = strings.TrimSpace(z); z != "" {
			pl.Zones = append(pl.Zones, z)
		}
	}
	return pl
}

// SizeFor is the shard size of project.
func (pl Plan) SizeFor(project [16]byte) int {
	if n, ok := pl.Overrides[project]; ok {
		return n
	}
	return pl.Size
}

func (pl Plan) zone(i int) string {
	if i < len(pl.Zones) {
		return pl.Zones[i]
	}
	return ""
}

// Partitions returns the partitions 0..n-1 the project may use, ascending (all when off).
func (pl Plan) Partitions(project [16]byte, n int) []int {
	all := make([]int, n)
	for i := range all {
		all[i] = i
	}
	k := pl.SizeFor(project)
	if k == 0 || n == 0 {
		return all
	}
	var nodes []Node
	if pl.Workers > 0 {
		for i := 0; i < pl.Workers; i++ {
			nodes = append(nodes, Node{strconv.Itoa(i), pl.zone(i)})
		}
	} else {
		for i := range all {
			nodes = append(nodes, Node{strconv.Itoa(i), pl.zone(i)})
		}
	}
	shard := map[string]bool{}
	for _, id := range SubsetZoned(project, nodes, k) {
		shard[id] = true
	}
	var mine []int
	for _, p := range all {
		node := p
		if pl.Workers > 0 {
			node = p % pl.Workers
		}
		if shard[strconv.Itoa(node)] {
			mine = append(mine, p)
		}
	}
	if len(mine) == 0 {
		return all
	}
	return mine
}

// Pick returns the partition for one record of project, or -1 when sharding is off for it.
// Equal keys (one trace) always share a partition.
func (pl Plan) Pick(project [16]byte, n int, key []byte) int {
	if pl.SizeFor(project) == 0 || n == 0 {
		return -1
	}
	c := pl.Partitions(project, n)
	h := sha256.Sum256(key)
	return c[binary.BigEndian.Uint64(h[:8])%uint64(len(c))]
}
