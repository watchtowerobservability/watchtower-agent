package cluster

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestSubsetMatchesRust(t *testing.T) {
	raw, err := os.ReadFile("testdata/shard_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vecs []struct {
		Project string   `json:"project"`
		Nodes   []string `json:"nodes"`
		K       int      `json:"k"`
		Want    []string `json:"want"`
	}
	if err := json.Unmarshal(raw, &vecs); err != nil {
		t.Fatal(err)
	}
	if len(vecs) == 0 {
		t.Fatal("no vectors")
	}
	for _, v := range vecs {
		b, err := hex.DecodeString(strings.ReplaceAll(v.Project, "-", ""))
		if err != nil || len(b) != 16 {
			t.Fatalf("bad project %q", v.Project)
		}
		var p [16]byte
		copy(p[:], b)
		if got := Subset(p, v.Nodes, v.K); !reflect.DeepEqual(got, v.Want) {
			t.Fatalf("project %s: got %v want %v", v.Project, got, v.Want)
		}
	}
}

func TestPlanMatchesRust(t *testing.T) {
	raw, err := os.ReadFile("testdata/pick_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vecs []struct {
		Project    string   `json:"project"`
		Partitions int      `json:"partitions"`
		Size       int      `json:"size"`
		Workers    int      `json:"workers"`
		Zones      []string `json:"zones"`
		KeyHex     string   `json:"key_hex"`
		Shard      []int    `json:"shard"`
		Want       int      `json:"want"`
	}
	if err := json.Unmarshal(raw, &vecs); err != nil {
		t.Fatal(err)
	}
	if len(vecs) == 0 {
		t.Fatal("no vectors")
	}
	for _, v := range vecs {
		p, ok := ParseProject(v.Project)
		key, err := hex.DecodeString(v.KeyHex)
		if !ok || err != nil {
			t.Fatalf("bad vector %+v", v)
		}
		pl := ParsePlan(v.Size, "", v.Workers, strings.Join(v.Zones, ","))
		if got := pl.Partitions(p, v.Partitions); !reflect.DeepEqual(got, v.Shard) {
			t.Fatalf("%s size %d workers %d: shard %v want %v", v.Project, v.Size, v.Workers, got, v.Shard)
		}
		if got := pl.Pick(p, v.Partitions, key); got != v.Want {
			t.Fatalf("%s key %s: pick %d want %d", v.Project, v.KeyHex, got, v.Want)
		}
	}
}

func TestPlanOffAndOverrides(t *testing.T) {
	p, _ := ParseProject("9e3779b9-7f4a-7c15-f39c-c0605cedc835")
	if got := (Plan{}).Pick(p, 16, []byte{1}); got != -1 {
		t.Fatalf("off plan picked %d", got)
	}
	pl := ParsePlan(0, "9e3779b9-7f4a-7c15-f39c-c0605cedc835:1, junk", 0, "")
	if pl.SizeFor(p) != 1 {
		t.Fatalf("override not read: %+v", pl)
	}
	first := pl.Pick(p, 16, []byte{0})
	for k := 0; k < 256; k++ {
		if got := pl.Pick(p, 16, []byte{byte(k)}); got != first {
			t.Fatalf("size 1 shard used partitions %d and %d", first, got)
		}
	}
}

func TestSubsetZonedSpreadsZones(t *testing.T) {
	p, _ := ParseProject("3c6ef372-fe94-f82b-e739-80c0b9db906b")
	var nodes []Node
	for i := 0; i < 9; i++ {
		nodes = append(nodes, Node{"w" + string(rune('0'+i)), []string{"a", "b", "c"}[i%3]})
	}
	zoneOf := map[string]string{}
	for _, n := range nodes {
		zoneOf[n.ID] = n.Zone
	}
	seen := map[string]bool{}
	for _, id := range SubsetZoned(p, nodes, 3) {
		seen[zoneOf[id]] = true
	}
	if len(seen) != 3 {
		t.Fatalf("subset of 3 covers zones %v", seen)
	}
}
