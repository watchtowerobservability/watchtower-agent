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
