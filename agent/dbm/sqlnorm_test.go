package dbm

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/watchtowerobservability/watchtower-agent/internal/repofile"
)

// Every implementation of the canonical normalizer must pass the shared vectors.
func TestSQLNormalizeVectors(t *testing.T) {
	b, err := os.ReadFile(repofile.Path("testdata/sql_normalize_vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Vectors []struct {
			Name, Input, Normalized, Hash string
			PG                            bool `json:"pg"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(b, &f); err != nil || len(f.Vectors) < 40 {
		t.Fatalf("vectors: %v (%d)", err, len(f.Vectors))
	}
	for _, v := range f.Vectors {
		n, h := HashSQL(v.Input, v.PG)
		if n != v.Normalized || h != v.Hash {
			t.Errorf("%s: got %q %s, want %q %s", v.Name, n, h, v.Normalized, v.Hash)
		}
	}
}
