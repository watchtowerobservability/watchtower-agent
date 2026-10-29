package repofile

import (
	"os"
	"testing"
)

func TestPathFindsAncestorFile(t *testing.T) {
	if _, err := os.Stat(Path("go.mod")); err != nil {
		t.Fatal(err)
	}
	if got := Path("no/such/file"); got != "no/such/file" {
		t.Fatalf("got %q", got)
	}
}
