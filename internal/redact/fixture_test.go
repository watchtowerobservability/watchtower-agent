package redact

import "os"

// readFixture reads testdata/<rel> from the repo root: three levels up in the monorepo
// (go/internal/redact), two in the public agent mirror (internal/redact).
func readFixture(rel string) ([]byte, error) {
	b, err := os.ReadFile("../../../testdata/" + rel)
	if err != nil {
		return os.ReadFile("../../testdata/" + rel)
	}
	return b, err
}
