// Package repofile finds repository files from tests, whether the code sits in the monorepo
// (go/ under the root) or in a mirrored public repo (the module at the root).
package repofile

import (
	"os"
	"path/filepath"
)

// Path returns rel resolved against the nearest ancestor directory that contains it, or rel
// itself when none does (so the caller's read error names the path).
func Path(rel string) string {
	dir, err := os.Getwd()
	if err != nil {
		return rel
	}
	for {
		p := filepath.Join(dir, rel)
		if _, err := os.Stat(p); err == nil {
			return p
		}
		up := filepath.Dir(dir)
		if up == dir {
			return rel
		}
		dir = up
	}
}
