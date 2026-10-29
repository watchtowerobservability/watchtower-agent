package gpu

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"
)

// RocmArgs is the fixed argument list for rocm-smi.
var RocmArgs = []string{"--showuse", "--showmeminfo", "vram", "--showtemp", "--showpower", "--json"}

func pathEnv() string { return os.Getenv("PATH") }

// ParseRocmJSON parses `rocm-smi --json` output: {"card0": {"GPU use (%)": "5", ...}, ...}.
// rocm-smi renames its keys between releases, so fields are found by key fragment.
func ParseRocmJSON(b []byte) ([]Reading, error) {
	var cards map[string]json.RawMessage
	if err := json.Unmarshal(b, &cards); err != nil {
		return nil, fmt.Errorf("rocm-smi output: %w", err)
	}
	names := make([]string, 0, len(cards))
	for k := range cards {
		if strings.HasPrefix(k, "card") {
			names = append(names, k)
		}
	}
	sort.Strings(names)
	out := make([]Reading, 0, len(names))
	for _, k := range names {
		var f map[string]any
		if json.Unmarshal(cards[k], &f) != nil {
			continue
		}
		out = append(out, Reading{
			Index: strings.TrimPrefix(k, "card"), Name: str(f, "Card series", "Card model"), Vendor: "amd",
			UtilPercent:  field(f, "GPU use (%)"),
			MemUsedBytes: field(f, "VRAM Total Used Memory (B)"),
			TempC:        field(f, "Temperature (Sensor edge)"),
			PowerW:       field(f, "Power (W)"),
		})
	}
	return out, nil
}

func str(f map[string]any, frags ...string) string {
	for _, frag := range frags {
		for k, v := range f {
			if s, ok := v.(string); ok && strings.Contains(k, frag) {
				return s
			}
		}
	}
	return ""
}

// field returns the number under the first key containing frag (NaN if absent).
func field(f map[string]any, frag string) float64 {
	keys := make([]string, 0, 2)
	for k := range f {
		if strings.Contains(k, frag) {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return math.NaN()
	}
	sort.Strings(keys)
	switch v := f[keys[0]].(type) {
	case string:
		return num(v)
	case float64:
		return v
	}
	return math.NaN()
}

// Rocm polls rocm-smi at path.
func Rocm(ctx context.Context, path string) ([]Reading, error) {
	b, err := run(ctx, path, RocmArgs...)
	if err != nil {
		return nil, err
	}
	return ParseRocmJSON(b)
}
