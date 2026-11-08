package trace

import (
	"fmt"

	"golang.org/x/arch/x86/x86asm"
)

// retOffsetsAMD64 decodes code from its start and returns the offset of each RET. A breakpoint
// inside an instruction corrupts the traced process, so anything undecodable fails the whole
// function and it stays unprobed.
func retOffsetsAMD64(code []byte) ([]uint64, error) {
	var out []uint64
	for i := 0; i < len(code); {
		inst, err := x86asm.Decode(code[i:], 64)
		if err != nil {
			return nil, fmt.Errorf("decode at +%d: %w", i, err)
		}
		if inst.Op == x86asm.RET {
			out = append(out, uint64(i))
		}
		i += inst.Len
	}
	return out, nil
}
