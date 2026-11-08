package trace

import (
	"reflect"
	"testing"
)

func TestRetOffsetsAMD64SkipsC3InsideOperands(t *testing.T) {
	code := []byte{
		0xB8, 0xC3, 0xC3, 0xC3, 0xC3, // mov eax, 0xc3c3c3c3
		0x48, 0x8B, 0xC3, // mov rax, rbx (0xC3 is the ModRM byte)
		0xC3, // ret
		0x90, // nop
		0xC3, // ret
	}
	got, err := retOffsetsAMD64(code)
	if err != nil {
		t.Fatal(err)
	}
	if want := []uint64{8, 10}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestRetOffsetsAMD64RefusesUndecodableCode(t *testing.T) {
	// 0x06 does not exist in 64-bit mode; a raw scan would have probed the 0xC3 after it
	if got, err := retOffsetsAMD64([]byte{0xC3, 0x06, 0xC3}); err == nil {
		t.Fatalf("want an error, got %v", got)
	}
}
