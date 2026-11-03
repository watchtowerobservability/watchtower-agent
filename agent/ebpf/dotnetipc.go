package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// .NET JIT code has no symbols on disk; the runtime names it in /tmp/perf-<pid>.map, which it
// writes only when asked. The agent asks through the runtime's diagnostics server (the documented
// Diagnostics IPC protocol, .NET 8+): Process command set, EnablePerfMap. Existing methods are
// written at once and new ones as they are jitted, so the next upload window has names. This is
// in place of a reader of the runtime's own tables, which needs per-release contracts.
const (
	ipcHeaderLen      = 20
	ipcProcess        = 0x04
	ipcEnablePerfMap  = 0x05
	ipcServer         = 0xff
	ipcOK             = 0x00
	ipcPerfMapOnly    = 3 // PerfMapType.PerfMap: the perf map, without jitdump files
	ipcMaxReplyLength = 1 << 12
)

var ipcMagic = []byte("DOTNET_IPC_V1\x00")

// ipcFrame is one request: magic, total size, command set and id, two reserved bytes, payload.
func ipcFrame(set, id byte, payload []byte) []byte {
	b := make([]byte, ipcHeaderLen, ipcHeaderLen+len(payload))
	copy(b, ipcMagic)
	binary.LittleEndian.PutUint16(b[14:], uint16(ipcHeaderLen+len(payload)))
	b[16], b[17] = set, id
	return append(b, payload...)
}

// enableDotnetPerfMap sends EnablePerfMap on an open diagnostics connection and reads the answer.
func enableDotnetPerfMap(c io.ReadWriter) error {
	if _, err := c.Write(ipcFrame(ipcProcess, ipcEnablePerfMap, binary.LittleEndian.AppendUint32(nil, ipcPerfMapOnly))); err != nil {
		return err
	}
	h := make([]byte, ipcHeaderLen)
	if _, err := io.ReadFull(c, h); err != nil {
		return err
	}
	if !bytes.Equal(h[:14], ipcMagic) {
		return errors.New("not a diagnostics IPC answer")
	}
	n := int(binary.LittleEndian.Uint16(h[14:]))
	if n < ipcHeaderLen || n > ipcMaxReplyLength {
		return fmt.Errorf("implausible diagnostics answer size %d", n)
	}
	p := make([]byte, n-ipcHeaderLen)
	if _, err := io.ReadFull(c, p); err != nil {
		return err
	}
	if h[16] != ipcServer || h[17] != ipcOK {
		code := uint32(0)
		if len(p) >= 4 {
			code = binary.LittleEndian.Uint32(p)
		}
		return fmt.Errorf("the runtime refused EnablePerfMap (0x%08x; .NET 8 or later is needed)", code)
	}
	return nil
}
