package ebpf

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

// ipcPeer answers one request with a canned reply and keeps what it was sent.
type ipcPeer struct {
	sent  bytes.Buffer
	reply *bytes.Reader
}

func (p *ipcPeer) Write(b []byte) (int, error) { return p.sent.Write(b) }
func (p *ipcPeer) Read(b []byte) (int, error)  { return p.reply.Read(b) }

func TestEnableDotnetPerfMap(t *testing.T) {
	ok := &ipcPeer{reply: bytes.NewReader(ipcFrame(ipcServer, ipcOK, make([]byte, 4)))}
	if err := enableDotnetPerfMap(ok); err != nil {
		t.Fatal(err)
	}
	want := append([]byte("DOTNET_IPC_V1\x00"), 24, 0, 0x04, 0x05, 0, 0, 3, 0, 0, 0)
	if !bytes.Equal(ok.sent.Bytes(), want) {
		t.Fatalf("sent % x", ok.sent.Bytes())
	}
	refused := &ipcPeer{reply: bytes.NewReader(ipcFrame(ipcServer, 0xff, binary.LittleEndian.AppendUint32(nil, 0x80131384)))}
	if err := enableDotnetPerfMap(refused); err == nil || !strings.Contains(err.Error(), "0x80131384") {
		t.Fatalf("err %v", err)
	}
	junk := &ipcPeer{reply: bytes.NewReader(make([]byte, 20))}
	if err := enableDotnetPerfMap(junk); err == nil {
		t.Fatal("a reply without the magic must fail")
	}
}
