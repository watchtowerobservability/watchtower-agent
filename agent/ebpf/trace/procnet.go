package trace

import (
	"bufio"
	"encoding/hex"
	"io"
	"net/netip"
	"strconv"
	"strings"
)

// Peer is the remote end of a TCP socket.
type Peer struct {
	Addr string
	Port int64
}

// ParseProcNetTCP maps socket inode to remote peer from the text of /proc/net/tcp or tcp6.
// Listening sockets (remote 0.0.0.0:0) are skipped.
func ParseProcNetTCP(r io.Reader) map[uint64]Peer {
	out := map[uint64]Peer{}
	sc := bufio.NewScanner(r)
	sc.Scan() // header
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 10 {
			continue
		}
		ino, err := strconv.ParseUint(f[9], 10, 64)
		if err != nil || ino == 0 {
			continue
		}
		addr, port, ok := parseHexAddr(f[2])
		if !ok || port == 0 {
			continue
		}
		out[ino] = Peer{Addr: addr, Port: port}
	}
	return out
}

// parseHexAddr decodes "0100007F:1F90": each 32-bit word of the address is little endian.
func parseHexAddr(s string) (string, int64, bool) {
	a, p, ok := strings.Cut(s, ":")
	if !ok {
		return "", 0, false
	}
	b, err := hex.DecodeString(a)
	if err != nil || (len(b) != 4 && len(b) != 16) {
		return "", 0, false
	}
	for i := 0; i+4 <= len(b); i += 4 {
		b[i], b[i+1], b[i+2], b[i+3] = b[i+3], b[i+2], b[i+1], b[i]
	}
	port, err := strconv.ParseInt(p, 16, 32)
	if err != nil {
		return "", 0, false
	}
	ip, _ := netip.AddrFromSlice(b)
	return ip.Unmap().String(), port, true
}

// SocketInode extracts the inode from a /proc/<pid>/fd link target such as "socket:[12345]".
func SocketInode(link string) (uint64, bool) {
	s, ok := strings.CutPrefix(link, "socket:[")
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseUint(strings.TrimSuffix(s, "]"), 10, 64)
	return n, err == nil
}
