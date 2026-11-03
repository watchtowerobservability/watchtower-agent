//go:build linux

package trace

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

// readProc loads the selection facts of pid from /proc. Ports are only read when a selector
// names one (it walks the fd table).
func readProc(withPorts bool) func(uint32) (ProcInfo, bool) {
	return func(pid uint32) (ProcInfo, bool) {
		dir := "/proc/" + strconv.FormatUint(uint64(pid), 10)
		var p ProcInfo
		var err error
		if p.Exe, err = os.Readlink(dir + "/exe"); err != nil {
			return p, false
		}
		if b, err := os.ReadFile(dir + "/comm"); err == nil {
			p.Name = strings.TrimSpace(string(b))
		}
		if b, err := os.ReadFile(dir + "/cgroup"); err == nil {
			p.Cgroup = string(b)
		}
		p.Environ, _ = os.ReadFile(dir + "/environ")
		p.Cmdline, _ = os.ReadFile(dir + "/cmdline")
		if withPorts {
			p.Ports = listenPorts(dir)
		}
		return p, true
	}
}

// listenPorts: the local ports of LISTEN sockets (state 0A) whose inode is one of pid's fds.
func listenPorts(dir string) []int {
	inodes := map[string]bool{}
	fds, _ := os.ReadDir(dir + "/fd")
	for _, fd := range fds {
		if l, err := os.Readlink(dir + "/fd/" + fd.Name()); err == nil && strings.HasPrefix(l, "socket:[") {
			inodes[strings.TrimSuffix(strings.TrimPrefix(l, "socket:["), "]")] = true
		}
	}
	var out []int
	for _, f := range []string{"/net/tcp", "/net/tcp6"} {
		fh, err := os.Open(dir + f)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(fh)
		for sc.Scan() {
			x := strings.Fields(sc.Text())
			if len(x) < 10 || x[3] != "0A" || !inodes[x[9]] {
				continue
			}
			if _, port, ok := parseHexAddr(x[1]); ok {
				out = append(out, int(port))
			}
		}
		_ = fh.Close()
	}
	return out
}
