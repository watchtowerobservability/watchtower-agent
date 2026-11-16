package container

import (
	"strings"
	"sync"
)

// Learned is what the socket-free log forwarder (logs.forward) learned about a container from
// the records its Docker log driver sends: name, compose service and the labels the driver
// attached (log-opt labels / labels-regex). It names and labels the cgroup series.
type Learned struct {
	Name    string
	Service string
	Labels  map[string]string
}

const maxLearned = 5000

var learned = struct {
	sync.RWMutex
	m map[string]Learned
}{m: map[string]Learned{}}

func learnKey(id string) string { return id[:min(12, len(id))] }

// Learn remembers l for the container id (full id or a prefix of at least 12 characters).
func Learn(id string, l Learned) {
	if len(id) < 12 {
		return
	}
	learned.Lock()
	defer learned.Unlock()
	if len(learned.m) >= maxLearned {
		learned.m = map[string]Learned{} // shortcut: containers come back with their next log line
	}
	learned.m[learnKey(id)] = l
}

// Lookup returns what was learned about the container id.
func Lookup(id string) (Learned, bool) {
	learned.RLock()
	defer learned.RUnlock()
	l, ok := learned.m[learnKey(id)]
	return l, ok
}

// ServiceFromName guesses the compose service from a container name "<project>-<service>-<n>"
// (or with underscores): the name without its trailing replica number. The project prefix cannot
// be told from a dash in the service name, so the guess keeps it unless a compose.service label
// arrived with the record.
func ServiceFromName(name string) string {
	name = strings.TrimPrefix(name, "/")
	if i := strings.LastIndexAny(name, "-_"); i > 0 && i < len(name)-1 && strings.Trim(name[i+1:], "0123456789") == "" {
		return name[:i]
	}
	return name
}
