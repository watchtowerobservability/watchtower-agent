package ebpf

import (
	"strconv"
	"strings"
)

// statStartTime parses field 22 (starttime) of a /proc/<pid>/stat line. Field 2 (comm) is
// parenthesised and may itself contain spaces and parentheses, so the fixed fields are read from
// after the last ')'. Returns 0 when the line is malformed.
func statStartTime(stat string) uint64 {
	i := strings.LastIndexByte(stat, ')')
	if i < 0 || i+2 > len(stat) {
		return 0
	}
	// After "pid (comm)" the next field is state (field 3); starttime (field 22) is the 20th.
	fields := strings.Fields(stat[i+2:])
	if len(fields) < 20 {
		return 0
	}
	v, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return 0
	}
	return v
}
