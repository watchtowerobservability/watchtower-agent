//go:build !windows

package logs

import (
	"fmt"
	"os"
	"syscall"
)

// fileID identifies a file across renames: device and inode.
func fileID(_ *os.File, fi os.FileInfo) string {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return fmt.Sprintf("%d-%d", st.Dev, st.Ino)
	}
	return fi.Name() // shortcut: no inode on this platform, so rotation by rename is not followed
}
