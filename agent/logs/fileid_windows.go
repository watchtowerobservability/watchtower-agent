//go:build windows

package logs

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// fileID identifies a file across renames: volume serial number and file index.
func fileID(f *os.File, fi os.FileInfo) string {
	var d windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &d); err != nil {
		return fi.Name()
	}
	return fmt.Sprintf("%d-%d-%d", d.VolumeSerialNumber, d.FileIndexHigh, d.FileIndexLow)
}
