//go:build !windows

package inventory

// shortcut: macOS and BSD report no packages (only dpkg/rpm/apk on Linux, uninstall keys on
// Windows); add pkgutil / pkg info readers when someone needs them.
func platformPackages() []Package { return nil }
