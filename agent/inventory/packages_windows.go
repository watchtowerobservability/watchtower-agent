//go:build windows

package inventory

import "golang.org/x/sys/windows/registry"

// platformPackages reads the uninstall keys (64- and 32-bit views): DisplayName and DisplayVersion.
func platformPackages() []Package {
	var out []Package
	for _, root := range []string{`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`} {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, root, registry.ENUMERATE_SUB_KEYS)
		if err != nil {
			continue
		}
		names, _ := k.ReadSubKeyNames(-1)
		k.Close()
		for _, n := range names {
			sk, err := registry.OpenKey(registry.LOCAL_MACHINE, root+`\`+n, registry.QUERY_VALUE)
			if err != nil {
				continue
			}
			name, _, err := sk.GetStringValue("DisplayName")
			ver, _, _ := sk.GetStringValue("DisplayVersion")
			sk.Close()
			if err == nil && name != "" {
				out = append(out, Package{Name: name, Version: ver, Manager: "windows"})
			}
		}
	}
	return out
}
