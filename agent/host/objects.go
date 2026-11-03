package host

import (
	"github.com/shirou/gopsutil/v4/disk"
	gnet "github.com/shirou/gopsutil/v4/net"
)

// Object is one discovered child of the host, with the labels its metrics carry.
type Object struct {
	Kind, Name string
	Labels     map[string]string
}

// Objects lists the filesystems, disks and interfaces the discovery rules let through: the
// same children Collect reports, for low-level-discovery rule prototypes (rulesync/lld.go).
func Objects(d Discovery) []Object {
	var out []Object
	if parts, err := disk.Partitions(false); err == nil {
		for _, p := range parts {
			if d.Allow(KindFilesystem, p.Mountpoint) {
				out = append(out, Object{Kind: KindFilesystem, Name: p.Mountpoint,
					Labels: map[string]string{"mountpoint": p.Mountpoint, "device": p.Device, "type": p.Fstype}})
			}
		}
	}
	if io, err := disk.IOCounters(); err == nil {
		for n := range io {
			if d.Allow(KindDisk, n) {
				out = append(out, Object{Kind: KindDisk, Name: n, Labels: map[string]string{"device": n}})
			}
		}
	}
	if nics, err := gnet.IOCounters(true); err == nil {
		for _, c := range nics {
			if d.Allow(KindNIC, c.Name) {
				out = append(out, Object{Kind: KindNIC, Name: c.Name, Labels: map[string]string{"device": c.Name}})
			}
		}
	}
	return out
}
