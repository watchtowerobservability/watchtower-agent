package snmp

import "context"

// SysInfo reads sysObjectID.0, sysName.0 and sysDescr.0 of a device (discovery, INF-021).
func SysInfo(ctx context.Context, t Target) (objectID, name, descr string, err error) {
	g, err := t.open(ctx)
	if err != nil {
		return "", "", "", err
	}
	defer g.Conn.Close()
	pdus, err := get(g, []string{"1.3.6.1.2.1.1.2.0", "1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.1.1.0"})
	if len(pdus) == 0 {
		if err == nil {
			err = context.DeadlineExceeded
		}
		return "", "", "", t.scrub(err)
	}
	for _, p := range pdus {
		switch norm(p.Name) {
		case "1.3.6.1.2.1.1.2.0":
			objectID = norm(pduString(p))
		case "1.3.6.1.2.1.1.5.0":
			name = pduString(p)
		case "1.3.6.1.2.1.1.1.0":
			descr = pduString(p)
		}
	}
	return objectID, name, descr, nil
}
