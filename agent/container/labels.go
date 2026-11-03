package container

import (
	"net"
	"strconv"
	"strings"
)

// LabelTarget is a container that opted in to scraping with the same keys as the pod
// annotations (watchtower.dev/scrape, port, path, integration), set as Docker labels.
type LabelTarget struct {
	ID, Name, IP, Path, Integration string
	Port                            int
}

const labelPrefix = "watchtower.dev/"

// LabelTargets returns the running containers whose labels opt in. Labels are untrusted input
// from whoever can start containers, so they only choose a port and path on the container's own IP.
func LabelTargets(cs []Info) []LabelTarget {
	var out []LabelTarget
	for _, c := range cs {
		l := c.Labels
		if l[labelPrefix+"scrape"] != "true" || c.State != "running" || net.ParseIP(c.IP) == nil {
			continue
		}
		port := 0
		if s := l[labelPrefix+"port"]; s != "" {
			n, err := strconv.Atoi(s)
			if err != nil || n <= 0 || n >= 65536 {
				continue
			}
			port = n
		} else if len(c.Ports) > 0 {
			port = c.Ports[0]
		}
		path := l[labelPrefix+"path"]
		if path == "" {
			path = "/metrics"
		}
		integ := l[labelPrefix+"integration"]
		if port == 0 || !strings.HasPrefix(path, "/") || strings.ContainsAny(path, " \t\r\n#") || len(path) > 200 || len(integ) > 100 {
			continue
		}
		out = append(out, LabelTarget{ID: c.ID, Name: c.Name, IP: c.IP, Port: port, Path: path, Integration: integ})
	}
	return out
}
