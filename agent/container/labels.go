package container

import (
	"net"
	"net/url"
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

// defaultPorts are the integration ports used when a container names none.
var defaultPorts = map[string]int{"postgres": 5432, "redis": 6379, "traefik": 8080, "nginx": 80}

// ImageIntegration maps an image reference (registry/name:tag@digest) to an integration name by
// its last path segment, or "".
func ImageIntegration(image string) string {
	if i := strings.IndexByte(image, '@'); i >= 0 {
		image = image[:i]
	}
	image = image[strings.LastIndexByte(image, '/')+1:]
	if i := strings.IndexByte(image, ':'); i >= 0 {
		image = image[:i]
	}
	if image == "postgresql" {
		return "postgres"
	}
	if _, ok := defaultPorts[image]; ok {
		return image
	}
	return ""
}

// IntegrationTargets returns running containers that name an integration with the label
// watchtower.integration (optionally watchtower.port), or, with byImage, are recognised by image.
// Credentials are never read from here: the agent's own file holds the base config (see
// modules_autodiscover.go). Containers that already opt in with watchtower.dev/scrape are left
// to LabelTargets.
func IntegrationTargets(cs []Info, byImage bool) []LabelTarget {
	var out []LabelTarget
	for _, c := range cs {
		l := c.Labels
		if l[labelPrefix+"scrape"] == "true" || c.State != "running" || net.ParseIP(c.IP) == nil {
			continue
		}
		integ := l["watchtower.integration"]
		if integ == "" && byImage {
			integ = ImageIntegration(c.Image)
		}
		if integ == "" || len(integ) > 100 {
			continue
		}
		port := defaultPorts[integ]
		if s := l["watchtower.port"]; s != "" {
			n, err := strconv.Atoi(s)
			if err != nil || n <= 0 || n >= 65536 {
				continue
			}
			port = n
		}
		if port == 0 && len(c.Ports) > 0 {
			port = c.Ports[0]
		}
		path := "/metrics"
		if integ == "nginx" {
			path = "/nginx_status"
			if su := l["watchtower.nginx.status_url"]; su != "" {
				// A label may only move the page on the container itself, never aim the agent elsewhere.
				u, err := url.Parse(su)
				if err != nil || u.Scheme != "http" || u.Hostname() != c.IP || u.User != nil || u.RawQuery != "" || !strings.HasPrefix(u.Path, "/") {
					continue
				}
				if u.Port() != "" {
					port, _ = strconv.Atoi(u.Port())
				} else {
					port = 80
				}
				path = u.Path
			}
		}
		if port <= 0 || port >= 65536 {
			continue
		}
		out = append(out, LabelTarget{ID: c.ID, Name: c.Name, IP: c.IP, Port: port, Path: path, Integration: integ})
	}
	return out
}
