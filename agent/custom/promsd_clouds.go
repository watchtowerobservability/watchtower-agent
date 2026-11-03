package custom

// More cloud discovery (CFT-A02): Lightsail, IONOS, OVHcloud, Triton, Uyuni.

import (
	"bytes"
	"context"
	"crypto/sha1" //nolint:gosec // OVH's request signature is defined as SHA-1
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

func init() {
	sdHTTPTypes["lightsail"] = SDConfig.lightsailSD
	sdHTTPTypes["ionos"] = SDConfig.ionosSD
	sdHTTPTypes["ovhcloud"] = SDConfig.ovhSD
	sdHTTPTypes["triton"] = SDConfig.tritonSD
	sdHTTPTypes["uyuni"] = SDConfig.uyuniSD
}

func portOr(p, def int) int {
	if p > 0 {
		return p
	}
	return def
}

// lightsailSD: Region and AWS keys as for ec2; only running instances.
func (c SDConfig) lightsailSD(ctx context.Context, hc *http.Client) ([]TargetSpec, error) {
	if c.Region == "" {
		return nil, errors.New("sd lightsail: region required")
	}
	cp, err := c.awsCreds(ctx)
	if err != nil {
		return nil, err
	}
	creds, err := cp.Retrieve(ctx)
	if err != nil {
		return nil, errors.New("aws credentials unavailable")
	}
	ep := cmpOr(c.Endpoint, "https://lightsail."+c.Region+".amazonaws.com/")
	var out []TargetSpec
	token := ""
	for range sdMaxPages {
		body, _ := json.Marshal(map[string]string{"pageToken": token})
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep, bytes.NewReader(body))
		if err != nil {
			return nil, errors.New("bad lightsail endpoint")
		}
		req.Header.Set("Content-Type", "application/x-amz-json-1.1")
		req.Header.Set("X-Amz-Target", "Lightsail_20161128.GetInstances")
		sum := sha256.Sum256(body)
		if err := v4.NewSigner().SignHTTP(ctx, creds, req, hex.EncodeToString(sum[:]), "lightsail", c.Region, time.Now()); err != nil {
			return nil, errors.New("sigv4 signing failed")
		}
		resp, err := hc.Do(req)
		if err != nil {
			return nil, errors.New("sd lightsail: request failed")
		}
		var res struct {
			Instances []struct {
				Name             string `json:"name"`
				PrivateIPAddress string `json:"privateIpAddress"`
				PublicIPAddress  string `json:"publicIpAddress"`
				State            struct {
					Name string `json:"name"`
				} `json:"state"`
				Location struct {
					AvailabilityZone string `json:"availabilityZone"`
				} `json:"location"`
			} `json:"instances"`
			NextPageToken string `json:"nextPageToken"`
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, sdMaxBody))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("sd lightsail: status %d", resp.StatusCode)
		}
		if err := json.Unmarshal(b, &res); err != nil {
			return nil, errors.New("sd lightsail: bad response")
		}
		for _, i := range res.Instances {
			ip := i.PrivateIPAddress
			if c.Public && i.PublicIPAddress != "" {
				ip = i.PublicIPAddress
			}
			if i.State.Name == "running" && ip != "" {
				out = append(out, TargetSpec{URL: c.scrapeURL(ip, portOr(c.Port, 9100)), Labels: map[string]string{"instance_name": i.Name, "zone": i.Location.AvailabilityZone}})
			}
		}
		if token = res.NextPageToken; token == "" {
			break
		}
	}
	return out, nil
}

// ionosSD: DatacenterID and Token; every running server's first NIC address.
func (c SDConfig) ionosSD(ctx context.Context, hc *http.Client) ([]TargetSpec, error) {
	if c.DatacenterID == "" || c.Token == "" {
		return nil, errors.New("sd ionos: datacenter_id and token required")
	}
	var res struct {
		Items []struct {
			Properties struct {
				Name    string `json:"name"`
				VMState string `json:"vmState"`
			} `json:"properties"`
			Entities struct {
				NICs struct {
					Items []struct {
						Properties struct {
							IPs []string `json:"ips"`
						} `json:"properties"`
					} `json:"items"`
				} `json:"nics"`
			} `json:"entities"`
		} `json:"items"`
	}
	u := strings.TrimSuffix(cmpOr(c.URL, "https://api.ionos.com/cloudapi/v6"), "/") + "/datacenters/" + url.PathEscape(c.DatacenterID) + "/servers?depth=3"
	if err := doJSON(ctx, hc, http.MethodGet, u, map[string]string{"Authorization": "Bearer " + c.Token}, nil, &res); err != nil {
		return nil, fmt.Errorf("sd ionos: %w", err)
	}
	var out []TargetSpec
	for _, s := range res.Items {
		if s.Properties.VMState != "RUNNING" || len(s.Entities.NICs.Items) == 0 || len(s.Entities.NICs.Items[0].Properties.IPs) == 0 {
			continue
		}
		out = append(out, TargetSpec{URL: c.scrapeURL(s.Entities.NICs.Items[0].Properties.IPs[0], portOr(c.Port, 9100)), Labels: map[string]string{"instance_name": s.Properties.Name}})
	}
	return out, nil
}

// ovhSign is OVH's request signature: "$1$" + sha1(secret+consumer+METHOD+url+body+timestamp).
func ovhSign(secret, consumer, method, u, body string, ts int64) string {
	sum := sha1.Sum([]byte(strings.Join([]string{secret, consumer, method, u, body, strconv.FormatInt(ts, 10)}, "+"))) //nolint:gosec // defined by the API
	return "$1$" + hex.EncodeToString(sum[:])
}

// ovhSD: ApplicationKey, ApplicationSecret, ConsumerKey; URL is the API base (default EU). VPS and
// dedicated servers, one target for each. Role selects one of "vps" or "dedicated_server".
func (c SDConfig) ovhSD(ctx context.Context, hc *http.Client) ([]TargetSpec, error) {
	if c.ApplicationKey == "" || c.ApplicationSecret == "" || c.ConsumerKey == "" {
		return nil, errors.New("sd ovhcloud: application_key, application_secret and consumer_key required")
	}
	base := strings.TrimSuffix(cmpOr(c.URL, "https://eu.api.ovh.com/1.0"), "/")
	get := func(p string, out any) error {
		u, ts := base+p, time.Now().Unix()
		return doJSON(ctx, hc, http.MethodGet, u, map[string]string{
			"X-Ovh-Application": c.ApplicationKey, "X-Ovh-Consumer": c.ConsumerKey,
			"X-Ovh-Timestamp": strconv.FormatInt(ts, 10), "X-Ovh-Signature": ovhSign(c.ApplicationSecret, c.ConsumerKey, http.MethodGet, u, "", ts),
		}, nil, out)
	}
	var out []TargetSpec
	for _, kind := range []struct{ role, path string }{{"vps", "/vps"}, {"dedicated_server", "/dedicated/server"}} {
		if c.Role != "" && c.Role != kind.role {
			continue
		}
		var names []string
		if err := get(kind.path, &names); err != nil {
			return nil, fmt.Errorf("sd ovhcloud: %w", err)
		}
		for _, n := range names {
			var ips []string
			if err := get(kind.path+"/"+url.PathEscape(n)+"/ips", &ips); err != nil {
				return nil, fmt.Errorf("sd ovhcloud: %w", err)
			}
			for _, ip := range ips {
				if !strings.Contains(ip, ":") { // the first IPv4; the v6 of the same host would double it
					out = append(out, TargetSpec{URL: c.scrapeURL(strings.TrimSuffix(ip, "/32"), portOr(c.Port, 9100)), Labels: map[string]string{"instance_name": n, "ovh_kind": kind.role}})
					break
				}
			}
		}
	}
	return out, nil
}

// tritonSD: URL is the CMON endpoint (https://cmon.example:9163), Account and DNSSuffix required.
func (c SDConfig) tritonSD(ctx context.Context, hc *http.Client) ([]TargetSpec, error) {
	if c.URL == "" || c.DNSSuffix == "" {
		return nil, errors.New("sd triton: url and dns_suffix required")
	}
	var res struct {
		Containers []struct {
			Alias    string `json:"vm_alias"`
			UUID     string `json:"vm_uuid"`
			ServerID string `json:"server_uuid"`
		} `json:"containers"`
	}
	u := strings.TrimSuffix(c.URL, "/") + "/v1/discover"
	if c.Account != "" {
		u += "?accounts=" + url.QueryEscape(c.Account)
	}
	if err := doJSON(ctx, hc, http.MethodGet, u, nil, nil, &res); err != nil {
		return nil, fmt.Errorf("sd triton: %w", err)
	}
	out := make([]TargetSpec, 0, len(res.Containers))
	for _, v := range res.Containers {
		out = append(out, TargetSpec{URL: c.scrapeURL(v.UUID+"."+c.DNSSuffix, portOr(c.Port, 9163)), Labels: map[string]string{"instance_name": v.Alias, "server_uuid": v.ServerID}})
	}
	return out, nil
}

// xmlValue is an XML-RPC value, as far as Uyuni's answers need.
type xmlValue struct {
	Int    string     `xml:"int"`
	I4     string     `xml:"i4"`
	String string     `xml:"string"`
	Chars  string     `xml:",chardata"`
	Array  []xmlValue `xml:"array>data>value"`
	Struct []struct {
		Name  string   `xml:"name"`
		Value xmlValue `xml:"value"`
	} `xml:"struct>member"`
}

func (v xmlValue) text() string { return strings.TrimSpace(v.String + v.Int + v.I4 + v.Chars) }

func (v xmlValue) field(name string) string {
	for _, m := range v.Struct {
		if m.Name == name {
			return m.Value.text()
		}
	}
	return ""
}

// xmlRPC calls method; params are strings and, for ints, already typed <int> values.
func xmlRPC(ctx context.Context, hc *http.Client, u, method string, params ...string) (xmlValue, error) {
	var b bytes.Buffer
	b.WriteString(`<?xml version="1.0"?><methodCall><methodName>` + method + `</methodName><params>`)
	for _, p := range params {
		b.WriteString("<param><value>")
		if strings.HasPrefix(p, "<int>") {
			b.WriteString(p)
		} else {
			b.WriteString("<string>")
			if err := xml.EscapeText(&b, []byte(p)); err != nil {
				return xmlValue{}, err
			}
			b.WriteString("</string>")
		}
		b.WriteString("</value></param>")
	}
	b.WriteString("</params></methodCall>")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, &b)
	if err != nil {
		return xmlValue{}, errors.New("bad uyuni url")
	}
	req.Header.Set("Content-Type", "text/xml")
	resp, err := hc.Do(req)
	if err != nil {
		return xmlValue{}, errors.New("request failed") // url.Error would repeat the URL
	}
	defer resp.Body.Close()
	var doc struct {
		Value xmlValue `xml:"params>param>value"`
		Fault *struct {
			Value xmlValue `xml:"value"`
		} `xml:"fault"`
	}
	if err := xml.NewDecoder(io.LimitReader(resp.Body, sdMaxBody)).Decode(&doc); err != nil {
		return xmlValue{}, errors.New("bad XML-RPC answer")
	}
	if doc.Fault != nil {
		return xmlValue{}, fmt.Errorf("%s refused: code %s", method, doc.Fault.Value.field("faultCode")) // the fault text can echo params
	}
	return doc.Value, nil
}

// uyuniSD: URL is the server's /rpc/api, Username and Password; one target per registered system.
func (c SDConfig) uyuniSD(ctx context.Context, hc *http.Client) ([]TargetSpec, error) {
	if c.URL == "" || c.Username == "" || c.Password == "" {
		return nil, errors.New("sd uyuni: url, username and password required")
	}
	login, err := xmlRPC(ctx, hc, c.URL, "auth.login", c.Username, c.Password)
	if err != nil {
		return nil, fmt.Errorf("sd uyuni: %w", err)
	}
	key := login.text()
	defer func() { _, _ = xmlRPC(context.WithoutCancel(ctx), hc, c.URL, "auth.logout", key) }()
	systems, err := xmlRPC(ctx, hc, c.URL, "system.listSystems", key)
	if err != nil {
		return nil, fmt.Errorf("sd uyuni: %w", err)
	}
	var out []TargetSpec
	for _, s := range systems.Array {
		id := s.field("id")
		if _, err := strconv.Atoi(id); err != nil {
			continue
		}
		net, err := xmlRPC(ctx, hc, c.URL, "system.getNetwork", key, "<int>"+id+"</int>")
		if err != nil {
			return nil, fmt.Errorf("sd uyuni: %w", err)
		}
		if host := cmpOr(net.field("hostname"), net.field("ip")); host != "" {
			out = append(out, TargetSpec{URL: c.scrapeURL(host, portOr(c.Port, 9100)), Labels: map[string]string{"instance_name": s.field("name"), "system_id": id}})
		}
	}
	return out, nil
}
