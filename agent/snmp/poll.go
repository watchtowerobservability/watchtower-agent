package snmp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
)

// MaxVarbinds caps the varbinds read from one device in one poll.
const MaxVarbinds = 10000

// V3 is one SNMPv3 user. Used for polling a device and, in the trap config, for the users whose
// traps are accepted.
type V3 struct {
	// EngineID is the sender's snmpEngineID in hex. Trap users need it (the sender is the
	// authoritative engine, so keys are localized with it); polling finds it by discovery.
	EngineID  string `json:"engine_id"`
	User      string `json:"user"`
	AuthProto string `json:"auth_protocol"` // sha, sha224, sha256, sha384, sha512
	AuthPass  string `json:"auth_passphrase"`
	PrivProto string `json:"priv_protocol"` // aes, aes192, aes256, aes192c, aes256c
	PrivPass  string `json:"priv_passphrase"`
}

// Target is one polled device. It is read from the agent's own file only.
type Target struct {
	Name      string   `json:"name"`      // shown as snmp.device; the address is never exported
	Address   string   `json:"address"`   // host or host:port (default port 161)
	Version   string   `json:"version"`   // "1", "2c" (default) or "3"
	Community string   `json:"community"` // v1 and v2c
	V3        *V3      `json:"v3"`
	Timeout   string   `json:"timeout"` // per request, default 3s
	Retries   int      `json:"retries"` // default 1
	Manifests []string `json:"manifests"`
}

var authProtos = map[string]gosnmp.SnmpV3AuthProtocol{
	"sha": gosnmp.SHA, "sha224": gosnmp.SHA224, "sha256": gosnmp.SHA256,
	"sha384": gosnmp.SHA384, "sha512": gosnmp.SHA512,
}

var privProtos = map[string]gosnmp.SnmpV3PrivProtocol{
	"aes": gosnmp.AES, "aes192": gosnmp.AES192, "aes256": gosnmp.AES256,
	"aes192c": gosnmp.AES192C, "aes256c": gosnmp.AES256C,
}

// usm converts a user to gosnmp security parameters and the message flags its level implies.
func (v V3) usm() (*gosnmp.UsmSecurityParameters, gosnmp.SnmpV3MsgFlags, error) {
	if v.User == "" {
		return nil, 0, errors.New("v3 user is empty")
	}
	sp := &gosnmp.UsmSecurityParameters{UserName: v.User}
	flags := gosnmp.NoAuthNoPriv
	if v.AuthPass != "" {
		ap, ok := authProtos[strings.ToLower(v.AuthProto)]
		if !ok || len(v.AuthPass) < 8 {
			return nil, 0, errors.New("v3 auth needs a protocol (sha*) and a passphrase of at least 8 characters")
		}
		sp.AuthenticationProtocol, sp.AuthenticationPassphrase = ap, v.AuthPass
		flags = gosnmp.AuthNoPriv
	}
	if v.PrivPass != "" {
		pp, ok := privProtos[strings.ToLower(v.PrivProto)]
		if !ok || len(v.PrivPass) < 8 || flags != gosnmp.AuthNoPriv {
			return nil, 0, errors.New("v3 priv needs auth, a protocol (aes*) and a passphrase of at least 8 characters")
		}
		sp.PrivacyProtocol, sp.PrivacyPassphrase = pp, v.PrivPass
		flags = gosnmp.AuthPriv
	}
	return sp, flags, nil
}

// Validate checks the target without touching the network.
func (t Target) Validate() error {
	if t.Name == "" || t.Address == "" {
		return errors.New("snmp target needs a name and an address")
	}
	switch t.Version {
	case "", "1", "2c":
		if t.Community == "" {
			return fmt.Errorf("snmp target %q: community is empty", t.Name)
		}
	case "3":
		if t.V3 == nil {
			return fmt.Errorf("snmp target %q: version 3 needs v3 settings", t.Name)
		}
		if _, _, err := t.V3.usm(); err != nil {
			return fmt.Errorf("snmp target %q: %w", t.Name, err)
		}
	default:
		return fmt.Errorf("snmp target %q: version must be 1, 2c or 3", t.Name)
	}
	if _, err := time.ParseDuration(orDefault(t.Timeout, "3s")); err != nil {
		return fmt.Errorf("snmp target %q: bad timeout", t.Name)
	}
	return nil
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

// scrub removes the address and every secret of the target from an error message.
func (t Target) scrub(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	host, _, herr := net.SplitHostPort(t.Address)
	if herr != nil {
		host = t.Address
	}
	secrets := []string{t.Address, host, t.Community}
	if t.V3 != nil {
		secrets = append(secrets, t.V3.User, t.V3.AuthPass, t.V3.PrivPass)
	}
	for _, s := range secrets {
		if s != "" {
			msg = strings.ReplaceAll(msg, s, "<redacted>")
		}
	}
	return errors.New(msg)
}

// session builds the gosnmp client (no network yet).
func (t Target) session(ctx context.Context) (*gosnmp.GoSNMP, error) {
	host, port := t.Address, "161"
	if h, p, err := net.SplitHostPort(t.Address); err == nil {
		host, port = h, p
	}
	pn, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return nil, errors.New("address has a bad port")
	}
	to, err := time.ParseDuration(orDefault(t.Timeout, "3s"))
	if err != nil || to <= 0 {
		return nil, errors.New("bad timeout")
	}
	retries := t.Retries
	if retries <= 0 {
		retries = 1
	}
	g := &gosnmp.GoSNMP{
		Target: host, Port: uint16(pn), Transport: "udp", Timeout: to, Retries: retries,
		MaxRepetitions: 20, Context: ctx,
	}
	switch t.Version {
	case "1":
		g.Version, g.Community = gosnmp.Version1, t.Community
	case "", "2c":
		g.Version, g.Community = gosnmp.Version2c, t.Community
	case "3":
		if t.V3 == nil {
			return nil, errors.New("version 3 needs v3 settings")
		}
		sp, flags, err := t.V3.usm()
		if err != nil {
			return nil, err
		}
		g.Version, g.SecurityModel, g.MsgFlags, g.SecurityParameters = gosnmp.Version3, gosnmp.UserSecurityModel, flags, sp
	default:
		return nil, errors.New("version must be 1, 2c or 3")
	}
	return g, nil
}

func (t Target) open(ctx context.Context) (*gosnmp.GoSNMP, error) {
	g, err := t.session(ctx)
	if err != nil {
		return nil, t.scrub(err)
	}
	if err := g.Connect(); err != nil {
		return nil, t.scrub(err)
	}
	return g, nil
}

// walkOne reads the subtree under oid, appending at most *budget varbinds (and lowering it).
// capped reports that the budget ran out before the subtree ended.
func walkOne(g *gosnmp.GoSNMP, oid string, budget *int) (_ []gosnmp.SnmpPDU, capped bool, _ error) {
	var out []gosnmp.SnmpPDU
	h := func(p gosnmp.SnmpPDU) error {
		if *budget <= 0 {
			capped = true
			return errors.New("varbind cap")
		}
		*budget--
		out = append(out, p)
		return nil
	}
	var err error
	if g.Version == gosnmp.Version1 {
		err = g.Walk(oid, h)
	} else {
		err = g.BulkWalk(oid, h)
	}
	if capped {
		err = nil
	}
	return out, capped, err
}

// Walk reads the subtrees under oids from the device, at most max varbinds in all (max <= 0 or
// above MaxVarbinds means MaxVarbinds). ctx bounds the whole walk. When a subtree fails the
// varbinds read so far are still returned together with the first error; error text never
// contains the address or a credential.
func Walk(ctx context.Context, t Target, oids []string, max int) ([]gosnmp.SnmpPDU, error) {
	g, err := t.open(ctx)
	if err != nil {
		return nil, err
	}
	defer g.Conn.Close()
	if max <= 0 || max > MaxVarbinds {
		max = MaxVarbinds
	}
	var out []gosnmp.SnmpPDU
	var first error
	for _, oid := range oids {
		ps, _, err := walkOne(g, oid, &max)
		out = append(out, ps...)
		if err != nil && first == nil {
			first = t.scrub(err)
		}
	}
	return out, first
}

// get reads scalars, skipping the ones the device does not have.
func get(g *gosnmp.GoSNMP, oids []string) ([]gosnmp.SnmpPDU, error) {
	chunk := 20
	if g.Version == gosnmp.Version1 {
		chunk = 1 // one missing OID fails a whole v1 request
	}
	var out []gosnmp.SnmpPDU
	var first error
	for i := 0; i < len(oids); i += chunk {
		pk, err := g.Get(oids[i:min(i+chunk, len(oids))])
		if err != nil {
			if first == nil {
				first = err
			}
			continue
		}
		for _, v := range pk.Variables {
			switch v.Type {
			case gosnmp.NoSuchObject, gosnmp.NoSuchInstance, gosnmp.Null, gosnmp.EndOfMibView:
			default:
				out = append(out, v)
			}
		}
	}
	return out, first
}
