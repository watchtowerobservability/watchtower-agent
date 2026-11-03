package netflow

// Sampling-rate scaling for NetFlow v9 and IPFIX (INF-016): a sampled exporter reports one
// packet in N, so its byte and packet counters are multiplied by N. N comes from the data record
// itself (samplingInterval 34, samplerRandomInterval 50, samplingPacketInterval 305) or from an
// options data record that announces it for a sampler id (48 / 302) or for the whole exporter.

import "sync"

const (
	ieSamplingInterval = 34
	ieSamplerID        = 48
	ieSamplerInterval  = 50
	ieSelectorID       = 302
	iePacketInterval   = 305
	maxSamplers        = 10_000
	maxSamplingRate    = 1 << 24 // a larger "rate" is a broken exporter, not sampling
)

type skey struct {
	exporter string
	domain   uint32
	sampler  uint64 // 0: the exporter-wide rate
}

type samplers struct {
	mu sync.Mutex
	m  map[skey]uint64
}

func (s *samplers) set(k skey, rate uint64) {
	if rate <= 1 || rate > maxSamplingRate {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil || len(s.m) >= maxSamplers {
		s.m = map[skey]uint64{} // bounded: a flood of sampler ids resets the table
	}
	s.m[k] = rate
}

func (s *samplers) get(k skey) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r := s.m[k]; r > 1 {
		return r
	}
	if k.sampler != 0 {
		return s.m[skey{k.exporter, k.domain, 0}]
	}
	return 0
}

// sampling is what one record says about sampling.
type sampling struct {
	rate       uint64
	sampler    uint64
	hasSampler bool
}

func (sp *sampling) read(typ uint16, n uint64) {
	switch typ {
	case ieSamplingInterval, ieSamplerInterval, iePacketInterval:
		if n > sp.rate {
			sp.rate = n
		}
	case ieSamplerID, ieSelectorID:
		sp.sampler, sp.hasSampler = n, true
	}
}

// optionRecords reads the records of an options data set and remembers the rates they announce.
func (c *Templates) optionRecords(exporter string, domain uint32, t *template, b []byte) {
	for len(b) >= t.recLen && t.recLen > 0 {
		rec := b[:t.recLen]
		b = b[t.recLen:]
		var sp sampling
		for _, fd := range t.fields {
			sp.read(fd.typ, uintN(rec[:fd.n]))
			rec = rec[fd.n:]
		}
		c.samp.set(skey{exporter, domain, sp.sampler}, sp.rate)
	}
}

// scale multiplies the counters by the record's own rate, else its sampler's, else the
// exporter-wide rate announced in options data.
func (c *Templates) scale(exporter string, domain uint32, f *Flow, sp sampling) {
	rate := sp.rate
	if rate <= 1 {
		rate = c.samp.get(skey{exporter, domain, sp.sampler})
	}
	if rate > 1 && rate <= maxSamplingRate {
		f.Bytes *= rate
		f.Packets *= rate
	}
}

// parseOptionTemplates reads a v9 options template set (id, scope length, option length in
// bytes) or an IPFIX options template set (id, field count, scope field count). The templates
// share the cache with data templates and are marked as options.
func (c *Templates) parseOptionTemplates(base tkey, b []byte) (bad int) {
	for len(b) >= 6 {
		id := be16(b)
		var n int
		if base.ipfix {
			n = int(be16(b[2:]))
			b = b[6:]
		} else {
			scopeLen, optLen := int(be16(b[2:])), int(be16(b[4:]))
			if scopeLen%4 != 0 || optLen%4 != 0 {
				return bad + 1
			}
			n = (scopeLen + optLen) / 4
			b = b[6:]
		}
		if n == 0 || n > maxFields || id < 256 {
			return bad + 1
		}
		t := &template{option: true}
		for range n {
			if len(b) < 4 {
				return bad + 1
			}
			typ, ln := be16(b), int(be16(b[2:]))
			b = b[4:]
			if base.ipfix && typ&enterpriseFlag != 0 {
				if len(b) < 4 {
					return bad + 1
				}
				b, typ = b[4:], unknownField
			}
			if ln == 0 || ln == varLen {
				return bad + 1
			}
			t.fields = append(t.fields, field{typ, ln})
			t.recLen += ln
		}
		if t.recLen > maxRecLen {
			return bad + 1
		}
		base.id = id
		c.put(base, t)
		// v9 pads an options template set to 4 bytes; what is left is too short to be a template
		if !base.ipfix && len(b) < 6 {
			return bad
		}
	}
	return bad
}
