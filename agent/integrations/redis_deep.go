package integrations

// Redis, Valkey, Dragonfly and KeyDB depth (track A2): per-command stats and latency percentiles,
// error stats, SLOWLOG samples, LATENCY LATEST, replica lag, cluster slot health, MEMORY DOCTOR
// advice and big/hot key patterns from a random key sample. Commands and keys are reported as
// a command name plus key patterns (`GET user:*:cart`), never values.

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/dbm"
	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

const (
	redisDeepEvery   = 20  // rounds between keyspace sampling and MEMORY DOCTOR (5 min at 15 s)
	redisMaxSlowCmds = 100 // commands tracked for slowlog totals
	redisTopPatterns = 20
)

type redisDeep struct {
	keySample  int
	round      int
	lastSlowID int64
	slow       map[string]*[2]float64 // command -> entries, total µs
}

func newRedisDeep(keySample int) *redisDeep {
	if keySample == 0 {
		keySample = 1000
	}
	return &redisDeep{keySample: max(keySample, 0), lastSlowID: -1, slow: map[string]*[2]float64{}}
}

// RedisSystem names the server from INFO: redis, valkey, dragonfly or keydb.
func RedisSystem(info map[string]string) (string, string) {
	switch {
	case info["dragonfly_version"] != "":
		return "dragonfly", info["dragonfly_version"]
	case info["valkey_version"] != "" || info["server_name"] == "valkey":
		return "valkey", info["valkey_version"]
	case strings.Contains(info["executable"], "keydb"):
		return "keydb", info["redis_version"]
	}
	return "redis", info["redis_version"]
}

func (d *redisDeep) collect(s *respSession, info map[string]string, out sink.Sink, now time.Time) {
	d.round++
	sys, ver := RedisSystem(info)
	out.Gauge("redis.server.info", "1", 1, map[string]string{"db.system.name": sys, "db.system.version": ver}, now)
	EmitRedisStats(out, info, now)
	if v, err := s.do("SLOWLOG", "GET", "128"); err == nil {
		d.slowlog(out, sys, v, now)
	}
	if v, err := s.do("LATENCY", "LATEST"); err == nil {
		EmitLatencyLatest(out, v, now)
	}
	if info["cluster_enabled"] == "1" {
		if t, err := s.str("CLUSTER", "INFO"); err == nil {
			EmitClusterInfo(out, ParseRedisInfo(t), now)
		}
	}
	if d.round%redisDeepEvery != 1 {
		return
	}
	if t, err := s.str("MEMORY", "DOCTOR"); err == nil {
		EmitMemoryDoctor(out, sys, t, now)
	}
	if d.keySample > 0 {
		d.sampleKeys(s, sys, info, out, now)
	}
}

// infoKV parses `a=1,b=2` INFO values.
func infoKV(v string) map[string]float64 {
	m := map[string]float64{}
	for _, kv := range strings.Split(v, ",") {
		if k, x, ok := strings.Cut(kv, "="); ok {
			if f, err := strconv.ParseFloat(x, 64); err == nil {
				m[k] = f
			}
		}
	}
	return m
}

// EmitRedisStats emits commandstats, latencystats, errorstats, keyspace expiry and replica lag.
func EmitRedisStats(out sink.Sink, info map[string]string, now time.Time) {
	masterOff, _ := strconv.ParseFloat(info["master_repl_offset"], 64)
	for k, v := range info {
		switch {
		case strings.HasPrefix(k, "cmdstat_"):
			m, a := infoKV(v), map[string]string{"db.operation.name": strings.TrimPrefix(k, "cmdstat_")}
			out.Sum("redis.command.calls", "{calls}", m["calls"], a, now)
			out.Sum("redis.command.time", "us", m["usec"], a, now)
			out.Sum("redis.command.failed", "{calls}", m["failed_calls"], a, now)
			out.Sum("redis.command.rejected", "{calls}", m["rejected_calls"], a, now)
		case strings.HasPrefix(k, "latency_percentiles_usec_"):
			cmd := strings.TrimPrefix(k, "latency_percentiles_usec_")
			for q, f := range infoKV(v) {
				out.Gauge("redis.command.latency", "us", f, map[string]string{"db.operation.name": cmd, "quantile": strings.TrimPrefix(q, "p")}, now)
			}
		case strings.HasPrefix(k, "errorstat_"):
			out.Sum("redis.errors", "{errors}", infoKV(v)["count"], map[string]string{"error.type": strings.TrimPrefix(k, "errorstat_")}, now)
		case strings.HasPrefix(k, "db") && strings.Contains(v, "keys="):
			m, a := infoKV(v), map[string]string{"db": k}
			out.Gauge("redis.db.expires", "{keys}", m["expires"], a, now)
			out.Gauge("redis.db.avg_ttl", "ms", m["avg_ttl"], a, now)
		case strings.HasPrefix(k, "slave") && strings.Contains(v, "offset="):
			f := map[string]string{}
			for _, kv := range strings.Split(v, ",") {
				if a, b, ok := strings.Cut(kv, "="); ok {
					f[a] = b
				}
			}
			a := map[string]string{"replica": f["ip"] + ":" + f["port"], "state": f["state"]}
			lag, _ := strconv.ParseFloat(f["lag"], 64)
			off, _ := strconv.ParseFloat(f["offset"], 64)
			out.Gauge("redis.replica.lag", "s", lag, a, now)
			out.Gauge("redis.replica.offset_lag", "By", max(masterOff-off, 0), a, now)
		}
	}
}

// redisKeyArgs is how many leading arguments of a command are keys (the rest are values).
func redisKeyArgs(cmd string) int {
	switch strings.ToUpper(cmd) {
	case "DEL", "UNLINK", "EXISTS", "MGET", "TOUCH", "WATCH", "SINTER", "SUNION", "SDIFF", "PFCOUNT":
		return 8
	case "EVAL", "EVALSHA", "EVAL_RO", "EVALSHA_RO", "FCALL", "FCALL_RO", "SCRIPT", "FUNCTION", "CONFIG", "CLIENT",
		"HELLO", "AUTH", "MIGRATE", "ACL", "MODULE", "DEBUG", "SELECT", "SCAN":
		return 0
	}
	return 1
}

func strs(v any) []string {
	arr, _ := v.([]any)
	out := make([]string, 0, len(arr))
	for _, x := range arr {
		s, _ := x.(string)
		out = append(out, s)
	}
	return out
}

// slowlog emits the entries newer than the last round's (on the first round, the last minute's),
// a sample per entry (at most 20) and cumulative per-command totals.
func (d *redisDeep) slowlog(out sink.Sink, sys string, v any, now time.Time) {
	entries, _ := v.([]any)
	newest := int64(-1)
	for _, e := range entries {
		if f, ok := e.([]any); ok && len(f) >= 4 {
			id, _ := f[0].(int64)
			newest = max(newest, id)
		}
	}
	first := d.lastSlowID < 0
	if newest < d.lastSlowID { // server restarted or SLOWLOG RESET: ids start again
		d.lastSlowID = -1
	}
	sampled := 0
	for _, e := range entries {
		f, ok := e.([]any)
		if !ok || len(f) < 4 {
			continue
		}
		id, _ := f[0].(int64)
		ts, _ := f[1].(int64)
		us, _ := f[2].(int64)
		if id <= d.lastSlowID || first && now.Unix()-ts > 60 {
			continue
		}
		args := strs(f[3])
		if len(args) == 0 {
			continue
		}
		cmd := strings.ToLower(args[0])
		t := d.slow[cmd]
		if t == nil && len(d.slow) < redisMaxSlowCmds {
			t = &[2]float64{}
			d.slow[cmd] = t
		}
		if t != nil {
			t[0]++
			t[1] += float64(us)
		}
		if sampled < 20 {
			sampled++
			red := dbm.Redact(args, redisKeyArgs(cmd))
			dbm.EmitSample(out, sys, "query.sample", "WARN", map[string]any{"command": red, "duration_us": us, "at": ts},
				map[string]string{"db.operation.name": cmd, "db.query.hash": dbm.Hash(red)}, now)
		}
	}
	d.lastSlowID = max(d.lastSlowID, newest)
	for cmd, t := range d.slow {
		a := map[string]string{"db.operation.name": cmd}
		out.Sum("redis.slowlog.entries", "{entries}", t[0], a, now)
		out.Sum("redis.slowlog.duration", "us", t[1], a, now)
	}
}

// EmitLatencyLatest reads LATENCY LATEST: [event, unix time, latest ms, all-time max ms] rows.
func EmitLatencyLatest(out sink.Sink, v any, now time.Time) {
	rows, _ := v.([]any)
	for _, r := range rows {
		f, ok := r.([]any)
		if !ok || len(f) < 4 {
			continue
		}
		ev, _ := f[0].(string)
		latest, _ := f[2].(int64)
		peak, _ := f[3].(int64)
		a := map[string]string{"event": ev}
		out.Gauge("redis.latency.latest", "ms", float64(latest), a, now)
		out.Gauge("redis.latency.max", "ms", float64(peak), a, now)
	}
}

// EmitClusterInfo emits CLUSTER INFO slot and node health.
func EmitClusterInfo(out sink.Sink, ci map[string]string, now time.Time) {
	ok := 0.0
	if ci["cluster_state"] == "ok" {
		ok = 1
	}
	out.Gauge("redis.cluster.state_ok", "1", ok, nil, now)
	for k, n := range map[string]string{"cluster_slots_assigned": "redis.cluster.slots.assigned", "cluster_slots_ok": "redis.cluster.slots.ok",
		"cluster_slots_pfail": "redis.cluster.slots.pfail", "cluster_slots_fail": "redis.cluster.slots.fail",
		"cluster_known_nodes": "redis.cluster.nodes", "cluster_size": "redis.cluster.shards"} {
		if f, err := strconv.ParseFloat(ci[k], 64); err == nil {
			out.Gauge(n, "1", f, nil, now)
		}
	}
}

// EmitMemoryDoctor files the MEMORY DOCTOR report as advice unless it found nothing.
func EmitMemoryDoctor(out sink.Sink, sys, report string, now time.Time) {
	healthy := strings.Contains(report, "can't find any memory issue") || strings.Contains(report, "is empty or is using very little memory")
	v := 0.0
	if !healthy {
		v = 1
		dbm.EmitSample(out, sys, "advice", "WARN", map[string]any{"source": "MEMORY DOCTOR", "report": sink.Truncate(report, 4000)}, nil, now)
	}
	out.Gauge("redis.memory.doctor_issues", "1", v, nil, now)
}

type keyPattern struct {
	Pattern  string  `json:"pattern"`
	Keys     float64 `json:"keys"`
	Bytes    float64 `json:"bytes"`
	MaxBytes float64 `json:"max_bytes"`
	Freq     float64 `json:"freq,omitempty"`
}

// sampleKeys sizes a random sample of keys (RANDOMKEY, then MEMORY USAGE and, under an LFU
// policy, OBJECT FREQ, all pipelined) and reports the patterns holding the most memory, scaled
// from the sample to db0's key count.
func (d *redisDeep) sampleKeys(s *respSession, sys string, info map[string]string, out sink.Sink, now time.Time) {
	cmds := make([][]string, d.keySample)
	for i := range cmds {
		cmds[i] = []string{"RANDOMKEY"}
	}
	rs, err := s.pipeline(cmds)
	if err != nil {
		return
	}
	seen := map[string]bool{}
	var keys []string
	for _, r := range rs {
		if k, ok := r.(string); ok && !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	lfu := strings.Contains(info["maxmemory_policy"], "lfu")
	cmds = cmds[:0]
	for _, k := range keys {
		cmds = append(cmds, []string{"MEMORY", "USAGE", k})
		if lfu {
			cmds = append(cmds, []string{"OBJECT", "FREQ", k})
		}
	}
	if rs, err = s.pipeline(cmds); err != nil {
		return
	}
	step := 1
	if lfu {
		step = 2
	}
	sizes := make([]int64, len(keys))
	freqs := make([]int64, len(keys))
	for i := range keys {
		sizes[i], _ = rs[i*step].(int64)
		if lfu {
			freqs[i], _ = rs[i*step+1].(int64)
		}
	}
	total := infoKV(info["db0"])["keys"]
	EmitKeyPatterns(out, sys, keys, sizes, freqs, total, now)
}

// EmitKeyPatterns groups sampled keys by pattern and emits the top patterns by memory.
func EmitKeyPatterns(out sink.Sink, sys string, keys []string, sizes, freqs []int64, dbKeys float64, now time.Time) {
	if len(keys) == 0 {
		return
	}
	scale := 1.0
	if dbKeys > float64(len(keys)) {
		scale = dbKeys / float64(len(keys))
	}
	by := map[string]*keyPattern{}
	for i, k := range keys {
		p := dbm.KeyPattern(k)
		kp := by[p]
		if kp == nil {
			kp = &keyPattern{Pattern: p}
			by[p] = kp
		}
		kp.Keys++
		kp.Bytes += float64(sizes[i])
		kp.MaxBytes = max(kp.MaxBytes, float64(sizes[i]))
		kp.Freq += float64(freqs[i])
	}
	all := make([]*keyPattern, 0, len(by))
	for _, kp := range by {
		kp.Keys *= scale
		kp.Bytes *= scale
		all = append(all, kp)
	}
	sort.Slice(all, func(i, j int) bool {
		return all[i].Bytes > all[j].Bytes || all[i].Bytes == all[j].Bytes && all[i].Pattern < all[j].Pattern
	})
	all = all[:min(len(all), redisTopPatterns)]
	for _, kp := range all {
		a := map[string]string{"redis.key.pattern": kp.Pattern}
		out.Gauge("redis.keyspace.pattern.keys", "{keys}", kp.Keys, a, now)
		out.Gauge("redis.keyspace.pattern.bytes", "By", kp.Bytes, a, now)
		out.Gauge("redis.keyspace.pattern.max_key_bytes", "By", kp.MaxBytes, a, now)
		if kp.Freq > 0 {
			out.Gauge("redis.keyspace.pattern.freq", "1", kp.Freq, a, now)
		}
	}
	out.Gauge("redis.keyspace.sampled", "{keys}", float64(len(keys)), nil, now)
	dbm.EmitSample(out, sys, "keyspace", "INFO", map[string]any{"sampled": len(keys), "patterns": all[:min(len(all), 10)]}, nil, now)
}
