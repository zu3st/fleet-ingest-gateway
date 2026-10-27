package authz

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"
)

// metrics is a minimal Prometheus text exposition: a few counters and one
// lookup latency summary. Label values are fixed reasons or validated tenants.
type metrics struct {
	mu          sync.Mutex
	decisions   map[[4]string]uint64 // tenant, decision, reason, source
	lookups     map[string]uint64    // result
	lookupSum   float64
	lookupCount uint64
}

func newMetrics() *metrics {
	return &metrics{decisions: map[[4]string]uint64{}, lookups: map[string]uint64{}}
}

func (m *metrics) decision(tenant, decision, reason string, cached bool) {
	source := "lookup"
	if cached {
		source = "cache"
	}
	m.mu.Lock()
	m.decisions[[4]string{tenant, decision, reason, source}]++
	m.mu.Unlock()
}

func (m *metrics) lookup(result string, d time.Duration) {
	m.mu.Lock()
	m.lookups[result]++
	m.lookupSum += d.Seconds()
	m.lookupCount++
	m.mu.Unlock()
}

func (m *metrics) write(w io.Writer) {
	m.mu.Lock()
	defer m.mu.Unlock()
	fmt.Fprintln(w, "# HELP fleet_authz_decisions_total Authorization decisions.")
	fmt.Fprintln(w, "# TYPE fleet_authz_decisions_total counter")
	keys := make([][4]string, 0, len(m.decisions))
	for k := range m.decisions {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return strings.Join(keys[i][:], "|") < strings.Join(keys[j][:], "|") })
	for _, k := range keys {
		fmt.Fprintf(w, "fleet_authz_decisions_total{tenant=%q,decision=%q,reason=%q,source=%q} %d\n",
			k[0], k[1], k[2], k[3], m.decisions[k])
	}
	fmt.Fprintln(w, "# HELP fleet_authz_es_lookups_total API key lookups in Elasticsearch.")
	fmt.Fprintln(w, "# TYPE fleet_authz_es_lookups_total counter")
	results := make([]string, 0, len(m.lookups))
	for r := range m.lookups {
		results = append(results, r)
	}
	sort.Strings(results)
	for _, r := range results {
		fmt.Fprintf(w, "fleet_authz_es_lookups_total{result=%q} %d\n", r, m.lookups[r])
	}
	fmt.Fprintln(w, "# HELP fleet_authz_es_lookup_seconds API key lookup latency.")
	fmt.Fprintln(w, "# TYPE fleet_authz_es_lookup_seconds summary")
	fmt.Fprintf(w, "fleet_authz_es_lookup_seconds_sum %g\n", m.lookupSum)
	fmt.Fprintf(w, "fleet_authz_es_lookup_seconds_count %d\n", m.lookupCount)
}
