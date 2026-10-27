package authz

import (
	"sync"
	"time"
)

const maxCacheEntries = 100_000

type cacheEntry struct {
	d       Decision
	expires time.Time
}

// cache holds decisions per tenant and key id. Only key-based decisions are
// cached; lookup failures are not.
type cache struct {
	mu sync.Mutex
	m  map[string]cacheEntry
}

func newCache() *cache { return &cache{m: map[string]cacheEntry{}} }

func cacheKey(tenant, keyID string) string { return tenant + "\x00" + keyID }

func (c *cache) get(k string, now time.Time) (Decision, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[k]
	if !ok || now.After(e.expires) {
		return Decision{}, false
	}
	return e.d, true
}

func (c *cache) put(k string, d Decision, ttl time.Duration, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.m) >= maxCacheEntries {
		for key, e := range c.m {
			if now.After(e.expires) {
				delete(c.m, key)
			}
		}
		if len(c.m) >= maxCacheEntries {
			c.m = map[string]cacheEntry{}
		}
	}
	c.m[k] = cacheEntry{d: d, expires: now.Add(ttl)}
}
