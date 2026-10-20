package memcache

import (
	"crypto/rand"
	"encoding/binary"
	"net"
	"sync"
	"time"
)

// nodeBackoff tracks consecutive failed dials to one server. Once failures
// reach the threshold, dials are skipped until blockedUntil; after that a
// single dial is let through to test the server while other callers keep
// failing fast, so a dead server sees one dial per backoff period per client
// instead of one per request.
type nodeBackoff struct {
	threshold   int
	baseBackoff time.Duration
	maxBackoff  time.Duration

	mu            sync.Mutex
	failures      int
	backoff       time.Duration
	blockedUntil  time.Time
	retryInFlight bool
}

// allow reports whether a dial may be attempted. Every allow() that returns
// true must be followed by exactly one record(), or the test dial is never
// released and the server stays backed off.
func (n *nodeBackoff) allow() bool {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.failures < n.threshold {
		return true
	}
	if time.Now().Before(n.blockedUntil) || n.retryInFlight {
		return false
	}
	n.retryInFlight = true
	return true
}

// record feeds a dial's outcome back into the tracker.
func (n *nodeBackoff) record(failed bool) {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.retryInFlight = false
	if !failed {
		n.failures = 0
		n.backoff = n.baseBackoff
		return
	}

	n.failures++
	// Dials started before the block keep failing in after it; only the
	// failure that crosses the threshold or a failed test dial extends it.
	if n.failures < n.threshold || time.Now().Before(n.blockedUntil) {
		return
	}
	n.blockedUntil = time.Now().Add(withJitter(n.backoff))
	n.backoff *= 2
	if n.backoff > n.maxBackoff {
		n.backoff = n.maxBackoff
	}
}

// withJitter returns a random duration in [d/2, 3d/2) so clients that backed
// off a server at the same moment don't all retry it at the same moment.
func withJitter(d time.Duration) time.Duration {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return d
	}
	frac := float64(binary.LittleEndian.Uint64(buf[:])>>11) / (1 << 53)
	return d/2 + time.Duration(frac*float64(d))
}

// nodeBackoff returns the tracker for addr, creating it on first use.
func (c *Client) nodeBackoff(addr net.Addr) *nodeBackoff {
	c.lk.Lock()
	defer c.lk.Unlock()
	if c.backoffs == nil {
		c.backoffs = make(map[string]*nodeBackoff)
	}
	n, ok := c.backoffs[addr.String()]
	if !ok {
		n = &nodeBackoff{
			threshold:   c.FailureThreshold,
			baseBackoff: c.baseBackoff(),
			maxBackoff:  c.maxBackoff(),
			backoff:     c.baseBackoff(),
		}
		c.backoffs[addr.String()] = n
	}
	return n
}

func (c *Client) baseBackoff() time.Duration {
	if c.BaseBackoff > 0 {
		return c.BaseBackoff
	}
	return DefaultBaseBackoff
}

func (c *Client) maxBackoff() time.Duration {
	if c.MaxBackoff > 0 {
		return c.MaxBackoff
	}
	return DefaultMaxBackoff
}
