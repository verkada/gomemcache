/*
Copyright 2011 Google Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package memcache provides a client for the memcached cache server.
package memcache

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Similar to:
// https://godoc.org/google.golang.org/appengine/memcache

var (
	// ErrCacheMiss means that a Get failed because the item wasn't present.
	ErrCacheMiss = errors.New("memcache: cache miss")

	// ErrCASConflict means that a CompareAndSwap call failed due to the
	// cached value being modified between the Get and the CompareAndSwap.
	// If the cached value was simply evicted rather than replaced,
	// ErrNotStored will be returned instead.
	ErrCASConflict = errors.New("memcache: compare-and-swap conflict")

	// ErrNotStored means that a conditional write operation (i.e. Add or
	// CompareAndSwap) failed because the condition was not satisfied.
	ErrNotStored = errors.New("memcache: item not stored")

	// ErrServer means that a server error occurred.
	ErrServerError = errors.New("memcache: server error")

	// ErrNoStats means that no statistics were available.
	ErrNoStats = errors.New("memcache: no statistics available")

	// ErrMalformedKey is returned when an invalid key is used.
	// Keys must be at maximum 250 bytes long and not
	// contain whitespace or control characters.
	ErrMalformedKey = errors.New("malformed: key is too long or contains invalid characters")

	// ErrNoServers is returned when no servers are configured or available.
	ErrNoServers = errors.New("memcache: no servers configured or available")
)

const (
	// DefaultTimeout is the default socket read/write timeout.
	DefaultTimeout = 100 * time.Millisecond

	// DefaultMaxIdleConns is the default maximum number of idle connections
	// kept for any single address.
	DefaultMaxIdleConns = 2
)

const buffered = 8 // arbitrary buffered channel size, for readability

// resumableError returns true if err is only a protocol-level cache error.
// This is used to determine whether or not a server connection should
// be re-used or not. If an error occurs, by default we don't reuse the
// connection, unless it was just a cache error.
func resumableError(err error) bool {
	switch err {
	case ErrCacheMiss, ErrCASConflict, ErrNotStored, ErrMalformedKey:
		return true
	}
	return false
}

func legalKey(key string) bool {
	if len(key) > 250 {
		return false
	}
	for i := 0; i < len(key); i++ {
		if key[i] <= ' ' || key[i] == 0x7f {
			return false
		}
	}
	return true
}

var (
	crlf            = []byte("\r\n")
	space           = []byte(" ")
	resultOK        = []byte("OK\r\n")
	resultStored    = []byte("STORED\r\n")
	resultNotStored = []byte("NOT_STORED\r\n")
	resultExists    = []byte("EXISTS\r\n")
	resultNotFound  = []byte("NOT_FOUND\r\n")
	resultDeleted   = []byte("DELETED\r\n")
	resultEnd       = []byte("END\r\n")
	resultOk        = []byte("OK\r\n")
	resultTouched   = []byte("TOUCHED\r\n")

	resultClientErrorPrefix = []byte("CLIENT_ERROR ")
	versionPrefix           = []byte("VERSION")
)

// New returns a memcache client using the provided server(s)
// with equal weight. If a server is listed multiple times,
// it gets a proportional amount of weight.
func New(server ...string) *Client {
	ss := new(ServerList)
	ss.SetServers(server...)
	return NewFromSelector(ss)
}

// NewFromSelector returns a new Client using the provided ServerSelector.
func NewFromSelector(ss ServerSelector) *Client {
	return &Client{selector: ss}
}

// Client is a memcache client.
// It is safe for unlocked use by multiple concurrent goroutines.
type Client struct {
	// Timeout specifies the socket read/write timeout.
	// If zero, DefaultTimeout is used.
	Timeout time.Duration

	// DialTimeout specifies the timeout for establishing new connections,
	// including the TLS handshake if TLS is enabled.
	// If zero, Timeout is used (for backward compatibility).
	//
	// DialTimeout is a single budget covering both the TCP connection and the
	// TLS handshake. Because the TLS handshake can be slow when the server is
	// under CPU pressure, a single tight budget can abort handshakes mid-flight.
	// Prefer ConnectTimeout + HandshakeTimeout (below) to budget them
	// separately; DialTimeout is retained for backward compatibility and is used
	// only when the split timeouts are zero.
	DialTimeout time.Duration

	// ConnectTimeout, when non-zero, bounds only the TCP connection
	// establishment (not the TLS handshake). Pair with HandshakeTimeout to
	// budget connect and handshake independently. If zero, the dialer falls back
	// to DialTimeout for the whole operation.
	ConnectTimeout time.Duration

	// HandshakeTimeout, when non-zero, bounds only the TLS handshake (separate
	// from the TCP connect). Has no effect for non-TLS clients. If zero, the TLS
	// handshake shares the DialTimeout/ConnectTimeout budget (legacy behavior).
	HandshakeTimeout time.Duration

	// OnDial, when non-nil, is invoked after every connection attempt (success
	// or failure) with timing and outcome details. It enables callers to emit
	// dial-count, connect/handshake-duration, and TLS-resumption metrics without
	// the library taking a metrics dependency.
	//
	// OnDial is invoked on a separate goroutine so it can never add latency to
	// the dial path; consequently it may run after the connection is already in
	// use, and the relative ordering of callbacks is not guaranteed. A panic in
	// the hook is recovered and discarded. The DialInfo is passed by value, so
	// the hook owns its copy.
	OnDial func(DialInfo)

	// MaxIdleConns specifies the maximum number of idle connections that will
	// be maintained per address. If less than one, DefaultMaxIdleConns will be
	// used.
	//
	// Consider your expected traffic rates and latency carefully. This should
	// be set to a number higher than your peak parallel requests.
	MaxIdleConns int

	selector ServerSelector

	lk        sync.Mutex
	freeconn  map[string][]*conn
	TlsConfig *tls.Config
}

// DialInfo reports the outcome of a single connection attempt to OnDial.
type DialInfo struct {
	// Addr is the server address that was dialed.
	Addr net.Addr
	// TLS is true if the attempt included a TLS handshake.
	TLS bool
	// ConnectDuration is the time spent establishing the TCP connection.
	ConnectDuration time.Duration
	// HandshakeDuration is the time spent on the TLS handshake. Zero for
	// non-TLS attempts or when the connect failed before the handshake began.
	HandshakeDuration time.Duration
	// Resumed is true if the TLS handshake resumed a previous session
	// (abbreviated handshake). Only meaningful when TLS is true and Err is nil.
	Resumed bool
	// Err is the failure, or nil on success.
	Err error
}

// Item is an item to be got or stored in a memcached server.
type Item struct {
	// Key is the Item's key (250 bytes maximum).
	Key string

	// Value is the Item's value.
	Value []byte

	// Flags are server-opaque flags whose semantics are entirely
	// up to the app.
	Flags uint32

	// Expiration is the cache expiration time, in seconds: either a relative
	// time from now (up to 1 month), or an absolute Unix epoch time.
	// Zero means the Item has no expiration time.
	Expiration int32

	// Compare and swap ID.
	casid uint64
}

// conn is a connection to a server.
type conn struct {
	nc   net.Conn
	rw   *bufio.ReadWriter
	addr net.Addr
	c    *Client
}

// release returns this connection back to the client's free pool
func (cn *conn) release() {
	cn.c.putFreeConn(cn.addr, cn)
}

func (cn *conn) extendDeadline() {
	cn.nc.SetDeadline(time.Now().Add(cn.c.netTimeout()))
}

// condRelease releases this connection if the error pointed to by err
// is nil (not an error) or is only a protocol level error (e.g. a
// cache miss).  The purpose is to not recycle TCP connections that
// are bad.
func (cn *conn) condRelease(err *error) {
	if *err == nil || resumableError(*err) {
		cn.release()
	} else {
		cn.nc.Close()
	}
}

func (c *Client) putFreeConn(addr net.Addr, cn *conn) {
	c.lk.Lock()
	defer c.lk.Unlock()
	if c.freeconn == nil {
		c.freeconn = make(map[string][]*conn)
	}
	freelist := c.freeconn[addr.String()]
	if len(freelist) >= c.maxIdleConns() {
		cn.nc.Close()
		return
	}
	c.freeconn[addr.String()] = append(freelist, cn)
}

func (c *Client) getFreeConn(addr net.Addr) (cn *conn, ok bool) {
	c.lk.Lock()
	defer c.lk.Unlock()
	if c.freeconn == nil {
		return nil, false
	}
	freelist, ok := c.freeconn[addr.String()]
	if !ok || len(freelist) == 0 {
		return nil, false
	}
	cn = freelist[len(freelist)-1]
	c.freeconn[addr.String()] = freelist[:len(freelist)-1]
	return cn, true
}

func (c *Client) netTimeout() time.Duration {
	if c.Timeout != 0 {
		return c.Timeout
	}
	return DefaultTimeout
}

func (c *Client) dialTimeout() time.Duration {
	if c.DialTimeout != 0 {
		return c.DialTimeout
	}
	// Fall back to Timeout for backward compatibility
	return c.netTimeout()
}

func (c *Client) maxIdleConns() int {
	if c.MaxIdleConns > 0 {
		return c.MaxIdleConns
	}
	return DefaultMaxIdleConns
}

// ConnectTimeoutError is the error type used when it takes
// too long to connect to the desired host. This level of
// detail can generally be ignored.
type ConnectTimeoutError struct {
	Addr net.Addr
}

func (cte *ConnectTimeoutError) Error() string {
	return "memcache: connect timeout to " + cte.Addr.String()
}

// useSplitTimeouts reports whether the caller configured independent connect
// and handshake budgets. When false, dial uses the legacy single-budget path.
func (c *Client) useSplitTimeouts() bool {
	return c.ConnectTimeout != 0 || c.HandshakeTimeout != 0
}

// connectTimeout is the TCP-connect budget for the split-timeout path. It falls
// back to dialTimeout() when ConnectTimeout is unset so a caller can configure
// only HandshakeTimeout and still get a sane connect bound.
func (c *Client) connectTimeout() time.Duration {
	if c.ConnectTimeout != 0 {
		return c.ConnectTimeout
	}
	return c.dialTimeout()
}

// handshakeTimeout is the TLS-handshake budget for the split-timeout path. It
// falls back to dialTimeout() when HandshakeTimeout is unset.
func (c *Client) handshakeTimeout() time.Duration {
	if c.HandshakeTimeout != 0 {
		return c.HandshakeTimeout
	}
	return c.dialTimeout()
}

func (c *Client) dial(addr net.Addr) (net.Conn, error) {
	if c.useSplitTimeouts() {
		return c.dialSplit(addr)
	}
	return c.dialLegacy(addr)
}

// dialLegacy preserves the original behavior: a single dialer Timeout covers
// both the TCP connection and (for TLS) the handshake.
func (c *Client) dialLegacy(addr net.Addr) (net.Conn, error) {
	start := time.Now()
	var (
		nc  net.Conn
		err error
	)
	nd := net.Dialer{Timeout: c.dialTimeout()}
	if c.TlsConfig != nil {
		nc, err = tls.DialWithDialer(&nd, addr.Network(), addr.String(), c.TlsConfig)
	} else {
		nc, err = nd.Dial(addr.Network(), addr.String())
	}
	err = c.normalizeDialErr(addr, err)
	c.reportDial(DialInfo{
		Addr:            addr,
		TLS:             c.TlsConfig != nil,
		ConnectDuration: time.Since(start),
		Resumed:         resumedFrom(nc, err),
		Err:             err,
	})
	if err != nil {
		return nil, err
	}
	return nc, nil
}

// dialSplit budgets the TCP connect and the TLS handshake independently, so a
// slow handshake (e.g. a CPU-bound server) does not consume the connect budget
// and a tight connect budget can fail a dead host fast without aborting healthy
// but slow handshakes.
func (c *Client) dialSplit(addr net.Addr) (net.Conn, error) {
	connectStart := time.Now()
	nd := net.Dialer{Timeout: c.connectTimeout()}
	rawConn, err := nd.Dial(addr.Network(), addr.String())
	connectDur := time.Since(connectStart)
	if err != nil {
		err = c.normalizeDialErr(addr, err)
		c.reportDial(DialInfo{Addr: addr, TLS: c.TlsConfig != nil, ConnectDuration: connectDur, Err: err})
		return nil, err
	}

	// Non-TLS: nothing more to do.
	if c.TlsConfig == nil {
		c.reportDial(DialInfo{Addr: addr, ConnectDuration: connectDur})
		return rawConn, nil
	}

	// TLS: run the handshake under its own deadline.
	handshakeStart := time.Now()
	tlsConn := tls.Client(rawConn, c.TlsConfig)
	if dl := c.handshakeTimeout(); dl > 0 {
		_ = tlsConn.SetDeadline(time.Now().Add(dl))
	}
	herr := tlsConn.Handshake()
	handshakeDur := time.Since(handshakeStart)
	// Clear the handshake deadline; per-op deadlines are managed elsewhere.
	_ = tlsConn.SetDeadline(time.Time{})
	if herr != nil {
		_ = tlsConn.Close()
		herr = c.normalizeDialErr(addr, herr)
		c.reportDial(DialInfo{
			Addr:              addr,
			TLS:               true,
			ConnectDuration:   connectDur,
			HandshakeDuration: handshakeDur,
			Err:               herr,
		})
		return nil, herr
	}
	c.reportDial(DialInfo{
		Addr:              addr,
		TLS:               true,
		ConnectDuration:   connectDur,
		HandshakeDuration: handshakeDur,
		Resumed:           tlsConn.ConnectionState().DidResume,
	})
	return tlsConn, nil
}

// normalizeDialErr maps a timeout to ConnectTimeoutError, matching legacy
// behavior, and passes other errors through unchanged.
func (c *Client) normalizeDialErr(addr net.Addr, err error) error {
	if err == nil {
		return nil
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return &ConnectTimeoutError{addr}
	}
	return err
}

// reportDial invokes the OnDial hook (if configured) on a separate goroutine so
// a slow hook cannot add latency to the dial path. A panic in the hook is
// recovered so it cannot crash the spawned goroutine (and thus the process).
func (c *Client) reportDial(info DialInfo) {
	hook := c.OnDial
	if hook == nil {
		return
	}
	go func() {
		defer func() { _ = recover() }()
		hook(info)
	}()
}

// resumedFrom reports whether a successful TLS connection resumed a session.
// Returns false for failures or non-TLS connections.
func resumedFrom(nc net.Conn, err error) bool {
	if err != nil || nc == nil {
		return false
	}
	if tc, ok := nc.(*tls.Conn); ok {
		return tc.ConnectionState().DidResume
	}
	return false
}

func (c *Client) getConn(addr net.Addr) (*conn, error) {
	cn, ok := c.getFreeConn(addr)
	if ok {
		cn.extendDeadline()
		return cn, nil
	}
	nc, err := c.dial(addr)
	if err != nil {
		return nil, err
	}
	cn = &conn{
		nc:   nc,
		addr: addr,
		rw:   bufio.NewReadWriter(bufio.NewReader(nc), bufio.NewWriter(nc)),
		c:    c,
	}
	cn.extendDeadline()
	return cn, nil
}

func (c *Client) onItem(item *Item, fn func(*Client, *bufio.ReadWriter, *Item) error) error {
	addr, err := c.selector.PickServer(item.Key)
	if err != nil {
		return err
	}
	cn, err := c.getConn(addr)
	if err != nil {
		return err
	}
	defer cn.condRelease(&err)
	if err = fn(c, cn.rw, item); err != nil {
		return err
	}
	return nil
}

func (c *Client) FlushAll() error {
	return c.selector.Each(c.flushAllFromAddr)
}

// Get gets the item for the given key. ErrCacheMiss is returned for a
// memcache cache miss. The key must be at most 250 bytes in length.
func (c *Client) Get(key string) (item *Item, err error) {
	err = c.withKeyAddr(key, func(addr net.Addr) error {
		return c.getFromAddr(addr, []string{key}, func(it *Item) { item = it })
	})
	if err == nil && item == nil {
		err = ErrCacheMiss
	}
	return
}

// Touch updates the expiry for the given key. The seconds parameter is either
// a Unix timestamp or, if seconds is less than 1 month, the number of seconds
// into the future at which time the item will expire. Zero means the item has
// no expiration time. ErrCacheMiss is returned if the key is not in the cache.
// The key must be at most 250 bytes in length.
func (c *Client) Touch(key string, seconds int32) (err error) {
	return c.withKeyAddr(key, func(addr net.Addr) error {
		return c.touchFromAddr(addr, []string{key}, seconds)
	})
}

func (c *Client) withKeyAddr(key string, fn func(net.Addr) error) (err error) {
	if !legalKey(key) {
		return ErrMalformedKey
	}
	addr, err := c.selector.PickServer(key)
	if err != nil {
		return err
	}
	return fn(addr)
}

func (c *Client) withAddrRw(addr net.Addr, fn func(*bufio.ReadWriter) error) (err error) {
	cn, err := c.getConn(addr)
	if err != nil {
		return err
	}
	defer cn.condRelease(&err)
	return fn(cn.rw)
}

func (c *Client) withKeyRw(key string, fn func(*bufio.ReadWriter) error) error {
	return c.withKeyAddr(key, func(addr net.Addr) error {
		return c.withAddrRw(addr, fn)
	})
}

func (c *Client) getFromAddr(addr net.Addr, keys []string, cb func(*Item)) error {
	return c.withAddrRw(addr, func(rw *bufio.ReadWriter) error {
		if _, err := fmt.Fprintf(rw, "gets %s\r\n", strings.Join(keys, " ")); err != nil {
			return err
		}
		if err := rw.Flush(); err != nil {
			return err
		}
		if err := parseGetResponse(rw.Reader, cb); err != nil {
			return err
		}
		return nil
	})
}

// flushAllFromAddr send the flush_all command to the given addr
func (c *Client) flushAllFromAddr(addr net.Addr) error {
	return c.withAddrRw(addr, func(rw *bufio.ReadWriter) error {
		if _, err := fmt.Fprintf(rw, "flush_all\r\n"); err != nil {
			return err
		}
		if err := rw.Flush(); err != nil {
			return err
		}
		line, err := rw.ReadSlice('\n')
		if err != nil {
			return err
		}
		switch {
		case bytes.Equal(line, resultOk):
			break
		default:
			return fmt.Errorf("memcache: unexpected response line from flush_all: %q", string(line))
		}
		return nil
	})
}

// ping sends the version command to the given addr
func (c *Client) ping(addr net.Addr) error {
	return c.withAddrRw(addr, func(rw *bufio.ReadWriter) error {
		if _, err := fmt.Fprintf(rw, "version\r\n"); err != nil {
			return err
		}
		if err := rw.Flush(); err != nil {
			return err
		}
		line, err := rw.ReadSlice('\n')
		if err != nil {
			return err
		}

		switch {
		case bytes.HasPrefix(line, versionPrefix):
			break
		default:
			return fmt.Errorf("memcache: unexpected response line from ping: %q", string(line))
		}
		return nil
	})
}

func (c *Client) touchFromAddr(addr net.Addr, keys []string, expiration int32) error {
	return c.withAddrRw(addr, func(rw *bufio.ReadWriter) error {
		for _, key := range keys {
			if _, err := fmt.Fprintf(rw, "touch %s %d\r\n", key, expiration); err != nil {
				return err
			}
			if err := rw.Flush(); err != nil {
				return err
			}
			line, err := rw.ReadSlice('\n')
			if err != nil {
				return err
			}
			switch {
			case bytes.Equal(line, resultTouched):
				break
			case bytes.Equal(line, resultNotFound):
				return ErrCacheMiss
			default:
				return fmt.Errorf("memcache: unexpected response line from touch: %q", string(line))
			}
		}
		return nil
	})
}

// GetMulti is a batch version of Get. The returned map from keys to
// items may have fewer elements than the input slice, due to memcache
// cache misses. Each key must be at most 250 bytes in length.
// If no error is returned, the returned map will also be non-nil.
func (c *Client) GetMulti(keys []string) (map[string]*Item, error) {
	var lk sync.Mutex
	m := make(map[string]*Item)
	addItemToMap := func(it *Item) {
		lk.Lock()
		defer lk.Unlock()
		m[it.Key] = it
	}

	keyMap := make(map[net.Addr][]string)
	for _, key := range keys {
		if !legalKey(key) {
			return nil, ErrMalformedKey
		}
		addr, err := c.selector.PickServer(key)
		if err != nil {
			return nil, err
		}
		keyMap[addr] = append(keyMap[addr], key)
	}

	ch := make(chan error, buffered)
	for addr, keys := range keyMap {
		go func(addr net.Addr, keys []string) {
			ch <- c.getFromAddr(addr, keys, addItemToMap)
		}(addr, keys)
	}

	var err error
	for _ = range keyMap {
		if ge := <-ch; ge != nil {
			err = ge
		}
	}
	return m, err
}

// parseGetResponse reads a GET response from r and calls cb for each
// read and allocated Item
func parseGetResponse(r *bufio.Reader, cb func(*Item)) error {
	for {
		line, err := r.ReadSlice('\n')
		if err != nil {
			return err
		}
		if bytes.Equal(line, resultEnd) {
			return nil
		}
		it := new(Item)
		size, err := scanGetResponseLine(line, it)
		if err != nil {
			return err
		}
		it.Value = make([]byte, size+2)
		_, err = io.ReadFull(r, it.Value)
		if err != nil {
			it.Value = nil
			return err
		}
		if !bytes.HasSuffix(it.Value, crlf) {
			it.Value = nil
			return fmt.Errorf("memcache: corrupt get result read")
		}
		it.Value = it.Value[:size]
		cb(it)
	}
}

// scanGetResponseLine populates it and returns the declared size of the item.
// It does not read the bytes of the item.
func scanGetResponseLine(line []byte, it *Item) (size int, err error) {
	pattern := "VALUE %s %d %d %d\r\n"
	dest := []interface{}{&it.Key, &it.Flags, &size, &it.casid}
	if bytes.Count(line, space) == 3 {
		pattern = "VALUE %s %d %d\r\n"
		dest = dest[:3]
	}
	n, err := fmt.Sscanf(string(line), pattern, dest...)
	if err != nil || n != len(dest) {
		return -1, fmt.Errorf("memcache: unexpected line in get response: %q", line)
	}
	return size, nil
}

// Set writes the given item, unconditionally.
func (c *Client) Set(item *Item) error {
	return c.onItem(item, (*Client).set)
}

func (c *Client) set(rw *bufio.ReadWriter, item *Item) error {
	return c.populateOne(rw, "set", item)
}

// Add writes the given item, if no value already exists for its
// key. ErrNotStored is returned if that condition is not met.
func (c *Client) Add(item *Item) error {
	return c.onItem(item, (*Client).add)
}

func (c *Client) add(rw *bufio.ReadWriter, item *Item) error {
	return c.populateOne(rw, "add", item)
}

// Replace writes the given item, but only if the server *does*
// already hold data for this key
func (c *Client) Replace(item *Item) error {
	return c.onItem(item, (*Client).replace)
}

func (c *Client) replace(rw *bufio.ReadWriter, item *Item) error {
	return c.populateOne(rw, "replace", item)
}

// Append appends the given item to the existing item, if a value already
// exists for its key. ErrNotStored is returned if that condition is not met.
func (c *Client) Append(item *Item) error {
	return c.onItem(item, (*Client).append)
}

func (c *Client) append(rw *bufio.ReadWriter, item *Item) error {
	return c.populateOne(rw, "append", item)
}

// Prepend prepends the given item to the existing item, if a value already
// exists for its key. ErrNotStored is returned if that condition is not met.
func (c *Client) Prepend(item *Item) error {
	return c.onItem(item, (*Client).prepend)
}

func (c *Client) prepend(rw *bufio.ReadWriter, item *Item) error {
	return c.populateOne(rw, "prepend", item)
}

// CompareAndSwap writes the given item that was previously returned
// by Get, if the value was neither modified or evicted between the
// Get and the CompareAndSwap calls. The item's Key should not change
// between calls but all other item fields may differ. ErrCASConflict
// is returned if the value was modified in between the
// calls. ErrNotStored is returned if the value was evicted in between
// the calls.
func (c *Client) CompareAndSwap(item *Item) error {
	return c.onItem(item, (*Client).cas)
}

func (c *Client) cas(rw *bufio.ReadWriter, item *Item) error {
	return c.populateOne(rw, "cas", item)
}

func (c *Client) populateOne(rw *bufio.ReadWriter, verb string, item *Item) error {
	if !legalKey(item.Key) {
		return ErrMalformedKey
	}
	var err error
	if verb == "cas" {
		_, err = fmt.Fprintf(rw, "%s %s %d %d %d %d\r\n",
			verb, item.Key, item.Flags, item.Expiration, len(item.Value), item.casid)
	} else {
		_, err = fmt.Fprintf(rw, "%s %s %d %d %d\r\n",
			verb, item.Key, item.Flags, item.Expiration, len(item.Value))
	}
	if err != nil {
		return err
	}
	if _, err = rw.Write(item.Value); err != nil {
		return err
	}
	if _, err := rw.Write(crlf); err != nil {
		return err
	}
	if err := rw.Flush(); err != nil {
		return err
	}
	line, err := rw.ReadSlice('\n')
	if err != nil {
		return err
	}
	switch {
	case bytes.Equal(line, resultStored):
		return nil
	case bytes.Equal(line, resultNotStored):
		return ErrNotStored
	case bytes.Equal(line, resultExists):
		return ErrCASConflict
	case bytes.Equal(line, resultNotFound):
		return ErrCacheMiss
	}
	return fmt.Errorf("memcache: unexpected response line from %q: %q", verb, string(line))
}

func writeReadLine(rw *bufio.ReadWriter, format string, args ...interface{}) ([]byte, error) {
	_, err := fmt.Fprintf(rw, format, args...)
	if err != nil {
		return nil, err
	}
	if err := rw.Flush(); err != nil {
		return nil, err
	}
	line, err := rw.ReadSlice('\n')
	return line, err
}

func writeExpectf(rw *bufio.ReadWriter, expect []byte, format string, args ...interface{}) error {
	line, err := writeReadLine(rw, format, args...)
	if err != nil {
		return err
	}
	switch {
	case bytes.Equal(line, resultOK):
		return nil
	case bytes.Equal(line, expect):
		return nil
	case bytes.Equal(line, resultNotStored):
		return ErrNotStored
	case bytes.Equal(line, resultExists):
		return ErrCASConflict
	case bytes.Equal(line, resultNotFound):
		return ErrCacheMiss
	}
	return fmt.Errorf("memcache: unexpected response line: %q", string(line))
}

// Delete deletes the item with the provided key. The error ErrCacheMiss is
// returned if the item didn't already exist in the cache.
func (c *Client) Delete(key string) error {
	return c.withKeyRw(key, func(rw *bufio.ReadWriter) error {
		return writeExpectf(rw, resultDeleted, "delete %s\r\n", key)
	})
}

// DeleteAll deletes all items in the cache.
func (c *Client) DeleteAll() error {
	return c.withKeyRw("", func(rw *bufio.ReadWriter) error {
		return writeExpectf(rw, resultDeleted, "flush_all\r\n")
	})
}

// Ping checks all instances if they are alive. Returns error if any
// of them is down.
func (c *Client) Ping() error {
	return c.selector.Each(c.ping)
}

// Increment atomically increments key by delta. The return value is
// the new value after being incremented or an error. If the value
// didn't exist in memcached the error is ErrCacheMiss. The value in
// memcached must be an decimal number, or an error will be returned.
// On 64-bit overflow, the new value wraps around.
func (c *Client) Increment(key string, delta uint64) (newValue uint64, err error) {
	return c.incrDecr("incr", key, delta)
}

// Decrement atomically decrements key by delta. The return value is
// the new value after being decremented or an error. If the value
// didn't exist in memcached the error is ErrCacheMiss. The value in
// memcached must be an decimal number, or an error will be returned.
// On underflow, the new value is capped at zero and does not wrap
// around.
func (c *Client) Decrement(key string, delta uint64) (newValue uint64, err error) {
	return c.incrDecr("decr", key, delta)
}

func (c *Client) incrDecr(verb, key string, delta uint64) (uint64, error) {
	var val uint64
	err := c.withKeyRw(key, func(rw *bufio.ReadWriter) error {
		line, err := writeReadLine(rw, "%s %s %d\r\n", verb, key, delta)
		if err != nil {
			return err
		}
		switch {
		case bytes.Equal(line, resultNotFound):
			return ErrCacheMiss
		case bytes.HasPrefix(line, resultClientErrorPrefix):
			errMsg := line[len(resultClientErrorPrefix) : len(line)-2]
			return errors.New("memcache: client error: " + string(errMsg))
		}
		val, err = strconv.ParseUint(string(line[:len(line)-2]), 10, 64)
		if err != nil {
			return err
		}
		return nil
	})
	return val, err
}

// Close closes any open connections.
//
// It returns the first error encountered closing connections, but always
// closes all connections.
//
// After Close, the Client may still be used.
func (c *Client) Close() error {
	c.lk.Lock()
	defer c.lk.Unlock()
	var ret error
	for _, conns := range c.freeconn {
		for _, c := range conns {
			if err := c.nc.Close(); err != nil && ret == nil {
				ret = err
			}
		}
	}
	c.freeconn = nil
	return ret
}

func (c *Client) WarmUpPool() int {
	var connReleasedWg, wg, connAcquired sync.WaitGroup
	var connsCreated int
	defer connReleasedWg.Wait()
	wg.Add(1)

	for i := 0; i < c.MaxIdleConns; i++ {
		c.selector.Each(func(addr net.Addr) error {
			connAcquired.Add(1)
			go func() {
				connReleasedWg.Add(1)
				defer connReleasedWg.Done()

				conn, err := c.getConn(addr)
				connAcquired.Done()
				if err != nil {
					fmt.Println(err)
					return
				}

				connsCreated++
				wg.Wait()
				conn.release()
				return
			}()
			return nil
		})
	}

	connAcquired.Wait()
	wg.Done()
	return connsCreated
}
