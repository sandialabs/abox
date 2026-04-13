package dnsfilter

import (
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// Resolver is an interface for DNS resolution.
// This abstraction enables mocking DNS queries in tests.
type Resolver interface {
	// Exchange performs a DNS query and returns the response.
	Exchange(m *dns.Msg, address string) (*dns.Msg, error)
}

// DefaultResolver implements Resolver using the miekg/dns package.
type DefaultResolver struct{}

// Exchange performs a DNS query, automatically retrying over TCP if UDP is truncated.
func (r *DefaultResolver) Exchange(m *dns.Msg, address string) (*dns.Msg, error) {
	// 1. Try UDP first (standard practice)
	udpClient := &dns.Client{
		Net:     "udp",
		Timeout: 2 * time.Second,
	}
	resp, _, err := udpClient.Exchange(m, address)

	// 2. If UDP succeeded but was truncated, retry over TCP.
	// RFC 7766: DNS over TCP is mandatory for large responses.
	// Sending TC=1 over TCP is a protocol violation that breaks systemd-resolved.
	if err == nil && resp != nil && resp.Truncated {
		tcpClient := &dns.Client{
			Net:     "tcp",
			Timeout: 2 * time.Second,
		}
		tcpResp, _, tcpErr := tcpClient.Exchange(m, address)
		if tcpErr == nil {
			return tcpResp, nil
		}
		// TCP failed, fall back to truncated UDP response
	}

	return resp, err
}

// resolverHolder wraps a Resolver to allow atomic.Value to store any Resolver type.
// atomic.Value requires consistent types, so we wrap the interface in a struct.
type resolverHolder struct {
	resolver Resolver
}

// resolverValue holds the global Resolver instance with atomic access.
// This prevents race conditions between SetResolver (used in tests) and
// getResolver (used by the server during DNS queries).
var resolverValue atomic.Value

func init() {
	resolverValue.Store(resolverHolder{resolver: &DefaultResolver{}})
}

// getResolver returns the current Resolver instance atomically.
func getResolver() Resolver {
	holder, ok := resolverValue.Load().(resolverHolder)
	if !ok {
		return &DefaultResolver{}
	}
	return holder.resolver
}

// setResolver sets the Resolver instance for test injection.
// Returns the previous Resolver so it can be restored after tests.
// This function is thread-safe.
func setResolver(r Resolver) Resolver {
	prev := getResolver()
	resolverValue.Store(resolverHolder{resolver: r})
	return prev
}

// mockResolver is a Resolver implementation for testing.
type mockResolver struct {
	// ExchangeFunc is called when Exchange is invoked.
	ExchangeFunc func(m *dns.Msg, address string) (*dns.Msg, error)
	// Calls records all query invocations for verification.
	Calls []mockResolverCall
}

// mockResolverCall records a single DNS query invocation.
type mockResolverCall struct {
	Question string
	Address  string
}

// Exchange calls the mock ExchangeFunc or returns nil if not set.
func (m *mockResolver) Exchange(msg *dns.Msg, address string) (*dns.Msg, error) {
	question := ""
	if len(msg.Question) > 0 {
		question = msg.Question[0].Name
	}
	m.Calls = append(m.Calls, mockResolverCall{Question: question, Address: address})
	if m.ExchangeFunc != nil {
		return m.ExchangeFunc(msg, address)
	}
	return nil, nil //nolint:nilnil // nil means no mock function configured
}
