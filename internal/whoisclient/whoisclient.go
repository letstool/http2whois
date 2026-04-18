// Package whoisparser provides WHOIS lookups for domains, IPv4/IPv6 addresses
// and AS numbers. It follows referral chains automatically and returns
// structured data.
//
// Basic usage:
//
//	p := whoisparser.New()
//	r, err := p.Lookup(context.Background(), "example.com")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Println(r.Registrar, r.Expires)
package whoisclient

import (
	"context"
	"net"
	"strings"
	"time"

	"nettools/http2whois/internal/whoisclient/parser"
	"nettools/http2whois/internal/whoisclient/query"
	"nettools/http2whois/internal/whoisclient/result"
	"nettools/http2whois/internal/whoisclient/servers"
)

// Parser is the main entry point for WHOIS lookups.
type Parser struct {
	opts         query.Options
	specialWhois map[string]servers.Server // TLD or IP-prefix overrides
}

// Option is a functional option for Parser.
type Option func(*Parser)

// WithTimeout sets the per-query socket timeout (default 10 s).
func WithTimeout(d time.Duration) Option {
	return func(p *Parser) { p.opts.Timeout = d }
}

// WithSpecialWhois registers a custom WHOIS server for a TLD or IP prefix.
//
//	p := whoisparser.New(
//	    whoisparser.WithSpecialWhois("it", whoisparser.CustomServer{
//	        Host:   "whois.nic.it",
//	        Port:   43,
//	        Format: "-u user -w pass %s",
//	    }),
//	)
func WithSpecialWhois(tld string, s CustomServer) Option {
	return func(p *Parser) {
		p.specialWhois[strings.ToLower(tld)] = servers.Server{
			Host:   s.Host,
			Port:   s.Port,
			Format: s.Format,
		}
	}
}

// CustomServer lets callers override the WHOIS server for a TLD.
type CustomServer struct {
	Host   string
	Port   int    // 0 -> 43
	Format string // query format; %s replaced by query
}

// New creates a Parser with the provided options.
func New(opts ...Option) *Parser {
	p := &Parser{
		opts:         query.DefaultOptions(),
		specialWhois: make(map[string]servers.Server),
	}
	for _, o := range opts {
		o(p)
	}
	return p
}

// Lookup performs a WHOIS lookup for the given target.
// The target may be:
//   - a domain name         ("example.com", "xn--bcher-kva.example")
//   - an IPv4 address       ("93.184.216.34")
//   - an IPv6 address       ("2606:2800:220:1:248:1893:25c8:1946")
//   - an AS number          ("AS15169", "AS 15169", "15169")
func (p *Parser) Lookup(ctx context.Context, target string) (*result.Result, error) {
	target = strings.TrimSpace(target)
	qType, server := p.resolve(target)

	responses, err := query.Lookup(ctx, target, server, p.opts)
	if err != nil {
		return nil, err
	}

	// Convert query.Response to what the parser expects
	adapted := make([]struct{ Server, Text string }, len(responses))
	for i, r := range responses {
		adapted[i].Server = r.Server
		adapted[i].Text = r.Text
	}

	return parser.Parse(target, qType, adapted), nil
}

// resolve identifies query type and selects the initial WHOIS server.
func (p *Parser) resolve(target string) (string, servers.Server) {
	// ASN?
	upper := strings.ToUpper(target)
	if strings.HasPrefix(upper, "AS") || isASN(target) {
		return "asn", servers.ASNServer
	}

	// IP address?
	if ip := net.ParseIP(target); ip != nil {
		if ip.To4() != nil {
			return "ipv4", servers.RIRServers["arin"]
		}
		return "ipv6", servers.RIRServers["ripe"]
	}

	// Domain: check custom overrides first
	parts := strings.Split(strings.ToLower(target), ".")
	tld := ""
	if len(parts) >= 2 {
		tld = parts[len(parts)-1]
		if len(parts) >= 3 {
			twoLevel := parts[len(parts)-2] + "." + tld
			if s, ok := p.specialWhois[twoLevel]; ok {
				return "domain", s
			}
		}
	}
	if s, ok := p.specialWhois[tld]; ok {
		return "domain", s
	}

	return "domain", servers.ForDomain(target)
}

// isASN returns true if the string looks like a bare AS number.
func isASN(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(s) > 0
}
