// Package query handles the low-level WHOIS TCP queries and referral chain following.
package query

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"nettools/http2whois/internal/whoisclient/servers"
)

const (
	defaultTimeout    = 10 * time.Second
	maxReferralDepth  = 5
	referralBufSize   = 65536
)

// Options configures a WHOIS query.
type Options struct {
	Timeout      time.Duration
	FollowRefErr bool // return partial result if referral fails
}

// DefaultOptions returns sensible defaults.
func DefaultOptions() Options {
	return Options{
		Timeout:      defaultTimeout,
		FollowRefErr: true,
	}
}

// Response holds the raw text returned by a single WHOIS server.
type Response struct {
	Server string
	Text   string
}

// Lookup performs a WHOIS query for the given target against the specified server,
// then follows referral pointers up to maxReferralDepth times.
// All raw responses are returned in order.
func Lookup(ctx context.Context, target string, server servers.Server, opts Options) ([]Response, error) {
	visited := make(map[string]bool)
	var results []Response

	current := server
	currentTarget := target

	for depth := 0; depth < maxReferralDepth; depth++ {
		if visited[current.Host] {
			break
		}
		visited[current.Host] = true

		text, err := rawQuery(ctx, current, currentTarget, opts.Timeout)
		if err != nil {
			if opts.FollowRefErr && len(results) > 0 {
				break
			}
			return results, fmt.Errorf("whois query to %s: %w", current.Addr(), err)
		}

		results = append(results, Response{Server: current.Host, Text: text})

		// Look for a referral server in the response
		next, found := extractReferral(text)
		if !found || next == "" || next == current.Host {
			break
		}
		current = servers.Server{Host: next}
	}

	return results, nil
}

// rawQuery dials the WHOIS server and returns the full response text.
func rawQuery(ctx context.Context, server servers.Server, target string, timeout time.Duration) (string, error) {
	if timeout == 0 {
		timeout = defaultTimeout
	}

	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	d := &net.Dialer{}
	conn, err := d.DialContext(dialCtx, "tcp", server.Addr())
	if err != nil {
		return "", err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	query := server.QueryString(target)
	if _, err := fmt.Fprint(conn, query); err != nil {
		return "", fmt.Errorf("writing query: %w", err)
	}

	var sb strings.Builder
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, referralBufSize), referralBufSize)
	for scanner.Scan() {
		sb.WriteString(scanner.Text())
		sb.WriteByte('\n')
	}
	if err := scanner.Err(); err != nil {
		// Network EOF is fine - server closed after sending data
		if !strings.Contains(err.Error(), "EOF") {
			return sb.String(), fmt.Errorf("reading response: %w", err)
		}
	}
	return sb.String(), nil
}

// referralPatterns are key prefixes that indicate a better WHOIS server.
var referralPatterns = []string{
	"whois server:",
	"registrar whois server:",
	"refer:",
	"whois:",
	"referral url:",   // sometimes contains http - skip those
}

// extractReferral searches the raw WHOIS text for a referral to another server.
func extractReferral(text string) (string, bool) {
	for _, line := range strings.Split(text, "\n") {
		lower := strings.ToLower(strings.TrimSpace(line))
		for _, pat := range referralPatterns {
			if strings.HasPrefix(lower, pat) {
				value := strings.TrimSpace(line[len(pat):])
				value = strings.TrimSpace(strings.TrimPrefix(value, ":"))
				// Skip HTTP referrals - we only handle port-43 servers
				if strings.HasPrefix(value, "http") {
					continue
				}
				if value != "" {
					return strings.ToLower(value), true
				}
			}
		}
	}
	return "", false
}
