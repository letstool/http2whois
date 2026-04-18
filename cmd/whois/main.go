// cmd/whois/main.go - standalone CLI example for the whoisparser module.
//
// Usage:
//   go run ./cmd/whois example.com
//   go run ./cmd/whois 93.184.216.34
//   go run ./cmd/whois AS15169
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"nettools/http2whois/internal/whoisclient"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: whois <domain|ip|asn>")
		os.Exit(1)
	}

	target := os.Args[1]

	p := whoisclient.New(
		whoisclient.WithTimeout(15 * time.Second),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	r, err := p.Lookup(ctx, target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "lookup error: %v\n", err)
		os.Exit(1)
	}

	// Pretty-print as JSON (excluding raw data for brevity)
	type summary struct {
		Query       string   `json:"query"`
		QueryType   string   `json:"queryType"`
		Available   bool     `json:"available"`
		DomainName  string   `json:"domainName,omitempty"`
		Registrar   string   `json:"registrar,omitempty"`
		Created     string   `json:"created,omitempty"`
		Expires     string   `json:"expires,omitempty"`
		Updated     string   `json:"updated,omitempty"`
		NameServers []string `json:"nameServers,omitempty"`
		Status      []string `json:"status,omitempty"`
		Network     string   `json:"network,omitempty"`
		NetName     string   `json:"netName,omitempty"`
		ASName      string   `json:"asName,omitempty"`
	}

	s := summary{
		Query:       r.Query,
		QueryType:   r.QueryType,
		Available:   r.Available,
		DomainName:  r.DomainName,
		Registrar:   r.Registrar,
		NameServers: r.NameServers,
		Status:      r.Status,
		Network:     r.Network,
		NetName:     r.NetName,
		ASName:      r.ASName,
	}
	if r.Created != nil {
		s.Created = r.Created.Format(time.RFC3339)
	}
	if r.Expires != nil {
		s.Expires = r.Expires.Format(time.RFC3339)
	}
	if r.Updated != nil {
		s.Updated = r.Updated.Format(time.RFC3339)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(s)

	// Also print raw WHOIS text for the first server
	if len(r.RawData) > 0 {
		fmt.Println("\n--- Raw WHOIS (first server) ---")
		fmt.Println(r.RawData[0])
	}
}
