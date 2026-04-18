package parser_test

import (
	"testing"
	"time"

	"nettools/http2whois/internal/whoisclient/parser"
)

type response = struct{ Server, Text string }

func adapt(server, text string) response {
	return response{Server: server, Text: text}
}

// Minimal .com WHOIS fixture
const comWhois = `
Domain Name: EXAMPLE.COM
Registry Domain ID: 2336799_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.markmonitor.com
Registrar URL: http://www.markmonitor.com
Updated Date: 2023-08-14T07:01:38Z
Creation Date: 1995-08-14T04:00:00Z
Registry Expiry Date: 2024-08-13T04:00:00Z
Registrar: MarkMonitor Inc.
Registrar IANA ID: 292
Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
Name Server: A.IANA-SERVERS.NET
Name Server: B.IANA-SERVERS.NET
DNSSEC: signedDelegation
`

func TestParseComDomain(t *testing.T) {
	r := parser.Parse("example.com", "domain", []response{adapt("whois.verisign-grs.com", comWhois)})

	if r.DomainName != "EXAMPLE.COM" {
		t.Errorf("DomainName = %q, want EXAMPLE.COM", r.DomainName)
	}
	if r.Registrar != "MarkMonitor Inc." {
		t.Errorf("Registrar = %q, want MarkMonitor Inc.", r.Registrar)
	}
	if len(r.NameServers) != 2 {
		t.Errorf("NameServers len = %d, want 2", len(r.NameServers))
	}
	if r.NameServers[0] != "a.iana-servers.net" {
		t.Errorf("NameServer[0] = %q, want a.iana-servers.net", r.NameServers[0])
	}
	if r.DNSSEC != "signedDelegation" {
		t.Errorf("DNSSEC = %q, want signedDelegation", r.DNSSEC)
	}
	if r.Available {
		t.Error("Available should be false")
	}
	if r.Created == nil {
		t.Fatal("Created is nil")
	}
	want := time.Date(1995, 8, 14, 4, 0, 0, 0, time.UTC)
	if !r.Created.Equal(want) {
		t.Errorf("Created = %v, want %v", r.Created, want)
	}
}

const notFoundWhois = `
% This is the AFNIC WHOIS server.
No match for "notexist.com".
`

func TestAvailable(t *testing.T) {
	r := parser.Parse("notexist.com", "domain", []response{adapt("whois.example.com", notFoundWhois)})
	if !r.Available {
		t.Error("expected Available = true for not-found response")
	}
}

const contactWhois = `
Domain Name: EXAMPLE.COM
Creation Date: 2000-01-01T00:00:00Z
Registrant Name: John Doe
Registrant Organization: Example Inc.
Registrant Email: john@example.com
Registrant Country: US
Admin Name: Admin User
Admin Email: admin@example.com
Tech Name: Tech User
Tech Email: tech@example.com
`

func TestContacts(t *testing.T) {
	r := parser.Parse("example.com", "domain", []response{adapt("whois.example.com", contactWhois)})

	if r.Registrant == nil {
		t.Fatal("Registrant is nil")
	}
	if r.Registrant.Name != "John Doe" {
		t.Errorf("Registrant.Name = %q", r.Registrant.Name)
	}
	if r.Registrant.Email != "john@example.com" {
		t.Errorf("Registrant.Email = %q", r.Registrant.Email)
	}
	if r.Admin == nil || r.Admin.Email != "admin@example.com" {
		t.Error("Admin contact not parsed correctly")
	}
	if r.Tech == nil || r.Tech.Name != "Tech User" {
		t.Error("Tech contact not parsed correctly")
	}
}

const ipWhois = `
NetRange:  93.184.216.0 - 93.184.216.255
CIDR:      93.184.216.0/24
NetName:   EDGECAST-NETBLK-03
NetHandle: NET-93-184-216-0-1
NetType:   Direct Assignment
`

func TestIPResult(t *testing.T) {
	r := parser.Parse("93.184.216.34", "ipv4", []response{adapt("whois.arin.net", ipWhois)})
	if r.NetName != "EDGECAST-NETBLK-03" {
		t.Errorf("NetName = %q", r.NetName)
	}
	if r.Network != "93.184.216.0/24" {
		t.Errorf("Network = %q", r.Network)
	}
}
