// Package parser extracts structured fields from raw WHOIS response text.
package parser

import (
	"net"
	"regexp"
	"strings"
	"time"
	"unicode"

	"nettools/http2whois/internal/whoisclient/result"
)

// dateLayouts contains common date formats found in WHOIS responses.
var dateLayouts = []string{
	time.RFC3339,
	"2006-01-02T15:04:05Z",
	"2006-01-02T15:04:05.999999999Z",
	"2006-01-02 15:04:05",
	"2006-01-02",
	"02-Jan-2006",
	"02/01/2006",
	"01/02/2006",
	"January 2, 2006",
	"02-Jan-2006 15:04:05 MST",
	"2006.01.02",
	"20060102",
}

// fieldMap maps canonical field names to their possible WHOIS key aliases.
var fieldMap = map[string][]string{
	"domainName": {
		"domain name", "domain", "query", "% query",
	},
	"domainID": {
		"registry domain id", "domain id",
	},
	"status": {
		"domain status", "status",
	},
	"nameServer": {
		"name server", "nameserver", "nserver",
	},
	"dnssec": {
		"dnssec",
	},
	"registrar": {
		"registrar", "sponsoring registrar",
	},
	"registrarURL": {
		"registrar url", "registrar website",
	},
	"registrarIANAID": {
		"registrar iana id", "iana id",
	},
	"registrarWhoisServer": {
		"registrar whois server",
	},
	"registrarAbuseEmail": {
		"registrar abuse contact email",
	},
	"registrarAbusePhone": {
		"registrar abuse contact phone",
	},
	"created": {
		"creation date", "created", "created on", "domain registration date",
		"registration time", "registered", "registered on",
	},
	"updated": {
		"updated date", "last updated", "last-modified", "last modified",
		"modified", "changed",
	},
	"expires": {
		"expiry date", "expiration date", "registry expiry date",
		"registrar registration expiration date", "expire date",
		"paid-till", "renewal date", "expires on",
	},
	// IP / network fields
	"network":   {"inetnum", "inet6num", "netrange", "cidr"},
	"netName":   {"netname", "net-name"},
	"netHandle": {"nethandle", "net-handle"},
	"parent":    {"parent"},
	"netType":   {"nettype", "net-type"},
	"origin":    {"origin"},
	"asName":    {"as-name", "asname"},
	"asDesc":    {"descr", "description"},
}

// contactPrefixes maps field prefix to the contact role.
var contactPrefixes = []struct {
	prefix string
	role   string
}{
	{"registrant", "registrant"},
	{"admin", "admin"},
	{"administrative", "admin"},
	{"tech", "tech"},
	{"technical", "tech"},
}

// availabilityPatterns indicate a domain is NOT registered.
var availabilityPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)no match`),
	regexp.MustCompile(`(?i)not found`),
	regexp.MustCompile(`(?i)no entries found`),
	regexp.MustCompile(`(?i)status:\s*available`),
	regexp.MustCompile(`(?i)the domain has not been registered`),
	regexp.MustCompile(`(?i)no matching record`),
	regexp.MustCompile(`(?i)domain not found`),
	regexp.MustCompile(`(?i)object does not exist`),
	regexp.MustCompile(`(?i)^%\s*no such domain`),
}

// Parse builds a Result from one or more raw WHOIS responses.
// The last response (deepest referral) is given the most weight for structured fields.
func Parse(query, queryType string, responses []struct{ Server, Text string }) *result.Result {
	r := &result.Result{
		Query:     query,
		QueryType: queryType,
	}

	if len(responses) == 0 {
		return r
	}

	// Collect raw data
	for _, resp := range responses {
		r.RawData = append(r.RawData, resp.Text)
	}
	r.WhoisServer = responses[0].Server

	// Use ALL response layers merged for field extraction;
	// later values override earlier ones for scalar fields.
	fields := make(map[string][]string)
	for _, resp := range responses {
		parseLines(resp.Text, fields)
	}

	// Check availability first on the first (authoritative) layer
	firstText := responses[0].Text
	for _, re := range availabilityPatterns {
		if re.MatchString(firstText) {
			r.Available = true
			return r
		}
	}

	// Populate scalar and list fields
	r.DomainName = first(fields["domainName"])
	r.DomainID = first(fields["domainID"])
	r.Status = dedup(fields["status"])
	r.NameServers = dedup(normalizeHosts(fields["nameServer"]))
	r.DNSSEC = first(fields["dnssec"])
	r.Registrar = first(fields["registrar"])
	r.RegistrarURL = first(fields["registrarURL"])
	r.RegistrarIANAID = first(fields["registrarIANAID"])
	r.RegistrarWhoisServer = first(fields["registrarWhoisServer"])
	r.RegistrarAbuseEmail = first(fields["registrarAbuseEmail"])
	r.RegistrarAbusePhone = first(fields["registrarAbusePhone"])

	// Dates
	r.Created = parseDate(first(fields["created"]))
	r.Updated = parseDate(first(fields["updated"]))
	r.Expires = parseDate(first(fields["expires"]))

	// IP / ASN fields
	r.Network = first(fields["network"])
	r.NetName = first(fields["netName"])
	r.NetHandle = first(fields["netHandle"])
	r.Parent = first(fields["parent"])
	r.NetType = first(fields["netType"])
	r.Origin = first(fields["origin"])
	r.ASName = first(fields["asName"])
	r.ASDesc = first(fields["asDesc"])
	r.Routes = dedup(fields["routes"])

	// Contacts - extracted from each response layer
	for _, resp := range responses {
		extractContacts(resp.Text, r)
	}

	return r
}

// parseLines scans a raw WHOIS text and fills the fields map.
func parseLines(text string, fields map[string][]string) {
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:idx]))
		val := strings.TrimSpace(line[idx+1:])
		if val == "" {
			continue
		}
		canonical := canonicalize(key)
		if canonical != "" {
			fields[canonical] = append(fields[canonical], val)
		}
	}
}

// canonicalize maps a raw WHOIS key to a canonical field name.
func canonicalize(key string) string {
	key = strings.ToLower(strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) || r == '-' || r == '_' {
			return ' '
		}
		return r
	}, key))
	key = strings.Join(strings.Fields(key), " ")

	for canonical, aliases := range fieldMap {
		for _, alias := range aliases {
			if key == alias {
				return canonical
			}
		}
	}
	return ""
}

// extractContacts parses registrant/admin/tech contact blocks.
func extractContacts(text string, r *result.Result) {
	lines := strings.Split(text, "\n")
	for i, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "%") {
			continue
		}
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:idx]))
		val := strings.TrimSpace(line[idx+1:])
		if val == "" {
			continue
		}

		for _, cp := range contactPrefixes {
			if !strings.HasPrefix(key, cp.prefix) {
				continue
			}
			suffix := strings.TrimPrefix(key, cp.prefix)
			suffix = strings.TrimSpace(strings.TrimPrefix(suffix, " "))

			c := getContact(r, cp.role)
			_ = i // could use for block parsing

			switch suffix {
			case "name", " name":
				if c.Name == "" {
					c.Name = val
				}
			case "organization", " organization", "org", " org":
				if c.Organization == "" {
					c.Organization = val
				}
			case "email", " email":
				if c.Email == "" {
					c.Email = strings.ToLower(val)
				}
			case "phone", " phone":
				if c.Phone == "" {
					c.Phone = val
				}
			case "fax", " fax":
				if c.Fax == "" {
					c.Fax = val
				}
			case "street", " street":
				if c.Street == "" {
					c.Street = val
				}
			case "city", " city":
				if c.City == "" {
					c.City = val
				}
			case "state/province", " state/province", "state", " state":
				if c.State == "" {
					c.State = val
				}
			case "postal code", " postal code":
				if c.PostalCode == "" {
					c.PostalCode = val
				}
			case "country", " country":
				if c.Country == "" {
					c.Country = val
				}
			}
			setContact(r, cp.role, c)
		}
	}
}

func getContact(r *result.Result, role string) result.Contact {
	switch role {
	case "registrant":
		if r.Registrant != nil {
			return *r.Registrant
		}
	case "admin":
		if r.Admin != nil {
			return *r.Admin
		}
	case "tech":
		if r.Tech != nil {
			return *r.Tech
		}
	}
	return result.Contact{}
}

func setContact(r *result.Result, role string, c result.Contact) {
	switch role {
	case "registrant":
		r.Registrant = &c
	case "admin":
		r.Admin = &c
	case "tech":
		r.Tech = &c
	}
}

// parseDate tries each known layout until one succeeds.
func parseDate(s string) *time.Time {
	if s == "" {
		return nil
	}
	// Trim timezone info that Go can't parse generically
	s = strings.TrimSpace(s)
	// Strip trailing Z offset variants
	s = regexp.MustCompile(`\s*\(.*\)\s*$`).ReplaceAllString(s, "")
	s = strings.TrimSpace(s)

	for _, layout := range dateLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return &t
		}
	}
	return nil
}

// first returns the first non-empty element of a slice.
func first(ss []string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

// dedup removes duplicate entries preserving order.
func dedup(ss []string) []string {
	seen := make(map[string]bool)
	out := ss[:0]
	for _, s := range ss {
		k := strings.ToLower(s)
		if !seen[k] {
			seen[k] = true
			out = append(out, s)
		}
	}
	return out
}

// normalizeHosts lowercases and strips trailing dots from DNS names.
func normalizeHosts(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		s = strings.ToLower(strings.TrimSpace(s))
		s = strings.TrimSuffix(s, ".")
		// Strip port if present in nameserver line
		if host, _, err := net.SplitHostPort(s); err == nil {
			s = host
		}
		out[i] = s
	}
	return out
}
