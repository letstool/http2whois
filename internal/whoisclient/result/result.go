// Package result defines the structured output of a WHOIS lookup.
package result

import "time"

// Contact holds registrant / admin / tech contact information.
type Contact struct {
	Handle       string `json:"handle,omitempty"`
	Name         string `json:"name,omitempty"`
	Organization string `json:"organization,omitempty"`
	Email        string `json:"email,omitempty"`
	Phone        string `json:"phone,omitempty"`
	Fax          string `json:"fax,omitempty"`
	Street       string `json:"street,omitempty"`
	City         string `json:"city,omitempty"`
	State        string `json:"state,omitempty"`
	PostalCode   string `json:"postalCode,omitempty"`
	Country      string `json:"country,omitempty"`
}

// Result is the structured output of a WHOIS lookup.
type Result struct {
	// Query metadata
	Query     string `json:"query"`
	QueryType string `json:"queryType"` // "domain", "ipv4", "ipv6", "asn"
	WhoisServer string `json:"whoisServer,omitempty"`

	// Domain fields
	DomainName  string   `json:"domainName,omitempty"`
	DomainID    string   `json:"domainID,omitempty"`
	Status      []string `json:"status,omitempty"`
	NameServers []string `json:"nameServers,omitempty"`
	DNSSEC      string   `json:"dnssec,omitempty"`

	// Registrar
	Registrar        string `json:"registrar,omitempty"`
	RegistrarURL     string `json:"registrarURL,omitempty"`
	RegistrarIANAID  string `json:"registrarIANAID,omitempty"`
	RegistrarWhoisServer string `json:"registrarWhoisServer,omitempty"`
	RegistrarAbuseEmail  string `json:"registrarAbuseEmail,omitempty"`
	RegistrarAbusePhone  string `json:"registrarAbusePhone,omitempty"`

	// Registry dates
	Created  *time.Time `json:"created,omitempty"`
	Updated  *time.Time `json:"updated,omitempty"`
	Expires  *time.Time `json:"expires,omitempty"`

	// Availability
	Available bool `json:"available"`

	// Contacts
	Registrant *Contact `json:"registrant,omitempty"`
	Admin      *Contact `json:"admin,omitempty"`
	Tech       *Contact `json:"tech,omitempty"`

	// IP / ASN specific
	Network     string   `json:"network,omitempty"`   // CIDR block
	NetName     string   `json:"netName,omitempty"`
	NetHandle   string   `json:"netHandle,omitempty"`
	Parent      string   `json:"parent,omitempty"`
	NetType     string   `json:"netType,omitempty"`
	Origin      string   `json:"origin,omitempty"`    // ASN origin
	ASName      string   `json:"asName,omitempty"`
	ASDesc      string   `json:"asDesc,omitempty"`
	Routes      []string `json:"routes,omitempty"`

	// Raw WHOIS text (all referral layers concatenated)
	RawData []string `json:"rawData"`
}
