package main

import (
	_ "embed"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"nettools/http2whois/internal/whoisclient"
)

//go:embed static/index.html
var indexHTML []byte

//go:embed static/favicon.png
var faviconPNG []byte

//go:embed static/openapi.json
var openapiJSON []byte

/* ---------- Configuration ---------- */

// config holds all server-level settings resolved at startup.
type config struct {
	addr           string        // listening address (host:port)
	whoisTimeout   time.Duration // per-query WHOIS socket timeout
	requestTimeout time.Duration // global HTTP request deadline
}

// resolveConfig builds the effective configuration by applying the priority rule:
//
//	CLI flag (if explicitly set) > environment variable > built-in default
//
// Each parameter follows the same three-step pattern so the precedence is
// uniform and easy to audit.
func resolveConfig() config {
	const (
		defaultAddr           = "127.0.0.1:8080"
		defaultWhoisTimeout   = 15 * time.Second
		defaultRequestTimeout = 20 * time.Second
	)

	// --- Declare CLI flags (default = sentinel, not the real default) ---
	// Using an empty string / 0 as sentinel lets us detect "was this flag
	// explicitly passed?" without depending on flag.Visit.
	flagAddr := flag.String(
		"addr", "",
		"listening address (host:port)  [env: LISTEN_ADDR, default: "+defaultAddr+"]",
	)
	flagWhoisTimeout := flag.Duration(
		"whois-timeout", 0,
		"per-query WHOIS socket timeout  [env: WHOIS_TIMEOUT, default: 15s]",
	)
	flagRequestTimeout := flag.Duration(
		"request-timeout", 0,
		"global HTTP request deadline    [env: REQUEST_TIMEOUT, default: 20s]",
	)
	flag.Parse()

	// --- Resolve each setting: CLI > env > default ---
	cfg := config{}

	cfg.addr = resolve(*flagAddr, os.Getenv("LISTEN_ADDR"), defaultAddr)

	if wt, err := parseDuration(*flagWhoisTimeout, "WHOIS_TIMEOUT"); err == nil {
		cfg.whoisTimeout = wt
	} else {
		cfg.whoisTimeout = defaultWhoisTimeout
	}

	if rt, err := parseDuration(*flagRequestTimeout, "REQUEST_TIMEOUT"); err == nil {
		cfg.requestTimeout = rt
	} else {
		cfg.requestTimeout = defaultRequestTimeout
	}

	return cfg
}

// resolve returns the first non-empty value among flag, env, and fallback.
func resolve(flagVal, envVal, fallback string) string {
	if flagVal != "" {
		return flagVal
	}
	if envVal != "" {
		return envVal
	}
	return fallback
}

// parseDuration returns flagVal if non-zero, then tries to parse the named
// environment variable, then returns an error so the caller can use its default.
func parseDuration(flagVal time.Duration, envKey string) (time.Duration, error) {
	if flagVal != 0 {
		return flagVal, nil
	}
	if raw := os.Getenv(envKey); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil {
			return 0, fmt.Errorf("invalid %s=%q: %w", envKey, raw, err)
		}
		return d, nil
	}
	return 0, fmt.Errorf("not set")
}

/* ---------- Request / response structures ---------- */

type WhoisRequest struct {
	IP          string `json:"ip"`
	Domain      string `json:"domain"`
	ASN         string `json:"asn"`
	WhoisServer string `json:"whoisserver"`
	Timeout     int    `json:"timeout"` // seconds (0 -> use server default)
}

type WhoisResponse struct {
	Status  string      `json:"status"`
	Answers interface{} `json:"answers"`
}

/* ---------- HTTP handlers ---------- */

func indexHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(indexHTML)
}

func faviconHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/png")
	w.Write(faviconPNG)
}

func openapiHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write(openapiJSON)
}

// makeWhoisHandler returns an http.HandlerFunc closed over the server config.
func makeWhoisHandler(defaultParser *whoisclient.Parser, cfg config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Decode the request body
		var req WhoisRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondJSON(w, WhoisResponse{Status: "ERROR", Answers: "invalid JSON"})
			return
		}
		defer r.Body.Close()

		// Validate and build the query
		var query string
		switch {
		case req.IP != "":
			query = req.IP
		case req.Domain != "":
			query = req.Domain
		case req.ASN != "":
			asn := req.ASN
			if !strings.HasPrefix(strings.ToUpper(asn), "AS") {
				asn = "AS" + asn
			}
			query = asn
		default:
			respondJSON(w, WhoisResponse{Status: "ERROR", Answers: "neither ip, domain nor asn provided"})
			return
		}

		// Dynamic options (per-request overrides)
		opts := []whoisclient.Option{}
		if req.Timeout > 0 {
			opts = append(opts, whoisclient.WithTimeout(time.Duration(req.Timeout)*time.Second))
		}

		// Optional whois server (domains only)
		if req.WhoisServer != "" && req.Domain != "" {
			host, port, err := parseHostPort(req.WhoisServer)
			if err == nil {
				tld := strings.ToLower(strings.SplitN(req.Domain, ".", 2)[1]) // simple TLD
				opts = append(opts, whoisclient.WithSpecialWhois(tld,
					whoisclient.CustomServer{
						Host:   host,
						Port:   port,
						Format: "",
					}))
			}
		}

		parser := defaultParser
		if len(opts) > 0 {
			parser = whoisclient.New(opts...)
		}

		// Lookup
		ctx, cancel := context.WithTimeout(context.Background(), cfg.requestTimeout)
		defer cancel()

		res, err := parser.Lookup(ctx, query)
		if err != nil {
			respondJSON(w, WhoisResponse{Status: "ERROR", Answers: err.Error()})
			return
		}
		if len(res.RawData) == 0 {
			respondJSON(w, WhoisResponse{Status: "NOTFOUND", Answers: []string{}})
			return
		}

		respondJSON(w, WhoisResponse{Status: "SUCCESS", Answers: res})
	}
}

/* ---------- Helpers ---------- */

func respondJSON(w http.ResponseWriter, resp WhoisResponse) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

// parseHostPort accepts "host" or "host:port". Returns the port as an integer.
func parseHostPort(s string) (host string, port int, err error) {
	parts := strings.Split(s, ":")
	if len(parts) == 1 {
		return parts[0], 43, nil // default port 43
	}
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("invalid host:port: %s", s)
	}
	host = parts[0]
	p, err := strconv.Atoi(parts[1])
	if err != nil {
		return "", 0, fmt.Errorf("invalid port: %w", err)
	}
	return host, p, nil
}

/* ---------- Entry point ---------- */

func main() {
	cfg := resolveConfig()

	defaultParser := whoisclient.New(
		whoisclient.WithTimeout(cfg.whoisTimeout),
	)

	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/favicon.png", faviconHandler)
	http.HandleFunc("/openapi.json", openapiHandler)
	http.HandleFunc("/api/v1/whois", makeWhoisHandler(defaultParser, cfg))

	fmt.Printf("Whois API listening on %s (whois-timeout=%s, request-timeout=%s)\n",
		cfg.addr, cfg.whoisTimeout, cfg.requestTimeout)

	if err := http.ListenAndServe(cfg.addr, nil); err != nil {
		fmt.Fprintln(os.Stderr, "Server error:", err)
		os.Exit(1)
	}
}
