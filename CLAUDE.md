# CLAUDE.md — http2whois

This file provides context for AI-assisted development on the `http2whois` project.

---

## Project overview

`http2whois` is a single-binary HTTP gateway that exposes WHOIS lookups as a JSON REST API.
It is written entirely in Go and embeds all static assets (web UI, favicon, OpenAPI spec) at compile time using `//go:embed` directives, so the resulting binary has zero runtime file dependencies.

The server accepts `POST /api/v1/whois` requests with a target (domain name, IP address, or AS number) and returns the parsed WHOIS record as structured JSON. It automatically follows referral chains to reach the most authoritative WHOIS server for each query.

---

## Repository layout

```
.
├── api/
│   └── swagger.yaml                          # OpenAPI 3.0 source (human-editable)
├── build/
│   └── Dockerfile                            # Two-stage Docker build (builder + scratch runtime)
├── cmd/
│   ├── http2whois/
│   │   ├── main.go                           # Entire HTTP server — single file
│   │   └── static/
│   │       ├── favicon.png                   # Embedded at build time
│   │       ├── index.html                    # Embedded web UI (dark/light, 15 languages)
│   │       └── openapi.json                  # Embedded OpenAPI spec (generated from swagger.yaml)
│   └── whois/
│       └── main.go                           # Standalone CLI tool for quick lookups
├── internal/
│   └── whoisclient/
│       ├── whoisclient.go                    # Public API: Parser, New(), Lookup(), functional options
│       ├── parser/
│       │   ├── parser.go                     # Extracts structured fields from raw WHOIS text
│       │   └── parser_test.go                # Unit tests for field parsing
│       ├── query/
│       │   └── query.go                      # Low-level TCP queries and referral chain following
│       ├── result/
│       │   └── result.go                     # Result and Contact struct definitions
│       └── servers/
│           └── servers.go                    # TLD-to-server map (1 000+ entries), RIR servers
├── scripts/
│   ├── 000_init.sh                           # go mod tidy
│   ├── 999_test.sh                           # Integration smoke tests (curl + jq)
│   ├── linux_build.sh                        # Native static binary build
│   ├── linux_run.sh                          # Run binary on Linux
│   ├── docker_build.sh                       # Build Docker image
│   ├── docker_run.sh                         # Run Docker container
│   ├── windows_build.cmd                     # Native build on Windows
│   └── windows_run.cmd                       # Run binary on Windows
├── go.mod
├── LICENSE                                   # MIT
├── README.md
└── CLAUDE.md                                 # This file
```

---

## Key design decisions

- **Single `main.go` for the server**: the entire HTTP server logic lives in `cmd/http2whois/main.go`. Keep it that way unless the file grows substantially.
- **Separate `internal/whoisclient` package**: WHOIS client logic is fully decoupled from the HTTP layer. It exposes a clean public API (`Parser`, `New()`, `Lookup()`, functional options) and can be imported independently by `cmd/whois`.
- **Embedded assets**: `favicon.png`, `index.html`, and `openapi.json` are embedded with `//go:embed`. Any change to these files is picked up at the next `go build` — no copy step needed.
- **Static binary**: the build uses `-tags netgo` and `-ldflags "-extldflags -static"` to produce a fully self-contained binary with no libc dependency. Do not introduce `cgo` dependencies.
- **No framework**: the HTTP layer uses only the standard library (`net/http`). Do not add a router or web framework.
- **No external dependencies**: the WHOIS client uses only the Go standard library. All TCP I/O, referral parsing, and field extraction are implemented from scratch.
- **Referral chain**: `internal/whoisclient/query` follows `whois server:` / `refer:` pointers up to a depth of 5, collecting raw responses from each hop. Later responses take precedence for scalar fields.
- **Handler factory**: `makeWhoisHandler` returns an `http.HandlerFunc` closed over the resolved `config` and the default `Parser` instance. This avoids package-level mutable state and simplifies testing.
- **WHOIS client origin**: `internal/whoisclient` is an adaptation of [prowebcraft/whois-parser](https://github.com/prowebcraft/whois-parser), automatically ported and restructured by **Claude Sonnet 4.6** by Anthropic.

---

## Environment variables & CLI flags

Every configuration value can be set via an environment variable **or** a command-line flag. The flag always takes priority. Resolution order: **CLI flag -> environment variable -> hard-coded default**.

| Environment variable | CLI flag           | Default           | Description                                                                 |
|----------------------|--------------------|-------------------|-----------------------------------------------------------------------------|
| `LISTEN_ADDR`        | `-addr`            | `127.0.0.1:8080`  | Listen address (`host:port`).                                               |
| `WHOIS_TIMEOUT`      | `-whois-timeout`   | `15s`             | Per-query WHOIS socket timeout. Accepts Go duration strings (e.g. `30s`).   |
| `REQUEST_TIMEOUT`    | `-request-timeout` | `20s`             | Global HTTP request deadline, including all referral hops.                  |

CLI flags are parsed with the standard library `flag` package. Flags use `""` / `0` as a sentinel value (not the real default) to detect whether a flag was explicitly passed, without relying on `flag.Visit`. Any new configuration entry must expose both a flag and its environment variable counterpart, following the same three-step resolution pattern in `resolveConfig()`.

---

## Build & run commands

```bash
# Initialise / tidy dependencies
bash scripts/000_init.sh

# Build native static binary -> ./out/http2whois
bash scripts/linux_build.sh

# Run (sets LISTEN_ADDR=0.0.0.0:8080)
bash scripts/linux_run.sh

# Build Docker image -> letstool/http2whois:latest
bash scripts/docker_build.sh

# Run Docker container
bash scripts/docker_run.sh

# Smoke tests (server must be running)
bash scripts/999_test.sh
```

---

## API contract

### Endpoint

```
POST /api/v1/whois
Content-Type: application/json
```

### Request fields

Exactly one of `ip`, `domain`, or `asn` must be provided per request.

| Field         | Type     | Required | Notes                                                                          |
|---------------|----------|----------|--------------------------------------------------------------------------------|
| `ip`          | `string` | (*)      | IPv4 or IPv6 address (e.g. `8.8.8.8`, `2001:4860:4860::8888`)                 |
| `domain`      | `string` | (*)      | Domain name (e.g. `example.com`)                                               |
| `asn`         | `string` | (*)      | AS number, with or without `AS` prefix (e.g. `15169` or `AS15169`)            |
| `whoisserver` | `string` | no       | Custom WHOIS server (`host` or `host:port`). Applies to domain lookups only.  |
| `timeout`     | `int`    | no       | Per-request WHOIS timeout in seconds (`0` uses the server default).            |

(*) Exactly one of these three fields is required.

### Response status values

| Value      | Meaning                                                       |
|------------|---------------------------------------------------------------|
| `SUCCESS`  | Query resolved — `answers` contains the parsed WHOIS result  |
| `NOTFOUND` | No WHOIS record found for the target                         |
| `ERROR`    | Bad request, invalid input, or network failure               |

### Other endpoints

| Method | Path            | Description                        |
|--------|-----------------|------------------------------------|
| `GET`  | `/`             | Embedded interactive web UI        |
| `GET`  | `/openapi.json` | OpenAPI 3.0 specification          |
| `GET`  | `/favicon.png`  | Application icon                   |

---

## Internal package responsibilities

### `internal/whoisclient` (whoisclient.go)

Public-facing API. Exposes `Parser`, `New()`, `Lookup()`, `WithTimeout()`, `WithSpecialWhois()`, and `CustomServer`. Handles query-type detection (domain / IPv4 / IPv6 / ASN), TLD and IP-prefix override resolution, and wires together `query` and `parser`.

### `internal/whoisclient/query` (query.go)

Low-level TCP transport. Opens a TCP connection to a WHOIS server (port 43 by default), sends the query string, reads the full response, and follows `whois server:` / `refer:` / `whois:` referral pointers up to `maxReferralDepth` (5) hops. HTTP referrals are ignored — only port-43 servers are supported. Returns all raw responses in order.

### `internal/whoisclient/parser` (parser.go)

Field extraction from raw WHOIS text. Scans lines for `key: value` pairs, normalises keys against `fieldMap` (canonical aliases), parses dates with 12 known layouts, and extracts registrant/admin/tech contact blocks. Checks availability patterns to set `Result.Available`. Later response layers override earlier ones for scalar fields.

### `internal/whoisclient/result` (result.go)

Defines the `Result` and `Contact` structs. `Result` covers domain fields, registrar details, registry dates, availability flag, contact pointers, IP/ASN network fields, and raw WHOIS text slices. All fields are JSON-tagged with `omitempty`.

### `internal/whoisclient/servers` (servers.go)

Static TLD-to-server map (`TLDServers`) with 1 000+ entries sourced from the IANA root zone database, RIR server map (`RIRServers`), default ASN server (`ASNServer`), IANA fallback (`IANAServer`), and `ForDomain()` helper. Two-level TLDs (e.g. `co.uk`) are tried before single TLDs. Some TLDs use a custom query format (`fmted()`), most use the default `%s\r\n` format (`plain()`).

---

## Web UI

The UI is a self-contained single-file HTML/JS/CSS application embedded in the binary.

- **Themes**: dark and light, switchable via a toggle button.
- **Languages**: 15 locales built in — Arabic (`ar`), Bengali (`bn`), Chinese (`zh`), German (`de`), English (`en`), Spanish (`es`), French (`fr`), Hindi (`hi`), Indonesian (`id`), Japanese (`ja`), Korean (`ko`), Portuguese (`pt`), Russian (`ru`), Urdu (`ur`), Vietnamese (`vi`). Language is selected from a dropdown. 
- **RTL support**: Arabic and Urdu automatically switch the layout to right-to-left.
- The UI calls `POST /api/v1/whois` and renders results in a table.
- The OpenAPI spec is also served at `/openapi.json` for use with tools such as Swagger UI or Postman.

To modify the UI, edit `cmd/http2whois/static/index.html` and rebuild.
To update the API spec, edit `api/swagger.yaml`, regenerate `openapi.json`, and rebuild.

---

## Adding support for a new TLD

1. Add an entry to `TLDServers` in `internal/whoisclient/servers/servers.go`:
   - Use `plain("whois.nic.example")` for standard query format.
   - Use `fmted("whois.example.com", "-T dn %s")` when the server requires a non-standard format.
2. If the TLD uses a two-level form (e.g. `co.example`), add it as a separate key.
3. Rebuild.

## Adding a new parsed WHOIS field

1. Add the new canonical name and its key aliases to `fieldMap` in `internal/whoisclient/parser/parser.go`.
2. Add the corresponding field to `result.Result` in `internal/whoisclient/result/result.go` with a JSON tag.
3. Assign the field in the `Parse()` function in `parser.go`.
4. Update `api/swagger.yaml` (the `WhoisResult` schema) and regenerate `openapi.json`.
5. Rebuild.

---

## Constraints & conventions

- Go version: **1.24+**
- No `cgo`. Keep `CGO_ENABLED=0`.
- No additional HTTP frameworks or routers.
- All HTTP server logic stays in `cmd/http2whois/main.go` unless a strong reason arises to split it.
- All WHOIS client logic stays in `internal/whoisclient` and its sub-packages.
- Error responses always return a `WhoisResponse` JSON body — never a plain-text error.
- The server never logs request bodies; avoid adding logging that could expose user-queried targets.
- All code, identifiers, comments, and documentation must be written in **English**. No icons, emoji, or non-ASCII decorations in comments or doc strings.
- **Every configuration environment variable must have a corresponding command-line flag** (parsed via `flag` from the standard library). The flag always takes priority over the environment variable. The resolution order is: CLI flag -> environment variable -> hard-coded default. New entries must follow the sentinel pattern used in `resolveConfig()` and be documented in the table above.

---

## AI-assisted development

This project was developed with the assistance of **Claude Sonnet 4.6** by Anthropic.

The embedded WHOIS client (`internal/whoisclient`) is an adaptation of [prowebcraft/whois-parser](https://github.com/prowebcraft/whois-parser), automatically ported and restructured by **Claude Sonnet 4.6** by Anthropic.
