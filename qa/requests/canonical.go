package requests

import (
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
)

type CanonicalInput struct {
	Method      string
	Path        string
	AppID       string
	BackendHost string

	TS          int64
	ChallengeID string
	UserID      string
	DeviceID    string

	BodySHA256Hex string
}

type ParsedCanonical struct {
	Method      string
	Path        string
	AppID       string
	BackendHost string
	TS          int64
	ChallengeID string
	UserID      string
	DeviceID    string
	BodySHA256  string
}
type PathNormalizeOptions struct {
	CollapseSlashes bool
}

var allowedMethods = map[string]struct{}{
	"GET":     {},
	"POST":    {},
	"PUT":     {},
	"PATCH":   {},
	"DELETE":  {},
	"HEAD":    {},
	"OPTIONS": {},
	"TRACE":   {},
	"CONNECT": {},
}

func CanonicalString(ci CanonicalInput) (string, error) {
	bodyHex := strings.ToLower(strings.TrimSpace(ci.BodySHA256Hex))
	if bodyHex == "" {
		return "", fmt.Errorf("missing body sha256")
	}
	if len(bodyHex) != 64 {
		return "", fmt.Errorf("invalid body sha256 length")
	}
	if _, err := hex.DecodeString(bodyHex); err != nil {
		return "", fmt.Errorf("invalid body sha256 hex")
	}

	aud := NormalizeBackendHost(ci.BackendHost)
	if aud == "" {
		return "", fmt.Errorf("invalid aud")
	}

	return strings.Join([]string{
		strings.ToUpper(ci.Method),
		ci.Path,
		fmt.Sprintf("APP: %s", ci.AppID),
		fmt.Sprintf("AUD: %s", aud),
		fmt.Sprintf("TS: %d", ci.TS),
		fmt.Sprintf("CHALLENGE: %s", ci.ChallengeID),
		fmt.Sprintf("USER: %s", ci.UserID),
		fmt.Sprintf("DEVICE: %s", ci.DeviceID),
		fmt.Sprintf("BODY-SHA256: %s", bodyHex),
	}, "\n"), nil
}

// ParseCanonicalString parses a canonical string back into fields.
func ParseCanonicalString(s string) (*ParsedCanonical, error) {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) != 8 {
		return nil, fmt.Errorf("unexpected canonical line count: got %d, want 8", len(lines))
	}

	out := &ParsedCanonical{
		Method: strings.TrimSpace(lines[0]),
		Path:   strings.TrimSpace(lines[1]),
	}

	// APP
	const appPrefix = "APP: "
	if !strings.HasPrefix(lines[2], appPrefix) {
		return nil, fmt.Errorf("invalid APP line: %q", lines[2])
	}
	out.AppID = strings.TrimSpace(strings.TrimPrefix(lines[2], appPrefix))

	// AUD
	const audPrefix = "AUD: "
	if !strings.HasPrefix(lines[3], audPrefix) {
		return nil, fmt.Errorf("invalid AUD line: %q", lines[3])
	}
	out.BackendHost = strings.TrimSpace(strings.TrimPrefix(lines[3], audPrefix))

	// TS
	const tsPrefix = "TS: "
	if !strings.HasPrefix(lines[4], tsPrefix) {
		return nil, fmt.Errorf("invalid TS line: %q", lines[4])
	}
	tsStr := strings.TrimSpace(strings.TrimPrefix(lines[4], tsPrefix))
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("parse TS: %w", err)
	}
	out.TS = ts

	// CHALLENGE
	const chPrefix = "CHALLENGE: "
	if !strings.HasPrefix(lines[5], chPrefix) {
		return nil, fmt.Errorf("invalid CHALLENGE line: %q", lines[5])
	}
	out.ChallengeID = strings.TrimSpace(strings.TrimPrefix(lines[5], chPrefix))

	// USER
	const userPrefix = "USER: "
	if !strings.HasPrefix(lines[6], userPrefix) {
		return nil, fmt.Errorf("invalid USER line: %q", lines[6])
	}
	out.UserID = strings.TrimSpace(strings.TrimPrefix(lines[6], userPrefix))

	// DEVICE
	const devPrefix = "DEVICE: "
	if !strings.HasPrefix(lines[7], devPrefix) {
		return nil, fmt.Errorf("invalid DEVICE line: %q", lines[7])
	}
	out.DeviceID = strings.TrimSpace(strings.TrimPrefix(lines[7], devPrefix))

	// BODY-SHA256
	const bodyPrefix = "BODY-SHA256: "
	if !strings.HasPrefix(lines[8], bodyPrefix) {
		return nil, fmt.Errorf("invalid BODY-SHA256 line: %q", lines[8])
	}
	out.BodySHA256 = strings.TrimSpace(strings.TrimPrefix(lines[8], bodyPrefix))

	return out, nil
}

// HostnameForDNS takes things like:
// - "localhost:1042"
// - "http://localhost:1042/quantum-auth/v1/secured"
// - "https://api.example.com:8443"
// - "[::1]:1042"
// and returns just the hostname you can use for DNS TXT lookup:
// - "localhost"
// - "api.example.com"
// - "::1"
func HostnameForDNS(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}

	// If it looks like a URL, parse it.
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil {
			s = u.Host
		}
	} else {
		// If it contains a path, drop it.
		if i := strings.IndexByte(s, '/'); i >= 0 {
			s = s[:i]
		}
	}

	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}

	// Remove port if present.
	// Handle IPv6 and host:port.
	if h, _, err := net.SplitHostPort(s); err == nil {
		return strings.TrimSpace(h)
	}

	// If it's bracketed IPv6 without port like "[::1]"
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		return strings.TrimSuffix(strings.TrimPrefix(s, "["), "]")
	}

	// Otherwise it's already host-only (or an un-splittable value); return as-is.
	return s
}

func NormalizeOptionalBackendHost(p *string) string {
	if p == nil {
		return ""
	}
	return NormalizeBackendHost(*p)
}

// NormalizeBackendHost returns canonical "hostname[:port]".
// - Lowercases hostname
// - Removes scheme/path/query/fragment
// - Strips default ports 80 and 443
// - Preserves non-default ports (e.g. :4000)
func NormalizeBackendHost(input string) string {
	s := strings.TrimSpace(input)
	if s == "" {
		return ""
	}

	// If it already looks like a URL, parse directly.
	// Otherwise add a dummy scheme so url.Parse can handle host[:port].
	toParse := s
	if !strings.Contains(toParse, "://") {
		toParse = "http://" + toParse
	}

	u, err := url.Parse(toParse)
	if err == nil && u.Host != "" {
		// u.Host may include port; u.Hostname()/Port() split safely.
		host := strings.ToLower(strings.TrimSpace(u.Hostname()))
		port := strings.TrimSpace(u.Port())

		// Strip default ports unconditionally (scheme-agnostic by design).
		if port == "80" || port == "443" {
			port = ""
		}
		if host == "" {
			return ""
		}
		if port != "" {
			return net.JoinHostPort(host, port)
		}
		return host
	}

	// Fallback: strip any scheme-like prefix, then take up to first '/'.
	// e.g. "https://EXAMPLE.com:4000/foo" -> "EXAMPLE.com:4000"
	raw := s
	if i := strings.Index(raw, "://"); i >= 0 {
		raw = raw[i+3:]
	}
	raw = strings.SplitN(raw, "/", 2)[0]
	raw = strings.TrimSpace(raw)

	// If raw is host:port, split; otherwise just lowercase host.
	host, port, err2 := net.SplitHostPort(raw)
	if err2 == nil {
		host = strings.ToLower(strings.TrimSpace(host))
		port = strings.TrimSpace(port)
		if port == "80" || port == "443" {
			port = ""
		}
		if host == "" {
			return ""
		}
		if port != "" {
			return net.JoinHostPort(host, port)
		}
		return host
	}

	// Could be plain hostname or an IPv6 literal without port.
	raw = strings.ToLower(raw)
	raw = strings.TrimSuffix(raw, ".") // optional: remove trailing dot
	return raw
}

func NormalizeAndValidateMethod(m string) (string, error) {
	m = strings.TrimSpace(m)
	if m == "" {
		return "", fmt.Errorf("missing method")
	}
	m = strings.ToUpper(m)

	if _, ok := allowedMethods[m]; !ok {
		return "", fmt.Errorf("unsupported method: %s", m)
	}
	return m, nil
}

func NormalizeAndValidatePath(p string, opt PathNormalizeOptions) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" {
		return "", fmt.Errorf("missing path")
	}
	if !utf8.ValidString(p) {
		return "", fmt.Errorf("path is not valid utf-8")
	}

	// Reject whitespace/control chars anywhere (prevents header/request-target injection weirdness)
	for _, r := range p {
		if r <= 0x1F || r == 0x7F {
			return "", fmt.Errorf("path contains control characters")
		}
	}

	// Reject full URL or scheme-relative forms (we only sign origin-form request-target)
	if strings.Contains(p, "://") || strings.HasPrefix(p, "//") {
		return "", fmt.Errorf("path must be origin-form (start with '/')")
	}

	// Fragments should never be in an HTTP request target; reject to avoid ambiguity
	if strings.Contains(p, "#") {
		return "", fmt.Errorf("path must not contain fragment")
	}

	if !strings.HasPrefix(p, "/") {
		return "", fmt.Errorf("path must start with '/'")
	}

	u, err := url.ParseRequestURI(p)
	if err != nil {
		return "", fmt.Errorf("invalid path: %w", err)
	}

	// Minimal normalization: optional collapse of repeated slashes in the PATH ONLY.
	pathOnly := u.Path
	if opt.CollapseSlashes {
		pathOnly = collapseSlashes(pathOnly)
	}

	// Recompose without altering RawQuery encoding or ordering
	out := pathOnly
	if u.RawQuery != "" {
		out += "?" + u.RawQuery
	}
	return out, nil
}

func ValidateUUIDv4(s string) (string, error) {
	u, err := uuid.Parse(strings.TrimSpace(s))
	if err != nil {
		return "", fmt.Errorf("invalid uuid")
	}
	if u == uuid.Nil {
		return "", fmt.Errorf("nil uuid not allowed")
	}
	if u.Version() != 4 {
		return "", fmt.Errorf("uuid must be v4")
	}
	return u.String(), nil
}

func collapseSlashes(s string) string {
	if !strings.Contains(s, "//") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	prev := byte(0)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '/' && prev == '/' {
			continue
		}
		b.WriteByte(c)
		prev = c
	}
	return b.String()
}
