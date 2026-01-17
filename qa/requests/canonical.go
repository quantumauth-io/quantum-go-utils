package requests

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

type CanonicalInput struct {
	Method string
	Path   string
	Host   string

	TS          int64
	ChallengeID string
	UserID      string
	DeviceID    string

	Body []byte
}

type ParsedCanonical struct {
	Method      string
	Path        string
	Host        string
	TS          int64
	ChallengeID string
	UserID      string
	DeviceID    string
	BodySHA256  string
}

func CanonicalString(ci CanonicalInput) string {
	bodyHash := sha256.Sum256(ci.Body)

	return strings.Join([]string{
		strings.ToUpper(ci.Method),
		ci.Path,
		ci.Host,
		fmt.Sprintf("TS: %d", ci.TS),
		fmt.Sprintf("CHALLENGE: %s", ci.ChallengeID),
		fmt.Sprintf("USER: %s", ci.UserID),
		fmt.Sprintf("DEVICE: %s", ci.DeviceID),
		fmt.Sprintf("BODY-SHA256: %s", hex.EncodeToString(bodyHash[:])),
	}, "\n")
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
		Host:   strings.TrimSpace(lines[2]),
	}

	// TS
	const tsPrefix = "TS: "
	if !strings.HasPrefix(lines[3], tsPrefix) {
		return nil, fmt.Errorf("invalid TS line: %q", lines[3])
	}
	tsStr := strings.TrimSpace(strings.TrimPrefix(lines[3], tsPrefix))
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("parse TS: %w", err)
	}
	out.TS = ts

	// CHALLENGE
	const chPrefix = "CHALLENGE: "
	if !strings.HasPrefix(lines[4], chPrefix) {
		return nil, fmt.Errorf("invalid CHALLENGE line: %q", lines[4])
	}
	out.ChallengeID = strings.TrimSpace(strings.TrimPrefix(lines[4], chPrefix))

	// USER
	const userPrefix = "USER: "
	if !strings.HasPrefix(lines[5], userPrefix) {
		return nil, fmt.Errorf("invalid USER line: %q", lines[5])
	}
	out.UserID = strings.TrimSpace(strings.TrimPrefix(lines[5], userPrefix))

	// DEVICE
	const devPrefix = "DEVICE: "
	if !strings.HasPrefix(lines[6], devPrefix) {
		return nil, fmt.Errorf("invalid DEVICE line: %q", lines[6])
	}
	out.DeviceID = strings.TrimSpace(strings.TrimPrefix(lines[6], devPrefix))

	// BODY-SHA256
	const bodyPrefix = "BODY-SHA256: "
	if !strings.HasPrefix(lines[7], bodyPrefix) {
		return nil, fmt.Errorf("invalid BODY-SHA256 line: %q", lines[7])
	}
	out.BodySHA256 = strings.TrimSpace(strings.TrimPrefix(lines[7], bodyPrefix))

	return out, nil
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
