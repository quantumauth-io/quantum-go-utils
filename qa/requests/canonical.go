package requests

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
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
