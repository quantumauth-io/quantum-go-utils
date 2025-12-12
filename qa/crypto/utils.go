package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// RandomBase64 returns N random bytes encoded in base64 (URL-safe, no padding).
func RandomBase64(n int) (string, error) {
	buf := make([]byte, n)
	_, err := rand.Read(buf)
	if err != nil {
		return "", fmt.Errorf("random: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(buf), nil
}
