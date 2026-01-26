package headers

type HeaderKey string

const (
	// Standard Authorization header
	HeaderAuthorization HeaderKey = "Authorization"

	// Authorization scheme
	HeaderQuantumAuth = "QuantumAuth"

	// === QuantumAuth signed request headers ===

	HeaderQAAppID       HeaderKey = "X-QA-App-Id"
	HeaderQAAudience    HeaderKey = "X-QA-Aud"
	HeaderQATimestamp   HeaderKey = "X-QA-Ts"
	HeaderQAChallengeID HeaderKey = "X-QA-Challenge-Id"
	HeaderQAUserID      HeaderKey = "X-QA-User-Id"
	HeaderQADeviceID    HeaderKey = "X-QA-Device-Id"
	HeaderQABodySHA256  HeaderKey = "X-QA-Body-Sha256"

	// Optional version
	HeaderQAVersion HeaderKey = "X-QA-Sig-Ver"
)
