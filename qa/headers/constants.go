package headers

type HeaderKey string

const (
	HeaderAuthorization           HeaderKey = "Authorization"
	HeaderQuantumAuthCanonicalB64 HeaderKey = "X-QuantumAuth-Canonical-B64"

	// Authorization scheme
	HeaderQuantumAuth = "QuantumAuth"
)
