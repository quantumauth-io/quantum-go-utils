package tpmdevice

import "context"

// Sealer can protect small secrets (like a 32-byte DEK) using the TPM.
// The returned blob is portable only to the SAME TPM (and same hierarchy/policy).
type Sealer interface {
	Seal(ctx context.Context, label string, secret []byte) ([]byte, error)
	Unseal(ctx context.Context, label string, blob []byte) ([]byte, error)
}
