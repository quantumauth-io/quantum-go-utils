//go:build !darwin

package tpmdevice

import (
	"context"
	"fmt"
)

// This exists only so code that references newEnclaveClient compiles on
// non-darwin platforms. It should never be called at runtime there.
func newEnclaveClient(_ context.Context, _ Config) (Client, error) {
	return nil, fmt.Errorf("Secure Enclave backend is only available on darwin")
}
