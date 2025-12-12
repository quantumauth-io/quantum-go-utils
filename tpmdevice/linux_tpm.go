//go:build linux

package tpmdevice

import (
	"fmt"
	"io"

	"github.com/google/go-tpm/legacy/tpm2"
)

// openTPM for linux: tries /dev/tpmrm0 then /dev/tpm0.
func openTPM() (io.ReadWriteCloser, error) {
	paths := []string{"/dev/tpmrm0", "/dev/tpm0"}
	var lastErr error

	for _, p := range paths {
		rwc, err := tpm2.OpenTPM(p)
		if err == nil {
			return rwc, nil
		}
		lastErr = err
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("no TPM device paths tried")
	}
	return nil, fmt.Errorf("no TPM device found: %w", lastErr)
}
