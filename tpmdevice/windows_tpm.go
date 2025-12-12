//go:build windows

package tpmdevice

import (
	"fmt"
	"io"

	tpm2 "github.com/google/go-tpm/legacy/tpm2"
)

// openTPM on Windows: use legacy tpm2.OpenTPM, which talks to the TPM
// via the Windows TBS layer.
func openTPM() (io.ReadWriteCloser, error) {
	rwc, err := tpm2.OpenTPM()
	if err != nil {
		return nil, fmt.Errorf("tpmdevice: OpenTPM (windows) failed: %w", err)
	}
	return rwc, nil
}
