//go:build darwin

package tpmdevice

import (
	"context"
	"errors"
)

type noSealer struct{}

func NewSealer(_ string) Sealer { return &noSealer{} }
func (s *noSealer) Seal(context.Context, string, []byte) ([]byte, error) {
	return nil, errors.New("tpm sealer not supported on darwin")
}
func (s *noSealer) Unseal(context.Context, string, []byte) ([]byte, error) {
	return nil, errors.New("tpm sealer not supported on darwin")
}
