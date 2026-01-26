//go:build darwin

package cryptoctx

import (
	"context"
	"fmt"
)

type Runtime interface {
	TPMPublicKeyB64() string
	PQPublicKeyB64(ctx context.Context) (string, error)

	SignTPMB64(ctx context.Context, msg []byte) (string, error)
	SignPQB64(ctx context.Context, msg []byte) (string, error)

	EnsurePQKeypair(ctx context.Context) error
	Close() error
}

type Config struct{}

func New(ctx context.Context, cfg Config) (Runtime, error) {
	_ = ctx
	_ = cfg
	return nil, fmt.Errorf("cryptoctx: darwin not supported yet (Secure Enclave backend not implemented)")
}
