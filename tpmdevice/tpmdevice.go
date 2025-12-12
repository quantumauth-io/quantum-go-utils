package tpmdevice

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"runtime"
	"strings"

	tpm2 "github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

const defaultHandle = tpmutil.Handle(0x81000001)

// Client is a TPM-backed signing client.
type Client interface {
	PublicKey() []byte                  // uncompressed 0x04||X||Y
	PublicKeyB64() string               // base64url(0x04||X||Y)
	Sign(msg []byte) ([]byte, error)    // raw R||S (64 bytes)
	SignB64(msg []byte) (string, error) // base64url(R||S)
	Close() error
}

type client struct {
	rwc    io.ReadWriteCloser
	handle tpmutil.Handle
	pub    []byte
	pubB64 string
}

type Config struct {
	Handle    tpmutil.Handle
	ForceNew  bool
	OwnerAuth string // TPM owner hierarchy auth (usually "")
	Logger    *log.Logger
}

func logf(logger *log.Logger, format string, args ...interface{}) {
	if logger != nil {
		logger.Printf(format, args...)
	}
}

func NewWithConfig(ctx context.Context, cfg Config) (Client, error) {
	switch runtime.GOOS {
	case "darwin":
		// Enclave backend (cgo)
		return newEnclaveClient(ctx, cfg)
	default:
		handle := cfg.Handle
		if handle == 0 {
			handle = defaultHandle
		}

		rwc, err := openTPM()
		if err != nil {
			return nil, err
		}

		// If ForceNew, remove any existing persistent object at this handle.
		if cfg.ForceNew {
			// Ignore errors here – if it's already gone, that's fine.
			_ = tpm2.EvictControl(rwc, cfg.OwnerAuth, tpm2.HandleOwner, handle, handle)
		}

		// Try to reuse an existing persistent key if ForceNew == false.
		if !cfg.ForceNew {
			pub, _, _, err := tpm2.ReadPublic(rwc, handle)
			if err == nil {
				uncompressed, err := publicToUncompressed(pub)
				if err != nil {
					_ = rwc.Close()
					return nil, err
				}
				pubB64 := base64.RawStdEncoding.EncodeToString(uncompressed)
				logf(cfg.Logger, "tpmdevice: using existing persistent key at 0x%x", handle)
				return &client{
					rwc:    rwc,
					handle: handle,
					pub:    uncompressed,
					pubB64: pubB64,
				}, nil
			}
			// This is where you saw:
			// "no existing key at 0x81000001: handle 1, error code 0xb : the handle is not correct for the use"
			logf(cfg.Logger, "tpmdevice: no existing key at 0x%x: %v", handle, err)
		}

		// Create a new primary signing key under owner hierarchy (single attempt)
		transient, uncompressed, err := createPrimarySigningKey(rwc, cfg.Logger)
		if err != nil {
			_ = rwc.Close()
			return nil, err
		}

		// Persist at the chosen handle. If this fails, we *do not* fall back;
		// persistence is required for stable device identity.
		if err := tpm2.EvictControl(
			rwc,
			cfg.OwnerAuth,
			tpm2.HandleOwner,
			transient,
			handle,
		); err != nil {
			_ = tpm2.FlushContext(rwc, transient)
			_ = rwc.Close()
			return nil, fmt.Errorf("tpmdevice: EvictControl (persist key) failed at 0x%x: %w", handle, err)
		}

		// EvictControl succeeded; flush transient and use the persistent handle.
		_ = tpm2.FlushContext(rwc, transient)

		pubB64 := base64.RawStdEncoding.EncodeToString(uncompressed)
		logf(cfg.Logger, "tpmdevice: created persistent key at 0x%x", handle)

		return &client{
			rwc:    rwc,
			handle: handle,
			pub:    uncompressed,
			pubB64: pubB64,
		}, nil
	}
}

// createPrimarySigningKey creates a transient ECC signing key and returns
// its handle + uncompressed public key. No retry logic – any hierarchy/driver
// issue is surfaced directly to the caller.
func createPrimarySigningKey(rwc io.ReadWriter, logger *log.Logger) (tpmutil.Handle, []byte, error) {
	template := tpm2.Public{
		Type:    tpm2.AlgECC,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagSign |
			tpm2.FlagFixedTPM |
			tpm2.FlagFixedParent |
			tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth,
		ECCParameters: &tpm2.ECCParams{
			CurveID: tpm2.CurveNISTP256,
		},
	}

	const hierarchy = tpm2.HandleOwner

	handle, _, err := tpm2.CreatePrimary(
		rwc,
		hierarchy,
		tpm2.PCRSelection{},
		"", // parentPassword
		"", // ownerPassword
		template,
	)
	if err != nil {
		logf(logger, "tpmdevice: CreatePrimary failed in 0x%x: %v", hierarchy, err)
		return 0, nil, fmt.Errorf("CreatePrimary failed: %w", err)
	}

	logf(logger, "tpmdevice: CreatePrimary OK in 0x%x (handle 0x%x)", hierarchy, handle)

	pub, _, _, err := tpm2.ReadPublic(rwc, handle)
	if err != nil {
		_ = tpm2.FlushContext(rwc, handle)
		return 0, nil, fmt.Errorf("ReadPublic: %w", err)
	}

	uncompressed, err := publicToUncompressed(pub)
	if err != nil {
		_ = tpm2.FlushContext(rwc, handle)
		return 0, nil, err
	}

	return handle, uncompressed, nil
}

func publicToUncompressed(pub tpm2.Public) ([]byte, error) {
	genericKey, err := pub.Key()
	if err != nil {
		return nil, fmt.Errorf("pub.Key: %w", err)
	}
	ec, ok := genericKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("unexpected key type %T", genericKey)
	}
	return uncompressedFromECDSA(ec), nil
}

// --- Client methods ---

func (c *client) PublicKey() []byte {
	return append([]byte(nil), c.pub...)
}

func (c *client) PublicKeyB64() string {
	return c.pubB64
}

func (c *client) Sign(msg []byte) ([]byte, error) {
	if c == nil || c.rwc == nil {
		return nil, fmt.Errorf("tpmdevice: client not initialized")
	}
	d := sha256.Sum256(msg)
	sig, err := tpm2.Sign(
		c.rwc,
		c.handle,
		"",
		d[:],
		nil,
		&tpm2.SigScheme{
			Alg:  tpm2.AlgECDSA,
			Hash: tpm2.AlgSHA256,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("tpmdevice: Sign: %w", err)
	}
	if sig.ECC == nil {
		return nil, fmt.Errorf("tpmdevice: TPM returned non-ECC signature")
	}
	raw := append(pad32(sig.ECC.R), pad32(sig.ECC.S)...)
	return raw, nil
}

func (c *client) SignB64(msg []byte) (string, error) {
	raw, err := c.Sign(msg)
	if err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(raw), nil
}

func (c *client) Close() error {
	if c == nil || c.rwc == nil {
		return nil
	}

	err := c.rwc.Close()
	c.rwc = nil // make Close idempotent

	if err == nil {
		return nil
	}

	// Ignore harmless double-close cases
	if errors.Is(err, os.ErrClosed) {
		return nil
	}
	if strings.Contains(err.Error(), "file already closed") {
		return nil
	}

	return fmt.Errorf("tpmdevice: close: %w", err)
}
