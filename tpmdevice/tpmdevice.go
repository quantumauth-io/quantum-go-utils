package tpmdevice

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/quantumauth-io/quantum-go-utils/log"
)

const (
	DefaultHandle      = tpmutil.Handle(0x8100A001) // QA reserved default
	defaultHandleStart = tpmutil.Handle(0x8100A001)
	defaultHandleCount = uint32(32)
)

// Client is a TPM-backed signing client.
type Client interface {
	Handle() tpmutil.Handle
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
	OwnerAuth string

	HandleStart tpmutil.Handle
	HandleCount uint32
}

func (c *client) Handle() tpmutil.Handle {
	if c == nil {
		return 0
	}
	return c.handle
}

func NewWithConfig(ctx context.Context, cfg Config) (Client, error) {
	switch runtime.GOOS {
	case "darwin":
		return newEnclaveClient(ctx, cfg)
	default:
		rwc, err := openTPM()
		if err != nil {
			return nil, err
		}

		// Decide which handle(s) to try
		if cfg.Handle != 0 {
			c, err := openOrCreateAtHandle(rwc, cfg, cfg.Handle)
			if err != nil {
				_ = rwc.Close()
				return nil, err
			}
			return c, nil
		}

		start := cfg.HandleStart
		if start == 0 {
			start = defaultHandleStart
		}
		count := cfg.HandleCount
		if count == 0 {
			count = defaultHandleCount
		}

		picked, err := pickOrCreateHandle(rwc, cfg, start, count)
		if err != nil {
			_ = rwc.Close()
			return nil, err
		}
		return picked, nil
	}
}

// pickOrCreateHandle scans [start, start+count) and:
// - reuses first compatible ECC key it finds
// - otherwise creates & persists a new ECC key in the first empty slot
// - skips incompatible keys (e.g. RSA) unless ForceNew is true
// pickOrCreateHandle scans a handle range and reuses or creates an ECC key.
func pickOrCreateHandle(rwc io.ReadWriteCloser, cfg Config, start tpmutil.Handle, count uint32) (Client, error) {
	var firstEmpty *tpmutil.Handle

	for i := uint32(0); i < count; i++ {
		h := tpmutil.Handle(uint32(start) + i)

		pub, _, _, err := tpm2.ReadPublic(rwc, h)
		if err == nil {
			uncompressed, err2 := publicToUncompressed(pub)
			if err2 == nil {
				return &client{
					rwc:    rwc,
					handle: h,
					pub:    uncompressed,
					pubB64: base64.RawStdEncoding.EncodeToString(uncompressed),
				}, nil
			}

			log.Warn("tpmdevice incompatible key at handle",
				"handle", fmt.Sprintf("0x%x", h),
				"error", err2,
			)

			if cfg.ForceNew {
				_ = tpm2.EvictControl(rwc, cfg.OwnerAuth, tpm2.HandleOwner, h, h)
				return createAndPersistAt(rwc, cfg, h)
			}
			continue
		}

		if isHandleEmptyErr(err) {
			if firstEmpty == nil {
				hh := h
				firstEmpty = &hh
			}
			continue
		}

		log.Error("tpmdevice ReadPublic failed",
			"handle", fmt.Sprintf("0x%x", h),
			"error", err,
		)
		return nil, err
	}

	if firstEmpty == nil {
		return nil, fmt.Errorf("tpmdevice: no free handle in range 0x%x..0x%x",
			start, tpmutil.Handle(uint32(start)+count-1))
	}

	log.Info("tpmdevice creating new ECC key", "handle", fmt.Sprintf("0x%x", *firstEmpty))
	return createAndPersistAt(rwc, cfg, *firstEmpty)
}

// openOrCreateAtHandle uses a specific handle:
// - if compatible ECC key exists -> reuse
// - if exists but incompatible -> error unless ForceNew, then evict & recreate
// - if empty -> create & persist
func openOrCreateAtHandle(rwc io.ReadWriteCloser, cfg Config, h tpmutil.Handle) (Client, error) {
	if cfg.ForceNew {
		_ = tpm2.EvictControl(rwc, cfg.OwnerAuth, tpm2.HandleOwner, h, h)
		return createAndPersistAt(rwc, cfg, h)
	}

	pub, _, _, err := tpm2.ReadPublic(rwc, h)
	if err == nil {
		uncompressed, err := publicToUncompressed(pub)
		if err != nil {
			return nil, fmt.Errorf("incompatible key at handle 0x%x: %w", h, err)
		}
		log.Info("tpmdevice using existing key", "handle", fmt.Sprintf("0x%x", h))
		return &client{
			rwc:    rwc,
			handle: h,
			pub:    uncompressed,
			pubB64: base64.RawStdEncoding.EncodeToString(uncompressed),
		}, nil
	}

	if !isHandleEmptyErr(err) {
		return nil, err
	}

	return createAndPersistAt(rwc, cfg, h)
}

func createAndPersistAt(rwc io.ReadWriteCloser, cfg Config, handle tpmutil.Handle) (Client, error) {
	transient, uncompressed, err := createPrimarySigningKey(rwc)
	if err != nil {
		return nil, err
	}

	if err := tpm2.EvictControl(rwc, cfg.OwnerAuth, tpm2.HandleOwner, transient, handle); err != nil {
		_ = tpm2.FlushContext(rwc, transient)
		return nil, err
	}

	_ = tpm2.FlushContext(rwc, transient)

	log.Info("tpmdevice persisted ECC key", "handle", fmt.Sprintf("0x%x", handle))

	return &client{
		rwc:    rwc,
		handle: handle,
		pub:    uncompressed,
		pubB64: base64.RawStdEncoding.EncodeToString(uncompressed),
	}, nil
}

func isHandleEmptyErr(err error) bool {
	if err == nil {
		return false
	}
	// go-tpm legacy returns TPM errors with text like:
	// "error code 0xb : the handle is not correct for the use"
	s := err.Error()
	return strings.Contains(s, "handle is not correct") ||
		strings.Contains(s, "0xb") ||
		strings.Contains(s, "TPM_RC_HANDLE")
}

// createPrimarySigningKey creates a transient ECC signing key and returns
// its handle + uncompressed public key. No retry logic – any hierarchy/driver
// issue is surfaced directly to the caller.
// createPrimarySigningKey creates a transient ECC signing key.
func createPrimarySigningKey(rwc io.ReadWriter) (tpmutil.Handle, []byte, error) {
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

	handle, _, err := tpm2.CreatePrimary(
		rwc,
		tpm2.HandleOwner,
		tpm2.PCRSelection{},
		"",
		"",
		template,
	)
	if err != nil {
		log.Error("tpmdevice CreatePrimary failed", "error", err)
		return 0, nil, err
	}

	pub, _, _, err := tpm2.ReadPublic(rwc, handle)
	if err != nil {
		_ = tpm2.FlushContext(rwc, handle)
		return 0, nil, err
	}

	uncompressed, err := publicToUncompressed(pub)
	if err != nil {
		_ = tpm2.FlushContext(rwc, handle)
		return 0, nil, err
	}

	return handle, uncompressed, nil
}

func publicToUncompressed(pub tpm2.Public) ([]byte, error) {
	key, err := pub.Key()
	if err != nil {
		return nil, err
	}
	ec, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("unexpected key type %T", key)
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
