package cryptoctx

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/schemes"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/quantumauth-io/quantum-go-utils/tpmdevice"
)

var (
	ErrCorruptOrTampered   = errors.New("cryptoctx: corrupt or tampered key file")
	ErrMissingPQKeyFile    = errors.New("cryptoctx: PQ key file missing")
	ErrMissingTPMPublicKey = errors.New("cryptoctx: TPM public key missing")
)

type Runtime interface {
	TPMPublicKeyB64() string
	PQPublicKeyB64(ctx context.Context) (string, error)

	SignTPMB64(ctx context.Context, msg []byte) (string, error)
	SignPQB64(ctx context.Context, msg []byte) (string, error)

	EnsurePQKeypair(ctx context.Context) error
	Close() error
}

type Config struct {
	// TPM signing key (persistent handle managed by tpmdevice.NewWithConfig)
	TPM tpmdevice.Config

	// TPM owner auth (often empty on dev machines)
	OwnerAuth string

	// PQ key storage
	PQKeyFilePath string // if empty, uses default in user config dir
	PQLabel       string // required; scopes DEK sealing/unsealing

	// CIRCL scheme name
	PQSchemeName string // default: "ML-DSA-65"

	// Optional tuning
	Now func() time.Time
}

type runtimeImpl struct {
	tpm       tpmdevice.Client
	sealer    tpmdevice.Sealer
	scheme    sign.Scheme
	pqPath    string
	pqLabel   string
	tpmPubB64 string
	now       func() time.Time
}

func New(ctx context.Context, cfg Config) (Runtime, error) {
	now := cfg.Now
	if now == nil {
		now = time.Now
	}

	schemeName := cfg.PQSchemeName
	if schemeName == "" {
		schemeName = "ML-DSA-65"
	}

	scheme := schemes.ByName(schemeName)
	if scheme == nil {
		return nil, fmt.Errorf("cryptoctx: PQ scheme %q not found", schemeName)
	}

	// TPM signer (persistent ECC key)
	tpmClient, err := tpmdevice.NewWithConfig(ctx, cfg.TPM)
	if err != nil {
		return nil, err
	}

	tpmPub := tpmClient.PublicKeyB64()
	if tpmPub == "" {
		_ = tpmClient.Close()
		return nil, ErrMissingTPMPublicKey
	}

	pqPath := cfg.PQKeyFilePath
	if pqPath == "" {
		pqPath, err = defaultPQPath()
		if err != nil {
			_ = tpmClient.Close()
			return nil, err
		}
	}

	if cfg.PQLabel == "" {
		_ = tpmClient.Close()
		return nil, fmt.Errorf("cryptoctx: PQLabel is required")
	}

	sealer := tpmdevice.NewSealer(cfg.OwnerAuth)

	rt := &runtimeImpl{
		tpm:       tpmClient,
		sealer:    sealer,
		scheme:    scheme,
		pqPath:    pqPath,
		pqLabel:   cfg.PQLabel,
		tpmPubB64: tpmPub,
		now:       now,
	}

	// Ensure file exists on first run
	if err := rt.EnsurePQKeypair(ctx); err != nil {
		_ = rt.Close()
		return nil, err
	}

	return rt, nil
}
func (r *runtimeImpl) Close() error {
	if r == nil || r.tpm == nil {
		return nil
	}
	return r.tpm.Close()
}

func (r *runtimeImpl) TPMPublicKeyB64() string {
	if r == nil {
		return ""
	}
	return r.tpmPubB64
}

func (r *runtimeImpl) SignTPMB64(ctx context.Context, msg []byte) (string, error) {
	_ = ctx // TPM signing doesn’t need ctx today; keep it for future
	if r == nil || r.tpm == nil {
		return "", fmt.Errorf("cryptoctx: TPM client not initialized")
	}
	return r.tpm.SignB64(msg)
}

func (r *runtimeImpl) PQPublicKeyB64(ctx context.Context) (string, error) {
	kp, err := r.loadPQKeypair(ctx)
	if err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(kp.Pub), nil
}

func (r *runtimeImpl) SignPQB64(ctx context.Context, msg []byte) (string, error) {
	kp, err := r.loadPQKeypair(ctx)
	if err != nil {
		return "", err
	}
	defer kp.zeroize()

	sk, err := r.scheme.UnmarshalBinaryPrivateKey(kp.Priv)
	if err != nil {
		return "", fmt.Errorf("cryptoctx: unmarshal PQ private key: %w", err)
	}

	sig := r.scheme.Sign(sk, msg, nil)
	if sig == nil {
		return "", fmt.Errorf("cryptoctx: PQ sign failed")
	}
	return base64.RawStdEncoding.EncodeToString(sig), nil
}

func (r *runtimeImpl) EnsurePQKeypair(ctx context.Context) error {
	if r == nil {
		return fmt.Errorf("cryptoctx: runtime is nil")
	}

	// If file exists, nothing to do.
	if _, err := os.Stat(r.pqPath); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("cryptoctx: stat PQ key file: %w", err)
	}

	// Create directories
	if err := os.MkdirAll(filepath.Dir(r.pqPath), 0o700); err != nil {
		return fmt.Errorf("cryptoctx: mkdir PQ dir: %w", err)
	}

	// Generate PQ keypair
	pk, sk, err := r.scheme.GenerateKey()
	if err != nil {
		return fmt.Errorf("cryptoctx: PQ keygen failed: %w", err)
	}

	pubBytes, err := pk.MarshalBinary()
	if err != nil {
		return fmt.Errorf("cryptoctx: marshal PQ pub: %w", err)
	}

	privBytes, err := sk.MarshalBinary()
	if err != nil {
		return fmt.Errorf("cryptoctx: marshal PQ priv: %w", err)
	}

	kp := pqKeypair{
		Pub:  pubBytes,
		Priv: privBytes,
	}
	defer kp.zeroize()

	if err := r.writeEncryptedPQKeypair(ctx, kp); err != nil {
		return err
	}

	return nil
}

// ---------- file format + crypto ----------

// v1 envelope: sealed DEK + XChaCha20-Poly1305 ciphertext of {pub,priv}
type pqEnvelopeV1 struct {
	V int `json:"v"`

	// DEK sealed to this TPM (tpmdevice.Sealer)
	SealedDEK_B64 string `json:"sealed_dek_b64"`

	// AEAD
	NonceB64 string `json:"nonce_b64"`
	CTB64    string `json:"ct_b64"`

	// Metadata
	Label string `json:"label"`
}

type pqPayloadV1 struct {
	Pub  []byte `json:"pub"`  // raw bytes (json will base64)
	Priv []byte `json:"priv"` // raw bytes (json will base64)
}

type pqKeypair struct {
	Pub  []byte
	Priv []byte
}

func (k *pqKeypair) zeroize() {
	if k == nil {
		return
	}
	zeroBytes(k.Pub)
	zeroBytes(k.Priv)
}

func (r *runtimeImpl) writeEncryptedPQKeypair(ctx context.Context, kp pqKeypair) error {
	// random DEK (32 bytes for XChaCha20-Poly1305)
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return fmt.Errorf("cryptoctx: rand dek: %w", err)
	}
	defer zeroBytes(dek)

	sealed, err := r.sealer.Seal(ctx, r.pqLabel, dek)
	if err != nil {
		return fmt.Errorf("cryptoctx: seal dek: %w", err)
	}

	payloadBytes, err := json.Marshal(pqPayloadV1{
		Pub:  kp.Pub,
		Priv: kp.Priv,
	})
	if err != nil {
		return fmt.Errorf("cryptoctx: marshal payload: %w", err)
	}

	aead, err := chacha20poly1305.NewX(dek)
	if err != nil {
		return fmt.Errorf("cryptoctx: aead: %w", err)
	}

	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("cryptoctx: rand nonce: %w", err)
	}

	// AAD binds file path + label so moving/tampering is detected
	aad := r.aad()

	ct := aead.Seal(nil, nonce, payloadBytes, aad)

	env := pqEnvelopeV1{
		V:             1,
		SealedDEK_B64: base64.StdEncoding.EncodeToString(sealed),
		NonceB64:      base64.StdEncoding.EncodeToString(nonce),
		CTB64:         base64.StdEncoding.EncodeToString(ct),
		Label:         r.pqLabel,
	}

	out, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return fmt.Errorf("cryptoctx: marshal envelope: %w", err)
	}

	return atomicWriteFile(r.pqPath, out, 0o600)
}

func (r *runtimeImpl) loadPQKeypair(ctx context.Context) (*pqKeypair, error) {
	b, err := os.ReadFile(r.pqPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrMissingPQKeyFile
		}
		return nil, fmt.Errorf("cryptoctx: read PQ key file: %w", err)
	}

	var env pqEnvelopeV1
	if err := json.Unmarshal(b, &env); err != nil {
		return nil, fmt.Errorf("cryptoctx: unmarshal envelope: %w", err)
	}
	if env.V != 1 {
		return nil, fmt.Errorf("cryptoctx: unsupported pq envelope version: %d", env.V)
	}
	if env.Label != "" && env.Label != r.pqLabel {
		return nil, ErrCorruptOrTampered
	}

	sealed, err := base64.StdEncoding.DecodeString(env.SealedDEK_B64)
	if err != nil {
		return nil, ErrCorruptOrTampered
	}
	nonce, err := base64.StdEncoding.DecodeString(env.NonceB64)
	if err != nil {
		return nil, ErrCorruptOrTampered
	}
	ct, err := base64.StdEncoding.DecodeString(env.CTB64)
	if err != nil {
		return nil, ErrCorruptOrTampered
	}

	dek, err := r.sealer.Unseal(ctx, r.pqLabel, sealed)
	if err != nil || len(dek) != 32 {
		if dek != nil {
			zeroBytes(dek)
		}
		return nil, ErrCorruptOrTampered
	}
	defer zeroBytes(dek)

	aead, err := chacha20poly1305.NewX(dek)
	if err != nil {
		return nil, fmt.Errorf("cryptoctx: aead: %w", err)
	}

	plain, err := aead.Open(nil, nonce, ct, r.aad())
	if err != nil {
		return nil, ErrCorruptOrTampered
	}

	var payload pqPayloadV1
	if err := json.Unmarshal(plain, &payload); err != nil {
		return nil, ErrCorruptOrTampered
	}
	if len(payload.Pub) == 0 || len(payload.Priv) == 0 {
		return nil, ErrCorruptOrTampered
	}

	return &pqKeypair{
		Pub:  payload.Pub,
		Priv: payload.Priv,
	}, nil
}

func (r *runtimeImpl) aad() []byte {
	// Stable AAD: include label + absolute path (or best-effort path)
	abs := r.pqPath
	if a, err := filepath.Abs(r.pqPath); err == nil {
		abs = a
	}
	return []byte("quantumauth:cryptoctx:pq:v1|" + r.pqLabel + "|" + abs)
}

// ---------- helpers ----------

func defaultPQPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("cryptoctx: UserConfigDir: %w", err)
	}
	return filepath.Join(dir, "quantumauth", "pqkeys.json.enc"), nil
}

func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	_ = os.Remove(tmp)

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("cryptoctx: mkdir: %w", err)
	}

	if err := os.WriteFile(tmp, data, perm); err != nil {
		return fmt.Errorf("cryptoctx: write tmp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("cryptoctx: rename: %w", err)
	}
	return nil
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
