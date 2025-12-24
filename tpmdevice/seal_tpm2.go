//go:build !darwin

package tpmdevice

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	tpm2 "github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

type tpm2Sealer struct {
	ownerAuth string
}

type sealedBlobV1 struct {
	V     int    `json:"v"`
	Label string `json:"label"`
	Priv  []byte `json:"priv"` // []byte becomes base64 automatically in JSON
	Pub   []byte `json:"pub"`
}

func NewSealer(ownerAuth string) Sealer {
	return &tpm2Sealer{ownerAuth: ownerAuth}
}

func (s *tpm2Sealer) Seal(ctx context.Context, label string, secret []byte) ([]byte, error) {
	if len(secret) == 0 {
		return nil, errors.New("tpmdevice: secret empty")
	}

	rwc, err := openTPM()
	if err != nil {
		return nil, err
	}
	defer rwc.Close()

	parent, err := createPrimaryStorageKey(rwc, s.ownerAuth)
	if err != nil {
		return nil, err
	}
	defer tpm2.FlushContext(rwc, parent)

	// A "sealed data" object is typically a KeyedHash object with AlgNull.
	pub := tpm2.Public{
		Type:    tpm2.AlgKeyedHash,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM |
			tpm2.FlagFixedParent |
			tpm2.FlagUserWithAuth |
			tpm2.FlagNoDA,
		KeyedHashParameters: &tpm2.KeyedHashParams{
			Alg: tpm2.AlgNull,
		},
	}

	// Create the sealed object under the parent, embedding `secret` as sensitive data.
	// NOTE: this is the correct family of functions in legacy/tpm2 (CreateKeyWithSensitiveInfo).
	privBlob, pubBlob, _, _, _, err := tpm2.CreateKeyWithSensitive(
		rwc,
		parent,
		tpm2.PCRSelection{}, // add PCR policy later if you want binding
		"",                  // parentPassword
		s.ownerAuth,         // ownerPassword (matches CreatePrimary call)
		pub,                 // public template
		secret,              // sensitive data to seal (DEK)
	)
	if err != nil {
		return nil, fmt.Errorf("tpmdevice: CreateKeyWithSensitiveInfo: %w", err)
	}

	out, err := json.Marshal(sealedBlobV1{
		V:     1,
		Label: label,
		Priv:  privBlob,
		Pub:   pubBlob,
	})
	if err != nil {
		return nil, fmt.Errorf("tpmdevice: marshal sealed blob: %w", err)
	}
	return out, nil
}

func (s *tpm2Sealer) Unseal(ctx context.Context, label string, blob []byte) ([]byte, error) {
	rwc, err := openTPM()
	if err != nil {
		return nil, err
	}
	defer rwc.Close()

	var sb sealedBlobV1
	if err := json.Unmarshal(blob, &sb); err != nil {
		return nil, fmt.Errorf("tpmdevice: unmarshal sealed blob: %w", err)
	}
	if sb.V != 1 {
		return nil, fmt.Errorf("tpmdevice: unsupported sealed blob version: %d", sb.V)
	}
	if sb.Label != "" && sb.Label != label {
		return nil, errors.New("tpmdevice: sealed blob label mismatch")
	}

	parent, err := createPrimaryStorageKey(rwc, s.ownerAuth)
	if err != nil {
		return nil, err
	}
	defer tpm2.FlushContext(rwc, parent)

	h, _, err := tpm2.Load(rwc, parent, "", sb.Pub, sb.Priv)
	if err != nil {
		return nil, fmt.Errorf("tpmdevice: Load(sealed): %w", err)
	}
	defer tpm2.FlushContext(rwc, h)

	secret, err := tpm2.Unseal(rwc, h, "")
	if err != nil {
		return nil, fmt.Errorf("tpmdevice: Unseal: %w", err)
	}
	return secret, nil
}

func createPrimaryStorageKey(rwc io.ReadWriter, ownerAuth string) (tpmutil.Handle, error) {
	template := tpm2.Public{
		Type:    tpm2.AlgECC,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagDecrypt |
			tpm2.FlagRestricted |
			tpm2.FlagFixedTPM |
			tpm2.FlagFixedParent |
			tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth,
		ECCParameters: &tpm2.ECCParams{
			CurveID: tpm2.CurveNISTP256,
		},
	}

	h, _, err := tpm2.CreatePrimary(
		rwc,
		tpm2.HandleOwner,
		tpm2.PCRSelection{},
		"",        // parentPassword
		ownerAuth, // ownerPassword
		template,
	)
	if err != nil {
		return 0, fmt.Errorf("tpmdevice: CreatePrimary(storage): %w", err)
	}
	return h, nil
}
