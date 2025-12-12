//go:build darwin && cgo

package tpmdevice

/*
#cgo darwin LDFLAGS: -framework Security -framework CoreFoundation
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>

// Helper to create or fetch a Secure Enclave key with a given label.
// This is intentionally left as a skeleton; it needs real implementation.
//
// OSStatus qa_get_or_create_enclave_key(CFStringRef label, SecKeyRef *keyOut);
// OSStatus qa_export_public(SecKeyRef key, CFDataRef *dataOut);
// OSStatus qa_sign_digest(SecKeyRef key, CFDataRef digest, CFDataRef *sigOut);
*/
import "C"

import (
	"errors"
	"fmt"
	"log"
)

type enclaveClient struct {
	key    C.SecKeyRef
	pub    []byte
	pubB64 string
	logger *log.Logger
}

func newEnclaveClient(_ context.Context, cfg Config) (Client, error) {
	if cfg.Logger != nil {
		cfg.Logger.Println("tpmdevice(darwin): Secure Enclave backend (cgo skeleton)")
	}

	label := "com.quantumauth.devicekey" // TODO: make configurable if needed

	cLabel := C.CFStringCreateWithCString(nil, C.CString(label), C.kCFStringEncodingUTF8)
	defer C.CFRelease(C.CFTypeRef(cLabel))

	var secKey C.SecKeyRef
	// TODO: call real qa_get_or_create_enclave_key here and check OSStatus.
	_ = secKey
	return nil, errors.New("Secure Enclave backend skeleton: C glue not implemented yet")
}

// PublicKey etc would be implemented once the C helpers exist
func (c *enclaveClient) PublicKey() []byte                  { return append([]byte(nil), c.pub...) }
func (c *enclaveClient) PublicKeyB64() string               { return c.pubB64 }
func (c *enclaveClient) Sign(msg []byte) ([]byte, error)    { return nil, fmt.Errorf("not implemented") }
func (c *enclaveClient) SignB64(msg []byte) (string, error) { return "", fmt.Errorf("not implemented") }
func (c *enclaveClient) Close() error                       { return nil }
