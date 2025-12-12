package tpmdevice

import (
	"crypto/ecdsa"
	"math/big"
)

// pad32 pads a big.Int to 32 bytes (big-endian).
func pad32(n *big.Int) []byte {
	out := make([]byte, 32)
	if n == nil {
		return out
	}
	nb := n.Bytes()
	if len(nb) > 32 {
		nb = nb[len(nb)-32:]
	}
	copy(out[32-len(nb):], nb)
	return out
}

// uncompressedFromECDSA encodes an ECDSA public key as:
// 0x04 || X || Y, each coordinate padded to 32 bytes.
func uncompressedFromECDSA(pub *ecdsa.PublicKey) []byte {
	xBytes := pub.X.Bytes()
	yBytes := pub.Y.Bytes()

	xPadded := make([]byte, 32)
	yPadded := make([]byte, 32)
	copy(xPadded[32-len(xBytes):], xBytes)
	copy(yPadded[32-len(yBytes):], yBytes)

	return append([]byte{0x04}, append(xPadded, yPadded...)...)
}
