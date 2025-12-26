package ethrpc

import (
	"fmt"
	"math/big"
	"strings"
)

func (h HexQuantity) Big() (*big.Int, error) {
	s := string(h)
	if s == "" {
		return nil, fmt.Errorf("empty hex quantity")
	}
	if s == "0x" || s == "0x0" {
		return big.NewInt(0), nil
	}
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = s[2:]
	}
	if s == "" {
		return big.NewInt(0), nil
	}
	n := new(big.Int)
	if _, ok := n.SetString(s, 16); !ok {
		return nil, fmt.Errorf("invalid hex quantity: %q", h)
	}
	return n, nil
}

func BigToHexQuantity(n *big.Int) string {
	if n == nil || n.Sign() == 0 {
		return "0x0"
	}
	return "0x" + strings.TrimLeft(n.Text(16), "0")
}

func NormalizeHex0x(s string) string {
	if s == "" {
		return ""
	}
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		return "0x" + s[2:]
	}
	return "0x" + s
}

func Strip0x(s string) string {
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		return s[2:]
	}
	return s
}
