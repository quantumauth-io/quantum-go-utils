package ethrpc

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
)

type BlockTag string

const (
	BlockLatest   BlockTag = "latest"
	BlockPending  BlockTag = "pending"
	BlockEarliest BlockTag = "earliest"
)

type HexQuantity string

// CallMsg matches the JSON-RPC eth_call / eth_estimateGas object.
type CallMsg struct {
	From     string `json:"from,omitempty"`
	To       string `json:"to,omitempty"`
	Gas      string `json:"gas,omitempty"`      // hex quantity
	GasPrice string `json:"gasPrice,omitempty"` // hex quantity (legacy)
	Value    string `json:"value,omitempty"`    // hex quantity
	Data     string `json:"data,omitempty"`
	// EIP-1559 optional fields
	MaxFeePerGas         string `json:"maxFeePerGas,omitempty"`
	MaxPriorityFeePerGas string `json:"maxPriorityFeePerGas,omitempty"`
}

// FeeSuggestion is a minimal generic structure for EIP-1559
type FeeSuggestion struct {
	GasTipCap *big.Int // maxPriorityFeePerGas
	GasFeeCap *big.Int // maxFeePerGas
}

// TxResult is a generic send result.
type TxResult struct {
	Hash common.Hash
}
