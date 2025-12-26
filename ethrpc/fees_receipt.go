// ethrpc/fees_receipts.go
package ethrpc

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
)

// MaxPriorityFeePerGas returns the suggested priority fee (wei) (EIP-1559).
func (c *Client) MaxPriorityFeePerGas(ctx context.Context) (*big.Int, error) {
	var out string
	if err := c.Call(ctx, "eth_maxPriorityFeePerGas", []any{}, &out); err != nil {
		return nil, err
	}
	return HexQuantity(out).Big()
}

type FeeHistory struct {
	OldestBlock   string     `json:"oldestBlock"`
	BaseFeePerGas []string   `json:"baseFeePerGas"`
	GasUsedRatio  []float64  `json:"gasUsedRatio"`
	Reward        [][]string `json:"reward,omitempty"`
}

// FeeHistory queries eth_feeHistory.
// - blockCount is a hex quantity string like "0x5"
// - newestBlock usually "latest"
// - rewardPercentiles can be nil if you don’t need rewards
func (c *Client) FeeHistory(ctx context.Context, blockCount string, newestBlock BlockTag, rewardPercentiles []float64) (*FeeHistory, error) {
	var out FeeHistory
	params := []any{NormalizeHex0x(blockCount), string(newestBlock)}
	if rewardPercentiles != nil {
		params = append(params, rewardPercentiles)
	}
	if err := c.Call(ctx, "eth_feeHistory", params, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

type TxReceipt struct {
	TransactionHash   string `json:"transactionHash"`
	BlockHash         string `json:"blockHash,omitempty"`
	BlockNumber       string `json:"blockNumber,omitempty"`
	From              string `json:"from"`
	To                string `json:"to,omitempty"`
	ContractAddress   string `json:"contractAddress,omitempty"`
	GasUsed           string `json:"gasUsed,omitempty"`
	EffectiveGasPrice string `json:"effectiveGasPrice,omitempty"`
	Status            string `json:"status,omitempty"` // 0x1 success, 0x0 fail (post-byzantium)
	Logs              []any  `json:"logs,omitempty"`
}

// GetTransactionReceiptRaw returns nil, nil if the tx is not mined yet (JSON-RPC returns null).
// txHash may be 0x-prefixed or not; it will be normalized.
func (c *Client) GetTransactionReceiptRaw(ctx context.Context, txHash string) (*TxReceipt, error) {
	var raw jsonRaw // helper to detect null
	if err := c.Call(ctx, "eth_getTransactionReceipt", []any{NormalizeHex0x(txHash)}, &raw); err != nil {
		return nil, err
	}
	if raw.IsNull() {
		return nil, nil
	}
	var out TxReceipt
	if err := raw.UnmarshalInto(&out); err != nil {
		return nil, fmt.Errorf("ethrpc: unmarshal receipt: %w", err)
	}
	return &out, nil
}

// ---- tiny helper so we can detect "null" while still using c.Call ----

// jsonRaw holds raw JSON bytes.
type jsonRaw []byte

func (r *jsonRaw) UnmarshalJSON(b []byte) error {
	*r = append((*r)[:0], b...)
	return nil
}

func (r *jsonRaw) IsNull() bool {
	return len(*r) == 0 || string(*r) == "null"
}

func (r *jsonRaw) UnmarshalInto(v any) error {
	return json.Unmarshal([]byte(*r), v)
}
