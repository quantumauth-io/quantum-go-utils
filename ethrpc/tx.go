package ethrpc

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// ---------- cheap helpers ----------

func ValidateRawTxHex(raw string) error {
	s := Strip0x(raw)
	if s == "" || len(s)%2 != 0 {
		return fmt.Errorf("invalid raw tx hex length")
	}
	_, err := hex.DecodeString(s)
	return err
}

// ---------- JSON-RPC wrappers ----------

func (c *Client) ChainIDHex(ctx context.Context) (string, error) {
	var out string
	if err := c.Call(ctx, "eth_chainId", []any{}, &out); err != nil {
		return "", err
	}
	return out, nil
}

func (c *Client) ChainID(ctx context.Context) (*big.Int, error) {
	hexID, err := c.ChainIDHex(ctx)
	if err != nil {
		return nil, err
	}
	return HexQuantity(hexID).Big()
}

func (c *Client) BlockNumber(ctx context.Context) (*big.Int, error) {
	var out string
	if err := c.Call(ctx, "eth_blockNumber", []any{}, &out); err != nil {
		return nil, err
	}
	return HexQuantity(out).Big()
}

func (c *Client) GetBalance(ctx context.Context, address string, blockTag BlockTag) (*big.Int, error) {
	addr := NormalizeHex0x(address)
	var out string
	if err := c.Call(ctx, "eth_getBalance", []any{addr, string(blockTag)}, &out); err != nil {
		return nil, err
	}
	return HexQuantity(out).Big()
}

func (c *Client) GetTransactionCount(ctx context.Context, address string, blockTag BlockTag) (*big.Int, error) {
	addr := NormalizeHex0x(address)
	var out string
	if err := c.Call(ctx, "eth_getTransactionCount", []any{addr, string(blockTag)}, &out); err != nil {
		return nil, err
	}
	return HexQuantity(out).Big()
}

func (c *Client) GasPrice(ctx context.Context) (*big.Int, error) {
	var out string
	if err := c.Call(ctx, "eth_gasPrice", []any{}, &out); err != nil {
		return nil, err
	}
	return HexQuantity(out).Big()
}

func (c *Client) GetCode(ctx context.Context, address string, blockTag BlockTag) (string, error) {
	addr := NormalizeHex0x(address)
	var out string
	err := c.Call(ctx, "eth_getCode", []any{addr, string(blockTag)}, &out)
	return out, err
}

func (c *Client) CallContract(ctx context.Context, msg CallMsg, blockTag BlockTag) (string, error) {
	if msg.From != "" {
		msg.From = NormalizeHex0x(msg.From)
	}
	if msg.To != "" {
		msg.To = NormalizeHex0x(msg.To)
	}
	if msg.Data != "" {
		msg.Data = NormalizeHex0x(msg.Data)
	}
	var out string
	err := c.Call(ctx, "eth_call", []any{msg, string(blockTag)}, &out)
	return out, err
}

func (c *Client) EstimateGas(ctx context.Context, msg CallMsg) (*big.Int, error) {
	if msg.From != "" {
		msg.From = NormalizeHex0x(msg.From)
	}
	if msg.To != "" {
		msg.To = NormalizeHex0x(msg.To)
	}
	if msg.Data != "" {
		msg.Data = NormalizeHex0x(msg.Data)
	}
	var out string
	if err := c.Call(ctx, "eth_estimateGas", []any{msg}, &out); err != nil {
		return nil, err
	}
	return HexQuantity(out).Big()
}

func (c *Client) SendRawTransaction(ctx context.Context, rawTxHex string) (common.Hash, error) {
	rawTxHex = NormalizeHex0x(rawTxHex)
	var out string
	if err := c.Call(ctx, "eth_sendRawTransaction", []any{rawTxHex}, &out); err != nil {
		return common.Hash{}, err
	}
	return common.HexToHash(out), nil
}

// ---------- ethclient-backed helpers (recommended for deploy + receipts) ----------

func (c *Client) PendingNonceAt(ctx context.Context, addr common.Address) (uint64, error) {
	if err := c.EnsureBackend(ctx); err != nil {
		return 0, err
	}
	return c.backend.PendingNonceAt(ctx, addr)
}

func (c *Client) SuggestGasTipCap(ctx context.Context) (*big.Int, error) {
	if err := c.EnsureBackend(ctx); err != nil {
		return nil, err
	}
	return c.backend.SuggestGasTipCap(ctx)
}

func (c *Client) SuggestGasPrice(ctx context.Context) (*big.Int, error) {
	if err := c.EnsureBackend(ctx); err != nil {
		return nil, err
	}
	return c.backend.SuggestGasPrice(ctx)
}

func (c *Client) HeaderByNumber(ctx context.Context, number *big.Int) (*types.Header, error) {
	if err := c.EnsureBackend(ctx); err != nil {
		return nil, err
	}
	return c.backend.HeaderByNumber(ctx, number)
}

func (c *Client) TransactionReceipt(ctx context.Context, txHash common.Hash) (*types.Receipt, error) {
	if err := c.EnsureBackend(ctx); err != nil {
		return nil, err
	}
	return c.backend.TransactionReceipt(ctx, txHash)
}

func (c *Client) WaitMined(ctx context.Context, txHash common.Hash, poll time.Duration) (*types.Receipt, error) {
	if poll <= 0 {
		poll = 2 * time.Second
	}
	for {
		r, err := c.TransactionReceipt(ctx, txHash)
		if err == nil && r != nil {
			return r, nil
		}
		// geth returns "not found" until mined
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(poll):
		}
	}
}

// ---------- Transactor helpers (generic deploy support) ----------

// NewTransactorFromPrivKeyHex creates a bind.TransactOpts for the active chain.
func (c *Client) NewTransactorFromPrivKeyHex(ctx context.Context, privKeyHex string) (*bind.TransactOpts, common.Address, error) {
	privKeyHex = Strip0x(privKeyHex)
	pk, err := crypto.HexToECDSA(privKeyHex)
	if err != nil {
		return nil, common.Address{}, fmt.Errorf("ethrpc: invalid privkey: %w", err)
	}
	return c.NewTransactorFromPrivKey(ctx, pk)
}

func (c *Client) NewTransactorFromPrivKey(ctx context.Context, pk *ecdsa.PrivateKey) (*bind.TransactOpts, common.Address, error) {
	if pk == nil {
		return nil, common.Address{}, fmt.Errorf("ethrpc: nil privkey")
	}
	chainID, err := c.ChainID(ctx)
	if err != nil {
		return nil, common.Address{}, err
	}
	from := crypto.PubkeyToAddress(pk.PublicKey)

	opts, err := bind.NewKeyedTransactorWithChainID(pk, chainID)
	if err != nil {
		return nil, common.Address{}, err
	}
	opts.From = from
	return opts, from, nil
}

// FillGasEIP1559 sets GasTipCap/GasFeeCap (if chain supports) and optionally estimates gas.
func (c *Client) FillGasEIP1559(ctx context.Context, opts *bind.TransactOpts, to *common.Address, data []byte, value *big.Int) error {
	if err := c.EnsureBackend(ctx); err != nil {
		return err
	}
	if opts == nil {
		return fmt.Errorf("ethrpc: nil transact opts")
	}

	tip, err := c.backend.SuggestGasTipCap(ctx)
	if err != nil {
		return err
	}
	head, err := c.backend.HeaderByNumber(ctx, nil)
	if err != nil {
		return err
	}
	if head.BaseFee == nil {
		// pre-1559: caller should use GasPrice
		return nil
	}

	// Simple default: feeCap = 2*baseFee + tip
	feeCap := new(big.Int).Mul(head.BaseFee, big.NewInt(2))
	feeCap.Add(feeCap, tip)

	opts.GasTipCap = tip
	opts.GasFeeCap = feeCap

	// Estimate gas if possible
	msg := ethereum.CallMsg{
		From:      opts.From,
		To:        to,
		Data:      data,
		Value:     value,
		GasTipCap: tip,
		GasFeeCap: feeCap,
	}
	gas, err := c.backend.EstimateGas(ctx, msg)
	if err == nil && gas > 0 && opts.GasLimit == 0 {
		// add small buffer
		opts.GasLimit = uint64(float64(gas) * 1.15)
	}
	return nil
}

// FillGasLegacy sets GasPrice and estimates gas limit (legacy style).
func (c *Client) FillGasLegacy(ctx context.Context, opts *bind.TransactOpts, to *common.Address, data []byte, value *big.Int) error {
	if err := c.EnsureBackend(ctx); err != nil {
		return err
	}
	if opts == nil {
		return fmt.Errorf("ethrpc: nil transact opts")
	}

	gp, err := c.backend.SuggestGasPrice(ctx)
	if err != nil {
		return err
	}
	opts.GasPrice = gp

	msg := ethereum.CallMsg{
		From:  opts.From,
		To:    to,
		Data:  data,
		Value: value,
	}
	gas, err := c.backend.EstimateGas(ctx, msg)
	if err == nil && gas > 0 && opts.GasLimit == 0 {
		opts.GasLimit = uint64(float64(gas) * 1.15)
	}
	return nil
}
