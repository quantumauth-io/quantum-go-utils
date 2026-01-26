package evm

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"math/big"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient/simulated"
)

// SimulatedBlockchainClient is a deterministic in-memory chain for tests/CI.
// It uses go-evm's ethclient/simulated backend. :contentReference[oaicite:2]{index=2}
//
// Note: ethclient/simulated does NOT provide a native SubscribeNewHead.
// We emulate it by polling HeaderByNumber(nil) and pushing deltas.
type SimulatedBlockchainClient struct {
	backend *simulated.Backend
	client  simulated.Client

	// Optional: only if you still want to keep this pattern
	eventLogChannelMap      map[string][]chan<- types.Log
	eventLogChannelMapMutex *sync.Mutex

	chainID *big.Int
}

var _ BlockchainClient = (*SimulatedBlockchainClient)(nil)

type SimOptions struct {
	BlockGasLimit uint64
}

// NewSimulatedBlockchainClient creates a simulated chain with a funded genesis account.
// The simulated backend always uses chainID 1337. :contentReference[oaicite:3]{index=3}
func NewSimulatedBlockchainClient(genesisAlloc types.GenesisAlloc, opts SimOptions) *SimulatedBlockchainClient {
	if opts.BlockGasLimit == 0 {
		opts.BlockGasLimit = 100_000_000
	}

	b := simulated.NewBackend(
		genesisAlloc,
		simulated.WithBlockGasLimit(opts.BlockGasLimit),
	)

	return &SimulatedBlockchainClient{
		backend:                 b,
		client:                  b.Client(),
		eventLogChannelMap:      make(map[string][]chan<- types.Log, 10),
		eventLogChannelMapMutex: &sync.Mutex{},
		chainID:                 big.NewInt(1337),
	}
}

// NewSimulatedBlockchainClientWithAutoKey generates a key, funds it in genesis,
// and returns the client + keypair for convenience.
func NewSimulatedBlockchainClientWithAutoKey(initialBalanceWei *big.Int, opts SimOptions) (*SimulatedBlockchainClient, *ecdsa.PrivateKey, common.Address, error) {
	if initialBalanceWei == nil {
		initialBalanceWei = new(big.Int)
		initialBalanceWei.SetString("100000000000000000000", 10) // 100 ETH
	}

	priv, err := crypto.GenerateKey()
	if err != nil {
		return nil, nil, common.Address{}, err
	}

	addr := crypto.PubkeyToAddress(priv.PublicKey)
	alloc := types.GenesisAlloc{
		addr: {Balance: initialBalanceWei},
	}

	return NewSimulatedBlockchainClient(alloc, opts), priv, addr, nil
}

func (c *SimulatedBlockchainClient) Close() error {
	if c.backend == nil {
		return nil
	}
	return c.backend.Close()
}

// Commit seals a block and advances the chain. :contentReference[oaicite:4]{index=4}
func (c *SimulatedBlockchainClient) Commit() common.Hash {
	return c.backend.Commit()
}

// AdjustTime changes block timestamp and creates a new block. :contentReference[oaicite:5]{index=5}
func (c *SimulatedBlockchainClient) AdjustTime(d time.Duration) error {
	return c.backend.AdjustTime(d)
}

func (c *SimulatedBlockchainClient) Rollback() {
	c.backend.Rollback()
}

func (c *SimulatedBlockchainClient) Fork(parent common.Hash) error {
	return c.backend.Fork(parent)
}

// --- BlockchainClient methods (mostly just forwarded to c.client) ---

func (c *SimulatedBlockchainClient) TransactionByHash(ctx context.Context, hash common.Hash) (*types.Transaction, bool, error) {
	return c.client.TransactionByHash(ctx, hash)
}

func (c *SimulatedBlockchainClient) TransactionReceipt(ctx context.Context, hash common.Hash) (*types.Receipt, error) {
	return c.client.TransactionReceipt(ctx, hash)
}

func (c *SimulatedBlockchainClient) BalanceAt(ctx context.Context, account common.Address, blockNumber *big.Int) (*big.Int, error) {
	return c.client.BalanceAt(ctx, account, blockNumber)
}

func (c *SimulatedBlockchainClient) NetworkID(ctx context.Context) (*big.Int, error) {
	// Sim backend always chainID 1337; NetworkID can be same here.
	return new(big.Int).Set(c.chainID), nil
}

func (c *SimulatedBlockchainClient) NonceAt(ctx context.Context, account common.Address, blockNumber *big.Int) (uint64, error) {
	return c.client.NonceAt(ctx, account, blockNumber)
}

func (c *SimulatedBlockchainClient) PendingNonceAt(ctx context.Context, account common.Address) (uint64, error) {
	return c.client.PendingNonceAt(ctx, account)
}

func (c *SimulatedBlockchainClient) SuggestGasPrice(ctx context.Context) (*big.Int, error) {
	return c.client.SuggestGasPrice(ctx)
}

func (c *SimulatedBlockchainClient) ChainID(ctx context.Context) (*big.Int, error) {
	return new(big.Int).Set(c.chainID), nil
}

func (c *SimulatedBlockchainClient) CallContract(ctx context.Context, msg ethereum.CallMsg, blockNumber *big.Int) ([]byte, error) {
	return c.client.CallContract(ctx, msg, blockNumber)
}

func (c *SimulatedBlockchainClient) BlockByNumber(ctx context.Context, number *big.Int) (*types.Block, error) {
	return c.client.BlockByNumber(ctx, number)
}

func (c *SimulatedBlockchainClient) TransactionCount(ctx context.Context, hash common.Hash) (uint, error) {
	return c.client.TransactionCount(ctx, hash)
}

func (c *SimulatedBlockchainClient) HeaderByNumber(ctx context.Context, number *big.Int) (*types.Header, error) {
	return c.client.HeaderByNumber(ctx, number)
}

// --- bind.ContractCaller / Transactor / Filterer ---

func (c *SimulatedBlockchainClient) CodeAt(ctx context.Context, contract common.Address, blockNumber *big.Int) ([]byte, error) {
	return c.client.CodeAt(ctx, contract, blockNumber)
}

func (c *SimulatedBlockchainClient) PendingCodeAt(ctx context.Context, account common.Address) ([]byte, error) {
	return c.client.PendingCodeAt(ctx, account)
}

func (c *SimulatedBlockchainClient) PendingCallContract(ctx context.Context, call ethereum.CallMsg) ([]byte, error) {
	return c.client.PendingCallContract(ctx, call)
}

func (c *SimulatedBlockchainClient) SuggestGasTipCap(ctx context.Context) (*big.Int, error) {
	return c.client.SuggestGasTipCap(ctx)
}

func (c *SimulatedBlockchainClient) EstimateGas(ctx context.Context, call ethereum.CallMsg) (uint64, error) {
	return c.client.EstimateGas(ctx, call)
}
func (c *SimulatedBlockchainClient) FeeHistory(ctx context.Context, blockCount uint64, lastBlock *big.Int, rewardPercentiles []float64) (*ethereum.FeeHistory, error) {
	return c.client.FeeHistory(ctx, blockCount, lastBlock, rewardPercentiles)
}

func (c *SimulatedBlockchainClient) SendTransaction(ctx context.Context, tx *types.Transaction) error {
	return c.client.SendTransaction(ctx, tx)
}

func (c *SimulatedBlockchainClient) FilterLogs(ctx context.Context, q ethereum.FilterQuery) ([]types.Log, error) {
	return c.client.FilterLogs(ctx, q)
}

func (c *SimulatedBlockchainClient) SubscribeFilterLogs(ctx context.Context, q ethereum.FilterQuery, ch chan<- types.Log) (ethereum.Subscription, error) {
	return c.client.SubscribeFilterLogs(ctx, q, ch)
}

// SubscribeNewHead is emulated via polling because ethclient/simulated.Client does not provide native new-head subscriptions.
func (c *SimulatedBlockchainClient) SubscribeNewHead(ctx context.Context, ch chan<- *types.Header) (ethereum.Subscription, error) {
	if ch == nil {
		return nil, errors.New("SubscribeNewHead: nil channel")
	}
	return newPollingHeadSub(ctx, c.client, ch, 250*time.Millisecond), nil
}

// ---- polling subscription implementation ----

type pollingHeadSub struct {
	errCh  chan error
	cancel context.CancelFunc
	once   sync.Once
}

func newPollingHeadSub(ctx context.Context, cli simulated.Client, out chan<- *types.Header, every time.Duration) ethereum.Subscription {
	subCtx, cancel := context.WithCancel(ctx)

	s := &pollingHeadSub{
		errCh:  make(chan error, 1),
		cancel: cancel,
	}

	go func() {
		defer close(s.errCh)

		t := time.NewTicker(every)
		defer t.Stop()

		var last uint64
		var initialized bool

		for {
			select {
			case <-subCtx.Done():
				return
			case <-t.C:
				h, err := cli.HeaderByNumber(subCtx, nil)
				if err != nil {
					// push the error once; subscriber sees it via Err()
					s.errCh <- err
					return
				}
				if h == nil || h.Number == nil {
					continue
				}
				n := h.Number.Uint64()
				if !initialized {
					last = n
					initialized = true
					out <- h
					continue
				}
				if n > last {
					last = n
					out <- h
				}
			}
		}
	}()

	return s
}

func (s *pollingHeadSub) Unsubscribe() {
	s.once.Do(func() { s.cancel() })
}

func (s *pollingHeadSub) Err() <-chan error {
	return s.errCh
}
