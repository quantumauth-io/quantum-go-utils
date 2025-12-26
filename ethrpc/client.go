package ethrpc

import (
	"context"
	"fmt"
	"math/big"
	"net/http"
	"sync"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/ethclient"
)

type Client struct {
	mu sync.RWMutex

	cfg *MultiConfig

	http *http.Client

	backend    *ethclient.Client
	backendURL string
}

func New(cfg *MultiConfig) (*Client, error) {
	if cfg == nil {
		return nil, fmt.Errorf("ethrpc: nil config")
	}
	if len(cfg.Networks) == 0 {
		return nil, fmt.Errorf("ethrpc: no networks configured")
	}
	cfg.Normalize()

	c := &Client{
		cfg:  cfg,
		http: newHTTPClient(),
	}
	// best effort: ensure backend if ActiveNetwork is set
	if cfg.ActiveNetwork != "" {
		_ = c.EnsureBackend(context.Background())
	}
	return c, nil
}

func (c *Client) Backend() bind.ContractBackend {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.backend
}

func (c *Client) EnsureBackend(ctx context.Context) error {
	url, err := c.activeURL()
	if err != nil {
		return err
	}

	c.mu.RLock()
	same := (c.backend != nil && c.backendURL == url)
	c.mu.RUnlock()
	if same {
		return nil
	}

	b, err := ethclient.DialContext(ctx, url)
	if err != nil {
		return fmt.Errorf("ethrpc: dial backend %q: %w", url, err)
	}

	c.mu.Lock()
	c.backend = b
	c.backendURL = url
	c.mu.Unlock()
	return nil
}

func (c *Client) UseNetwork(networkName string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.cfg.Networks[networkName]; !ok {
		return fmt.Errorf("ethrpc: unknown network %q", networkName)
	}
	c.cfg.ActiveNetwork = networkName

	n := c.cfg.Networks[networkName]
	if len(n.RPCs) == 0 {
		return fmt.Errorf("ethrpc: network %q has no rpcs", networkName)
	}

	if c.cfg.ActiveRPC == "" || !hasRPC(n.RPCs, c.cfg.ActiveRPC) {
		c.cfg.ActiveRPC = n.RPCs[0].Name
	}
	return nil
}

func (c *Client) UseRPC(rpcName string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	n, ok := c.cfg.Networks[c.cfg.ActiveNetwork]
	if !ok || c.cfg.ActiveNetwork == "" {
		return fmt.Errorf("ethrpc: active network not set")
	}
	if !hasRPC(n.RPCs, rpcName) {
		return fmt.Errorf("ethrpc: rpc %q not found in network %q", rpcName, c.cfg.ActiveNetwork)
	}
	c.cfg.ActiveRPC = rpcName
	return nil
}

func hasRPC(rpcs []RPC, name string) bool {
	for _, r := range rpcs {
		if r.Name == name {
			return true
		}
	}
	return false
}

func (c *Client) activeURL() (string, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.cfg.ActiveNetwork == "" {
		return "", fmt.Errorf("ethrpc: active network not set")
	}
	n, ok := c.cfg.Networks[c.cfg.ActiveNetwork]
	if !ok {
		return "", fmt.Errorf("ethrpc: unknown active network %q", c.cfg.ActiveNetwork)
	}
	if c.cfg.ActiveRPC == "" {
		return "", fmt.Errorf("ethrpc: active rpc not set for %q", c.cfg.ActiveNetwork)
	}
	for _, r := range n.RPCs {
		if r.Name == c.cfg.ActiveRPC {
			return r.URL, nil
		}
	}
	return "", fmt.Errorf("ethrpc: active rpc %q not found for %q", c.cfg.ActiveRPC, c.cfg.ActiveNetwork)
}

func (c *Client) SupportedNetworks() []NetworkInfo {
	if c == nil || c.cfg == nil {
		return nil
	}
	out := make([]NetworkInfo, 0, len(c.cfg.Networks))
	for name, n := range c.cfg.Networks {
		chainHex := n.ChainIDHex
		if chainHex == "" && n.ChainID != 0 {
			chainHex = BigToHexQuantity(new(big.Int).SetUint64(n.ChainID))
		}
		out = append(out, NetworkInfo{Name: name, ChainIDHex: NormalizeHex0x(chainHex)})
	}
	return out
}
