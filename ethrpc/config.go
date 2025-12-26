package ethrpc

// MultiConfig holds many networks and lets you select an active network + rpc.
type MultiConfig struct {
	Networks      map[string]NetworkConfig `json:"networks" yaml:"networks"`
	ActiveNetwork string                   `json:"activeNetwork" yaml:"activeNetwork"`
	ActiveRPC     string                   `json:"activeRPC" yaml:"activeRPC"`
}

// NetworkConfig describes a network and its RPC endpoints.
type NetworkConfig struct {
	Name       string `json:"name" yaml:"name"`
	ChainID    uint64 `json:"chainId" yaml:"chainId"`
	ChainIDHex string `json:"chainIdHex" yaml:"chainIdHex"`

	RPCs []RPC `json:"rpcs" yaml:"rpcs"`
}

// RPC describes one endpoint in a network.
type RPC struct {
	Name string `json:"name" yaml:"name"`
	URL  string `json:"url" yaml:"url"`
}

type NetworkInfo struct {
	Name       string `json:"name"`
	ChainIDHex string `json:"chainIdHex"`
}

func (mc *MultiConfig) Normalize() {
	if mc == nil {
		return
	}
	for name, n := range mc.Networks {
		n.Name = name
		mc.Networks[name] = n
	}
}
