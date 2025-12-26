package ethrpc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type rpcReq struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Method  string `json:"method"`
	Params  any    `json:"params"`
}

type rpcErr struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcRes struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int             `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *rpcErr         `json:"error,omitempty"`
}

func newHTTPClient() *http.Client {
	return &http.Client{Timeout: 15 * time.Second}
}

// Call performs a raw JSON-RPC call against the currently-active URL.
func (c *Client) Call(ctx context.Context, method string, params any, out any) error {
	url, err := c.activeURL()
	if err != nil {
		return err
	}

	body, err := json.Marshal(rpcReq{JSONRPC: "2.0", ID: 1, Method: method, Params: params})
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("ethrpc: http status %d", resp.StatusCode)
	}

	var res rpcRes
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return err
	}
	if res.Error != nil {
		return fmt.Errorf("ethrpc: %s (%d)", res.Error.Message, res.Error.Code)
	}
	if out != nil {
		return json.Unmarshal(res.Result, out)
	}
	return nil
}
