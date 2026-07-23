// Copyright 2022 Google LLC.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package client

// rpclite is a minimal RPC client that speaks the same gob-based wire protocol
// as net/rpc but does not import net/rpc itself. This avoids pulling in
// net/rpc's debug HTTP handler which depends on html/template, a known blocker
// for the Go linker's method dead code elimination (DCE) optimization.
//
// Wire protocol (identical to net/rpc):
//   - Client sends: gob-encoded request header, then gob-encoded args
//   - Server sends: gob-encoded response header, then gob-encoded reply
//
// The request/response structs mirror net/rpc.Request and net/rpc.Response
// exactly, so this client is compatible with existing net/rpc servers.

import (
	"encoding/gob"
	"errors"
	"io"
	"sync"
)

// request mirrors net/rpc.Request — must match exactly for wire compatibility.
type request struct {
	ServiceMethod string
	Seq           uint64
}

// response mirrors net/rpc.Response — must match exactly for wire compatibility.
type response struct {
	ServiceMethod string
	Seq           uint64
	Error         string
}

// rpcClient is a minimal replacement for net/rpc.Client.
type rpcClient struct {
	conn io.ReadWriteCloser
	enc  *gob.Encoder
	dec  *gob.Decoder
	mu   sync.Mutex
	seq  uint64
}

// newRPCClient creates a new RPC client, equivalent to rpc.NewClient.
func newRPCClient(conn io.ReadWriteCloser) *rpcClient {
	return &rpcClient{
		conn: conn,
		enc:  gob.NewEncoder(conn),
		dec:  gob.NewDecoder(conn),
	}
}

// Call invokes the named method, waits for it to complete, and returns the error status.
func (c *rpcClient) Call(serviceMethod string, args any, reply any) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.seq++
	req := request{ServiceMethod: serviceMethod, Seq: c.seq}

	if err := c.enc.Encode(&req); err != nil {
		return err
	}
	if err := c.enc.Encode(args); err != nil {
		return err
	}

	var resp response
	if err := c.dec.Decode(&resp); err != nil {
		return err
	}
	if err := c.dec.Decode(reply); err != nil {
		return err
	}
	if resp.Error != "" {
		return errors.New(resp.Error)
	}
	return nil
}

// Close closes the underlying connection.
func (c *rpcClient) Close() error {
	return c.conn.Close()
}
