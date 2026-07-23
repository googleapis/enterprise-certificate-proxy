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

import (
	"io"
	"net/rpc"
	"testing"
)

// EchoService is a trivial RPC service for testing wire compatibility.
type EchoService struct{}

// EchoArgs are the arguments for the Echo method.
type EchoArgs struct {
	Msg string
}

// EchoReply is the reply from the Echo method.
type EchoReply struct {
	Msg string
}

// Echo returns the input message as-is.
func (e *EchoService) Echo(args EchoArgs, reply *EchoReply) error {
	reply.Msg = args.Msg
	return nil
}

// newTestClientServer creates a connected rpclite client and net/rpc server
// pair over an in-memory pipe, verifying wire compatibility.
func newTestClientServer(t *testing.T) *rpcClient {
	t.Helper()
	clientRead, serverWrite := io.Pipe()
	serverRead, clientWrite := io.Pipe()

	srv := rpc.NewServer()
	if err := srv.Register(&EchoService{}); err != nil {
		t.Fatal(err)
	}

	go srv.ServeConn(&Connection{serverRead, serverWrite})

	return newRPCClient(&Connection{clientRead, clientWrite})
}

func TestRPCLite_WireCompatibility(t *testing.T) {
	client := newTestClientServer(t)
	defer client.Close()

	var reply EchoReply
	if err := client.Call("EchoService.Echo", EchoArgs{Msg: "hello"}, &reply); err != nil {
		t.Fatalf("Call: got %v, want nil", err)
	}
	if reply.Msg != "hello" {
		t.Errorf("Call: got reply %q, want %q", reply.Msg, "hello")
	}
}

func TestRPCLite_MultipleCalls(t *testing.T) {
	client := newTestClientServer(t)
	defer client.Close()

	for i, msg := range []string{"first", "second", "third"} {
		var reply EchoReply
		if err := client.Call("EchoService.Echo", EchoArgs{Msg: msg}, &reply); err != nil {
			t.Fatalf("Call %d: got %v, want nil", i, err)
		}
		if reply.Msg != msg {
			t.Errorf("Call %d: got reply %q, want %q", i, reply.Msg, msg)
		}
	}
}

func TestRPCLite_UnknownMethod(t *testing.T) {
	client := newTestClientServer(t)
	defer client.Close()

	var reply EchoReply
	err := client.Call("EchoService.NoSuchMethod", EchoArgs{}, &reply)
	if err == nil {
		t.Fatal("Call unknown method: got nil, want error")
	}
}
