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
	"bytes"
	"errors"
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
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("Close: got %v, want nil err", err)
		}
	})

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
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("Close: got %v, want nil err", err)
		}
	})

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
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("Close: got %v, want nil err", err)
		}
	})

	var reply EchoReply
	err := client.Call("EchoService.NoSuchMethod", EchoArgs{}, &reply)
	if err == nil {
		t.Fatal("Call unknown method: got nil, want error")
	}
}

// SignerService mirrors the real signer's method signatures: every reply is a
// pointer to a slice rather than to a struct, which is what makes the error
// path below worth testing.
type SignerService struct{}

// SignerArgs are the arguments for the Sign and FailingSign methods.
type SignerArgs struct {
	Digest []byte
}

// Sign returns a stand-in signature for the given digest.
func (s *SignerService) Sign(args SignerArgs, reply *[]byte) error {
	*reply = append([]byte("signed:"), args.Digest...)
	return nil
}

// FailingSign always fails, standing in for a signer that rejects a request.
func (s *SignerService) FailingSign(args SignerArgs, reply *[]byte) error {
	return errors.New("unsupported hash function")
}

// rpcCaller is the subset of net/rpc.Client that rpcClient replaces, letting a
// test drive both implementations through the same calls.
type rpcCaller interface {
	Call(serviceMethod string, args any, reply any) error
	Close() error
}

// newSignerServer registers SignerService on a net/rpc server reachable over an
// in-memory pipe and returns the client end of the connection.
func newSignerServer(t *testing.T) io.ReadWriteCloser {
	t.Helper()
	clientRead, serverWrite := io.Pipe()
	serverRead, clientWrite := io.Pipe()

	srv := rpc.NewServer()
	if err := srv.Register(&SignerService{}); err != nil {
		t.Fatal(err)
	}
	go srv.ServeConn(&Connection{serverRead, serverWrite})

	return &Connection{clientRead, clientWrite}
}

// TestRPCLite_MatchesNetRPC pins rpcClient to net/rpc.Client's observable
// behaviour: for each call, both clients talk to an identical net/rpc server and
// must agree on the reply and on the error text.
func TestRPCLite_MatchesNetRPC(t *testing.T) {
	testCases := []struct {
		name      string
		method    string
		digest    []byte
		wantReply []byte
		wantErr   string
	}{
		{
			name:      "successful call",
			method:    "SignerService.Sign",
			digest:    []byte("digest"),
			wantReply: []byte("signed:digest"),
		},
		{
			name:    "error returned by the service method",
			method:  "SignerService.FailingSign",
			digest:  []byte("digest"),
			wantErr: "unsupported hash function",
		},
		{
			name:    "unknown method",
			method:  "SignerService.NoSuchMethod",
			digest:  []byte("digest"),
			wantErr: "rpc: can't find method SignerService.NoSuchMethod",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			clients := map[string]rpcCaller{
				"net/rpc": rpc.NewClient(newSignerServer(t)),
				"rpclite": newRPCClient(newSignerServer(t)),
			}

			replies := map[string][]byte{}
			errs := map[string]string{}
			for name, client := range clients {
				t.Cleanup(func() {
					if err := client.Close(); err != nil {
						t.Errorf("%s: Close: got %v, want nil err", name, err)
					}
				})

				var reply []byte
				err := client.Call(testCase.method, SignerArgs{Digest: testCase.digest}, &reply)
				replies[name] = reply
				if err != nil {
					errs[name] = err.Error()
				}

				if errs[name] != testCase.wantErr {
					t.Errorf("%s: Call error = %q, want %q", name, errs[name], testCase.wantErr)
				}
				if !bytes.Equal(reply, testCase.wantReply) {
					t.Errorf("%s: Call reply = %q, want %q", name, reply, testCase.wantReply)
				}
			}

			// The point of the exercise: rpclite must be indistinguishable from
			// net/rpc, not merely correct in isolation.
			if errs["rpclite"] != errs["net/rpc"] {
				t.Errorf("error mismatch:\n  rpclite: %q\n  net/rpc: %q", errs["rpclite"], errs["net/rpc"])
			}
			if !bytes.Equal(replies["rpclite"], replies["net/rpc"]) {
				t.Errorf("reply mismatch:\n  rpclite: %q\n  net/rpc: %q", replies["rpclite"], replies["net/rpc"])
			}
		})
	}
}
