// Copyright 2025 Google LLC
//
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

// This file contains tests for the test passthrough proxy.
package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// TestProxyHandlerHTTP tests the proxy for a standard HTTP request.
func TestProxyHandlerHTTP(t *testing.T) {
	// 1. Create a destination server that the proxy will forward requests to.
	// This server will simply respond with a known message.
	destinationServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// We can verify that the request was correctly proxied by checking headers.
		if r.Header.Get("X-Proxied-By") != "Go-Test" {
			t.Errorf("Expected 'X-Proxied-By' header to be 'Go-Test', but got '%s'", r.Header.Get("X-Proxied-By"))
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Success from destination"))
	}))
	defer destinationServer.Close()

	// 2. Create the proxy server using our ProxyHandler from proxy.go.
	proxyServer := httptest.NewServer(http.HandlerFunc(ProxyHandler))
	defer proxyServer.Close()

	// 3. Configure an HTTP client to use our proxy server.
	proxyURL, err := url.Parse(proxyServer.URL)
	if err != nil {
		t.Fatalf("Failed to parse proxy URL: %v", err)
	}

	// The transport's Proxy field tells the client where to send requests.
	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
	}
	client := &http.Client{
		Transport: transport,
	}

	// 4. Create a request to the *destination server*. The client's transport
	// will ensure it goes through the proxy first.
	req, err := http.NewRequest("GET", destinationServer.URL, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	// Add a custom header to verify it gets passed through the proxy.
	req.Header.Add("X-Proxied-By", "Go-Test")

	// 5. Execute the request.
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to execute request via proxy: %v", err)
	}
	defer resp.Body.Close()

	// 6. Assert that the response is what we expect from the destination server.
	// This confirms the proxy successfully forwarded the request and returned the response.
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status code %d, but got %d", http.StatusOK, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	expectedBody := "Success from destination"
	if string(body) != expectedBody {
		t.Errorf("Expected response body '%s', but got '%s'", expectedBody, string(body))
	}
}
