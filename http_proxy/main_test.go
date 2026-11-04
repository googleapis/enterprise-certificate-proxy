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

// This file contains unit tests for the ECP proxy.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	testPort = 8080
)

var (
	testPath = fmt.Sprintf("http://localhost:%d/some/path", testPort)
)

func TestAppConfigFromFlags(t *testing.T) {
	tests := []struct {
		name         string
		args         []string
		envAuthToken string
		wantErr      bool
		want         *AppConfig
	}{
		{
			name:         "Missing Nonce",
			args:         []string{"-port", "8080", "-enterprise_certificate_file_path", "/path/to/cert.json"},
			envAuthToken: "test-auth-token",
			wantErr:      true,
		},
		{
			name:         "Missing Port",
			args:         []string{"-enterprise_certificate_file_path", "/path/to/cert.json", "-nonce_token", "abc"},
			envAuthToken: "test-auth-token",
			wantErr:      true,
		},
		{
			name:         "Invalid Port (zero)",
			args:         []string{"-port", "0", "-enterprise_certificate_file_path", "/path/to/cert.json", "-nonce_token", "abc"},
			envAuthToken: "test-auth-token",
			wantErr:      true,
		},
		{
			name:         "Invalid Port (negative)",
			args:         []string{"-port", "-1", "-enterprise_certificate_file_path", "/path/to/cert.json", "-nonce_token", "abc"},
			envAuthToken: "test-auth-token",
			wantErr:      true,
		},
		{
			name:         "Missing Certificate Path",
			args:         []string{"-port", "8080", "-nonce_token", "abc"},
			envAuthToken: "test-auth-token",
			wantErr:      false,
			want: &AppConfig{
				Port:       8080,
				NonceToken: "abc",
				AuthToken:  "test-auth-token",
			},
		},
		{
			name:         "Empty Certificate Path",
			args:         []string{"-port", "8080", "-enterprise_certificate_file_path", "", "-nonce_token", "abc"},
			envAuthToken: "test-auth-token",
			wantErr:      false,
			want: &AppConfig{
				Port:       8080,
				NonceToken: "abc",
				AuthToken:  "test-auth-token",
			},
		},
		{
			name:         "Happy Path with Optional Proxy URL",
			args:         []string{"-port", "8080", "-enterprise_certificate_file_path", "/path/to/cert.json", "-gcloud_configured_upstream_proxy_url", "http://proxy.example.com", "-nonce_token", "abc"},
			envAuthToken: "test-auth-token",
			wantErr:      false,
			want: &AppConfig{
				Port:                             8080,
				EnterpriseCertificateFilePath:    "/path/to/cert.json",
				GcloudConfiguredUpstreamProxyURL: "http://proxy.example.com",
				NonceToken:                       "abc",
				AuthToken:                        "test-auth-token",
			},
		},
		{
			name:         "Happy Path with Nonce Token",
			args:         []string{"-port", "8080", "-nonce_token", "my-secret-token"},
			envAuthToken: "test-auth-token",
			wantErr:      false,
			want: &AppConfig{
				Port:       8080,
				NonceToken: "my-secret-token",
				AuthToken:  "test-auth-token",
			},
		},
		{
			name:         "Missing Auth Token Env Var (Backward Compatibility with Old gcloud)",
			args:         []string{"-port", "8080", "-nonce_token", "abc"},
			envAuthToken: "",
			wantErr:      false,
			want: &AppConfig{
				Port:       8080,
				NonceToken: "abc",
				AuthToken:  "",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(authTokenEnvVar, tt.envAuthToken)

			// Each test needs its own flag set.
			fs := flag.NewFlagSet(tt.name, flag.ContinueOnError)
			// Discard output to avoid polluting test logs.
			fs.SetOutput(io.Discard)

			// Temporarily replace the default command-line flags with our test set.
			originalCommandLine := flag.CommandLine
			flag.CommandLine = fs
			defer func() { flag.CommandLine = originalCommandLine }()

			// Temporarily replace os.Args to simulate command-line arguments.
			originalArgs := os.Args
			os.Args = append([]string{tt.name}, tt.args...)
			defer func() { os.Args = originalArgs }()

			got, err := newAppConfigFromFlags()

			if (err != nil) != tt.wantErr {
				t.Errorf("newProxyConfigFromFlags() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if got.Port != tt.want.Port {
					t.Errorf("newProxyConfigFromFlags() Port = %v, want %v", got.Port, tt.want.Port)
				}
				if got.EnterpriseCertificateFilePath != tt.want.EnterpriseCertificateFilePath {
					t.Errorf("newProxyConfigFromFlags() EnterpriseCertificateFilePath = %v, want %v", got.EnterpriseCertificateFilePath, tt.want.EnterpriseCertificateFilePath)
				}
				if got.GcloudConfiguredUpstreamProxyURL != tt.want.GcloudConfiguredUpstreamProxyURL {
					t.Errorf("newProxyConfigFromFlags() GcloudConfiguredUpstreamProxyURL = %v, want %v", got.GcloudConfiguredUpstreamProxyURL, tt.want.GcloudConfiguredUpstreamProxyURL)
				}
				if got.NonceToken != tt.want.NonceToken {
					t.Errorf("newProxyConfigFromFlags() NonceToken = %v, want %v", got.NonceToken, tt.want.NonceToken)
				}
				if got.AuthToken != tt.want.AuthToken {
					t.Errorf("newProxyConfigFromFlags() AuthToken = %v, want %v", got.AuthToken, tt.want.AuthToken)
				}
			}
		})
	}
}

func TestWriteError(t *testing.T) {
	rr := httptest.NewRecorder()
	originalErr := errors.New("original error")
	errorMsg := "test error message"
	statusCode := http.StatusInternalServerError

	writeError(rr, originalErr, errorMsg, statusCode)

	if rr.Code != statusCode {
		t.Errorf("writeError() status code = %v, want %v", rr.Code, statusCode)
	}

	if contentType := rr.Header().Get("Content-Type"); contentType != "application/json" {
		t.Errorf("writeError() Content-Type header = %q, want %q", contentType, "application/json")
	}

	if proxyError := rr.Header().Get(ecpInternalErrorHeader); proxyError != "true" {
		t.Errorf("writeError() %s header = %q, want %q", ecpInternalErrorHeader, proxyError, "true")
	}

	var resp ErrorResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("writeError() failed to decode response body: %v", err)
	}

	if resp.Code != statusCode {
		t.Errorf("writeError() response body code = %v, want %v", resp.Code, statusCode)
	}

	if resp.Message != errorMsg {
		t.Errorf("writeError() response body message = %q, want %q", resp.Message, errorMsg)
	}

	if resp.Error != originalErr.Error() {
		t.Errorf("writeError() response body error = %q, want %q", resp.Error, originalErr.Error())
	}
}

// mockRoundTripper is a mock implementation of http.RoundTripper for testing purposes.
type mockRoundTripper struct {
	// capturedRequest stores the last http.Request that was "transported".
	capturedRequest *http.Request
	// roundTripError can be set to simulate a transport error.
	roundTripError error
	// responseToReturn is the http.Response to return from RoundTrip.
	responseToReturn *http.Response
}

// RoundTrip captures the request and returns a predefined response or error.
func (m *mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	m.capturedRequest = req
	if m.roundTripError != nil {
		return nil, m.roundTripError
	}
	if m.responseToReturn != nil {
		return m.responseToReturn, nil
	}
	// Default successful response
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewBufferString("mock response")),
		Header:     make(http.Header),
	}, nil
}

func NewProxyConfigForTest() *ProxyConfig {
	proxyConfig := newDefaultProxyConfig()
	proxyConfig.Port = testPort
	return proxyConfig
}

// TestNewECPProxyHandler tests the core proxy handler logic.
func TestNewECPProxyHandler(t *testing.T) {
	tests := []struct {
		name               string
		targetHostHeader   string
		expectedStatusCode int
		expectErrorHeader  bool
		roundTripperError  error
		validateDirector   bool
	}{
		{
			name:               "valid_request",
			targetHostHeader:   "storage.mtls.googleapis.com",
			expectedStatusCode: http.StatusOK,
			expectErrorHeader:  false,
			validateDirector:   true,
		},
		{
			name:               "valid_non_mtls_google_api_request",
			targetHostHeader:   "oauth2.googleapis.com",
			expectedStatusCode: http.StatusOK,
			expectErrorHeader:  false,
			validateDirector:   true,
		},
		{
			name:               "missing_target_host_header",
			targetHostHeader:   "",
			expectedStatusCode: http.StatusBadRequest,
			expectErrorHeader:  true,
		},
		{
			name:               "reverse_proxy_error_handling",
			targetHostHeader:   "storage.mtls.googleapis.com",
			expectedStatusCode: http.StatusBadGateway,
			expectErrorHeader:  true,
			roundTripperError:  fmt.Errorf("mock transport error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRT := &mockRoundTripper{
				roundTripError: tt.roundTripperError,
			}
			handler := newECPProxyHandler(mockRT)

			req := httptest.NewRequest(http.MethodGet, testPath, nil)
			if tt.targetHostHeader != "" {
				req.Header.Set(targetHostHeader, tt.targetHostHeader)
			}
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			// Check status code
			if rr.Code != tt.expectedStatusCode {
				t.Errorf("Expected status code %d, got %d", tt.expectedStatusCode, rr.Code)
			}

			// Check for custom error header
			if tt.expectErrorHeader && rr.Header().Get(ecpInternalErrorHeader) == "" {
				t.Errorf("Expected %s header to be present, but it was missing", ecpInternalErrorHeader)
			}
			if !tt.expectErrorHeader && rr.Header().Get(ecpInternalErrorHeader) != "" {
				t.Errorf("Did not expect %s header to be present, but it was: %s", ecpInternalErrorHeader, rr.Header().Get(ecpInternalErrorHeader))
			}

			// If it's a valid request, validate director logic
			if tt.validateDirector && tt.expectedStatusCode == http.StatusOK {
				if mockRT.capturedRequest == nil {
					t.Fatal("mockRoundTripper did not capture any request")
				}

				// Verify URL and Host rewrite
				if mockRT.capturedRequest.URL.Scheme != "https" {
					t.Errorf("Expected scheme to be 'https', got %s", mockRT.capturedRequest.URL.Scheme)
				}
				if mockRT.capturedRequest.URL.Host != tt.targetHostHeader {
					t.Errorf("Expected URL host to be %s, got %s", tt.targetHostHeader, mockRT.capturedRequest.URL.Host)
				}
				if mockRT.capturedRequest.Host != tt.targetHostHeader {
					t.Errorf("Expected Host header to be %s, got %s", tt.targetHostHeader, mockRT.capturedRequest.Host)
				}

				// Verify custom header removal
				if mockRT.capturedRequest.Header.Get(targetHostHeader) != "" {
					t.Errorf("Expected %s header to be removed from outgoing request, but it was present", targetHostHeader)
				}
			}

			// For error cases, check the error response body structure
			if tt.expectErrorHeader {
				var errResp ErrorResponse
				err := json.Unmarshal(rr.Body.Bytes(), &errResp)
				if err != nil {
					t.Fatalf("Failed to unmarshal error response: %v", err)
				}
				if errResp.Code != tt.expectedStatusCode {
					t.Errorf("Expected error response code %d, got %d", tt.expectedStatusCode, errResp.Code)
				}
				if errResp.Message == "" {
					t.Errorf("Expected error response message to be non-empty")
				}
				if errResp.Error == "" {
					t.Errorf("Expected error response 'Error' field to be non-empty")
				}
			}
		})
	}
}

// TestNewECPProxyHandler_DirectorLogic specifically tests the Director's URL and Host rewriting.
func TestNewECPProxyHandler_DirectorLogic(t *testing.T) {
	mockRT := &mockRoundTripper{}

	targetHost := "another.mtls.googleapis.com"
	originalPath := "/api/v1/data?param=value"
	req := httptest.NewRequest(http.MethodGet, "http://localhost:8080"+originalPath, nil)
	req.Header.Set(targetHostHeader, targetHost)

	rr := httptest.NewRecorder()
	handler := newECPProxyHandler(mockRT)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected status code %d, got %d. Body: %s", http.StatusOK, rr.Code, rr.Body.String())
	}

	if mockRT.capturedRequest == nil {
		t.Fatal("mockRoundTripper did not capture any request")
	}

	// Verify the outgoing request's URL and Host
	expectedURL := &url.URL{
		Scheme:   "https",
		Host:     targetHost,
		Path:     "/api/v1/data",
		RawQuery: "param=value",
	}

	if mockRT.capturedRequest.URL.String() != expectedURL.String() {
		t.Errorf("Expected outgoing URL %q, got %q", expectedURL.String(), mockRT.capturedRequest.URL.String())
	}
	if mockRT.capturedRequest.Host != targetHost {
		t.Errorf("Expected outgoing Host header %q, got %q", targetHost, mockRT.capturedRequest.Host)
	}
	if mockRT.capturedRequest.Header.Get(targetHostHeader) != "" {
		t.Errorf("Expected %s header to be removed from outgoing request, but it was present", targetHostHeader)
	}
}

// TestNewECPProxyHandler_ErrorHandlerInvocation ensures the custom ErrorHandler is called.
func TestNewECPProxyHandler_ErrorHandlerInvocation(t *testing.T) {
	mockRT := &mockRoundTripper{
		roundTripError: fmt.Errorf("simulated transport error"),
	}

	req := httptest.NewRequest(http.MethodGet, "http://localhost:8080/test", nil)
	req.Header.Set(targetHostHeader, "valid.mtls.googleapis.com")
	rr := httptest.NewRecorder()

	handler := newECPProxyHandler(mockRT)
	handler.ServeHTTP(rr, req)

	// Verify that the ErrorHandler logic (which calls writeError) was executed
	// by checking the status code and custom error header.
	if rr.Code != http.StatusBadGateway {
		t.Errorf("Expected status code %d, got %d", http.StatusBadGateway, rr.Code)
	}
	if rr.Header().Get(ecpInternalErrorHeader) == "" {
		t.Errorf("Expected %s header to be present, but it was missing", ecpInternalErrorHeader)
	}

	var errResp ErrorResponse
	err := json.Unmarshal(rr.Body.Bytes(), &errResp)
	if err != nil {
		t.Fatalf("Failed to unmarshal error response: %v", err)
	}
	if errResp.Code != http.StatusBadGateway {
		t.Errorf("Expected error response code %d, got %d", http.StatusBadGateway, errResp.Code)
	}
	if errResp.Message == "" {
		t.Errorf("Expected error response message to be non-empty")
	}
	if errResp.Error == "" {
		t.Errorf("Expected error response 'Error' field to be non-empty")
	}
}

func TestReadyzHandler(t *testing.T) {
	nonceToken := "test-nonce-token"
	handler := newReadyzHandler(nonceToken)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	expected := nonceToken
	if rr.Body.String() != expected {
		t.Errorf("handler returned unexpected body: got %v want %v",
			rr.Body.String(), expected)
	}
}

func TestRouter(t *testing.T) {
	nonceToken := "test-nonce"
	authToken := "test-auth-token"

	newTestRouter := func(mockRT *mockRoundTripper) http.Handler {
		return newRouter(newReadyzHandler(nonceToken), createAuthenticatedHttpHandler(authToken, newECPProxyHandler(mockRT)))
	}

	t.Run("readyz_endpoint_does_not_require_auth_token", func(t *testing.T) {
		mockRT := &mockRoundTripper{}
		router := newTestRouter(mockRT)

		req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("router.ServeHTTP(/readyz) status = %d, want %d", rr.Code, http.StatusOK)
		}
		if rr.Body.String() != nonceToken {
			t.Errorf("router.ServeHTTP(/readyz) body = %q, want %q", rr.Body.String(), nonceToken)
		}
		if strings.Contains(rr.Body.String(), authToken) {
			t.Errorf("router.ServeHTTP(/readyz) body = %q, must not expose the auth token", rr.Body.String())
		}
		for k, v := range rr.Header() {
			for _, vv := range v {
				if strings.Contains(vv, authToken) {
					t.Errorf("router.ServeHTTP(/readyz) header %s = %q, must not expose the auth token", k, vv)
				}
			}
		}
		if mockRT.capturedRequest != nil {
			t.Error("router.ServeHTTP(/readyz) unexpectedly forwarded request to proxy handler")
		}
	})

	t.Run("readyz_with_target_host_header_forwards_to_proxy", func(t *testing.T) {
		mockRT := &mockRoundTripper{}
		router := newTestRouter(mockRT)

		req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
		req.Header.Set(targetHostHeader, "storage.mtls.googleapis.com")
		req.Header.Set(authTokenHeader, authToken)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("router.ServeHTTP(/readyz with target host) status = %d, want %d", rr.Code, http.StatusOK)
		}
		if mockRT.capturedRequest == nil {
			t.Fatal("router.ServeHTTP(/readyz with target host) did not call proxy handler")
		}
		if mockRT.capturedRequest.URL.Path != "/readyz" {
			t.Errorf("capturedRequest.URL.Path = %q, want %q", mockRT.capturedRequest.URL.Path, "/readyz")
		}
	})

	t.Run("readyz_with_target_host_header_requires_auth_token", func(t *testing.T) {
		mockRT := &mockRoundTripper{}
		router := newTestRouter(mockRT)

		req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
		req.Header.Set(targetHostHeader, "storage.mtls.googleapis.com")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("router.ServeHTTP(/readyz with target host, no auth token) status = %d, want %d", rr.Code, http.StatusUnauthorized)
		}
		if mockRT.capturedRequest != nil {
			t.Error("router.ServeHTTP(/readyz with target host, no auth token) unexpectedly forwarded request")
		}
	})

	t.Run("some_path_endpoint", func(t *testing.T) {
		mockRT := &mockRoundTripper{}
		router := newTestRouter(mockRT)

		req := httptest.NewRequest(http.MethodGet, "/some/path", nil)
		req.Header.Set(targetHostHeader, "storage.mtls.googleapis.com")
		req.Header.Set(authTokenHeader, authToken)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Expected status code %d for proxy, got %d", http.StatusOK, rr.Code)
		}
		if mockRT.capturedRequest == nil {
			t.Fatal("Proxy handler was not called")
		}
		if mockRT.capturedRequest.URL.Path != "/some/path" {
			t.Errorf("Expected path %q, got %q", "/some/path", mockRT.capturedRequest.URL.Path)
		}
		if got := mockRT.capturedRequest.Header.Get(authTokenHeader); got != "" {
			t.Errorf("forwarded request %s header = %q, want it stripped", authTokenHeader, got)
		}
	})

	t.Run("endpoint_with_double_slashes", func(t *testing.T) {
		mockRT := &mockRoundTripper{}
		router := newTestRouter(mockRT)

		uriWithPathWithDoubleSlashes := "/resources/https://us-central1-docker.pkg.dev/some/image"
		req := httptest.NewRequest(http.MethodGet, uriWithPathWithDoubleSlashes, nil)
		req.Header.Set(targetHostHeader, "containeranalysis.mtls.googleapis.com")
		req.Header.Set(authTokenHeader, authToken)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Expected status code %d for proxy, got %d (Make sure path cleaning is disabled)", http.StatusOK, rr.Code)
		}
		if mockRT.capturedRequest == nil {
			t.Fatal("Proxy handler was not called")
		}
		// Confirm the // was preserved and successfully forwarded
		if mockRT.capturedRequest.URL.Path != uriWithPathWithDoubleSlashes {
			t.Errorf("Expected path %q, got %q", uriWithPathWithDoubleSlashes, mockRT.capturedRequest.URL.Path)
		}
	})
}

func TestCreateAuthenticatedHttpHandler(t *testing.T) {
	const authToken = "test-auth-token"
	tests := []struct {
		name           string
		serverToken    string
		requestToken   string
		setHeader      bool
		wantStatusCode int
		wantForwarded  bool
	}{
		{
			name:           "valid_token",
			serverToken:    authToken,
			requestToken:   authToken,
			setHeader:      true,
			wantStatusCode: http.StatusOK,
			wantForwarded:  true,
		},
		{
			name:           "missing_token",
			serverToken:    authToken,
			setHeader:      false,
			wantStatusCode: http.StatusUnauthorized,
		},
		{
			name:           "empty_token",
			serverToken:    authToken,
			requestToken:   "",
			setHeader:      true,
			wantStatusCode: http.StatusUnauthorized,
		},
		{
			name:           "wrong_token",
			serverToken:    authToken,
			requestToken:   "wrong-token",
			setHeader:      true,
			wantStatusCode: http.StatusUnauthorized,
		},
		{
			name:           "token_prefix",
			serverToken:    authToken,
			requestToken:   authToken[:len(authToken)-1],
			setHeader:      true,
			wantStatusCode: http.StatusUnauthorized,
		},
		{
			name:           "server_without_token_allows_requests_and_strips_header",
			serverToken:    "",
			requestToken:   "unexpected-token",
			setHeader:      true,
			wantStatusCode: http.StatusOK,
			wantForwarded:  true,
		},
		{
			name:           "server_without_token_allows_requests_without_header",
			serverToken:    "",
			setHeader:      false,
			wantStatusCode: http.StatusOK,
			wantForwarded:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRT := &mockRoundTripper{}
			handler := createAuthenticatedHttpHandler(tt.serverToken, newECPProxyHandler(mockRT))

			req := httptest.NewRequest(http.MethodGet, testPath, nil)
			req.Header.Set(targetHostHeader, "storage.mtls.googleapis.com")
			if tt.setHeader {
				req.Header.Set(authTokenHeader, tt.requestToken)
			}
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != tt.wantStatusCode {
				t.Errorf("createAuthenticatedHttpHandler status = %d, want %d", rr.Code, tt.wantStatusCode)
			}
			if gotForwarded := mockRT.capturedRequest != nil; gotForwarded != tt.wantForwarded {
				t.Errorf("createAuthenticatedHttpHandler forwarded = %v, want %v", gotForwarded, tt.wantForwarded)
			}
			if tt.wantForwarded {
				if got := mockRT.capturedRequest.Header.Get(authTokenHeader); got != "" {
					t.Errorf("forwarded request %s header = %q, want it stripped", authTokenHeader, got)
				}
			} else {
				if rr.Header().Get(ecpInternalErrorHeader) == "" {
					t.Errorf("expected %s header on rejected request", ecpInternalErrorHeader)
				}
			}
		})
	}
}

func TestRoutingTransport(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		wantECP bool
	}{
		{
			name:    "mtls_host",
			host:    "storage.mtls.googleapis.com",
			wantECP: true,
		},
		{
			name:    "mtls_sandbox_host",
			host:    "pubsub.mtls.sandbox.googleapis.com",
			wantECP: true,
		},
		{
			name:    "mtls_tpc_host",
			host:    "foo.mtls.apis-tpczero.goog",
			wantECP: true,
		},
		{
			name:    "regular_host",
			host:    "storage.googleapis.com",
			wantECP: false,
		},
		{
			name:    "host_containing_mtls",
			host:    "example.mtls.com",
			wantECP: true,
		},
		{
			name:    "host_without_mtls",
			host:    "google.com",
			wantECP: false,
		},
		{
			name:    "host_starting_with_mtls_websocket",
			host:    "mtls.tunnel.cloudproxy.app",
			wantECP: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ecpRT := &mockRoundTripper{}
			defaultRT := &mockRoundTripper{}
			routingRT := &RoutingTransport{
				ECPTransport:     ecpRT,
				DefaultTransport: defaultRT,
			}

			req := httptest.NewRequest(http.MethodGet, "https://"+tt.host, nil)
			_, err := routingRT.RoundTrip(req)
			if err != nil {
				t.Fatalf("RoundTrip(%q) failed: %v", tt.host, err)
			}

			if gotECP := ecpRT.capturedRequest != nil; gotECP != tt.wantECP {
				t.Errorf("RoutingTransport.RoundTrip(%q) used ECPTransport = %v, want %v", tt.host, gotECP, tt.wantECP)
			}
			if gotDefault := defaultRT.capturedRequest != nil; gotDefault == tt.wantECP {
				t.Errorf("RoutingTransport.RoundTrip(%q) used DefaultTransport = %v, want %v", tt.host, gotDefault, !tt.wantECP)
			}
		})
	}
}

func TestRunServer_BindsLoopbackAndRejectsPortInUse(t *testing.T) {
	t.Run("ipv4_port_in_use", func(t *testing.T) {
		occupiedListener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("net.Listen(127.0.0.1:0) failed: %v", err)
		}
		occupiedPort := occupiedListener.Addr().(*net.TCPAddr).Port

		proxyConfig := newDefaultProxyConfig()
		proxyConfig.Port = occupiedPort

		if err := runServer(context.Background(), proxyConfig, newReadyzHandler("nonce")); err == nil {
			occupiedListener.Close()
			t.Fatalf("runServer() on occupied IPv4 port %d = nil, want non-nil error", occupiedPort)
		}
		occupiedListener.Close()
	})

	t.Run("ipv6_port_in_use", func(t *testing.T) {
		occupiedListener, err := net.Listen("tcp6", "[::1]:0")
		if err != nil {
			t.Skipf("IPv6 loopback not available: %v", err)
		}
		occupiedPort := occupiedListener.Addr().(*net.TCPAddr).Port

		proxyConfig := newDefaultProxyConfig()
		proxyConfig.Port = occupiedPort

		if err := runServer(context.Background(), proxyConfig, newReadyzHandler("nonce")); err == nil {
			occupiedListener.Close()
			t.Fatalf("runServer() on occupied IPv6 port %d = nil, want non-nil error", occupiedPort)
		}
		occupiedListener.Close()
	})
}

func TestRunServer_BindsOnlyToLoopback(t *testing.T) {
	// Find a free port.
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen(127.0.0.1:0) failed: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()

	proxyConfig := newDefaultProxyConfig()
	proxyConfig.Port = port

	ctx, cancel := context.WithCancel(context.Background())
	errChan := make(chan error, 1)
	go func() { errChan <- runServer(ctx, proxyConfig, newReadyzHandler("nonce")) }()
	defer func() {
		cancel()
		if err := <-errChan; err != nil {
			t.Errorf("runServer() returned error: %v", err)
		}
	}()

	// The loopback address must be reachable.
	loopbackAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	var conn net.Conn
	for i := 0; i < 50; i++ {
		conn, err = net.DialTimeout("tcp", loopbackAddr, 100*time.Millisecond)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("net.Dial(%s) failed: %v", loopbackAddr, err)
	}
	conn.Close()

	// Non-loopback interface addresses must not be reachable.
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatalf("net.InterfaceAddrs() failed: %v", err)
	}
	checked := 0
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok || ipNet.IP.IsLoopback() || ipNet.IP.To4() == nil {
			continue
		}
		addr := net.JoinHostPort(ipNet.IP.String(), strconv.Itoa(port))
		if c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond); err == nil {
			c.Close()
			t.Errorf("net.Dial(%s) succeeded, want proxy unreachable on non-loopback interfaces", addr)
		}
		checked++
	}
	if checked == 0 {
		t.Log("no non-loopback IPv4 interface addresses found; only verified loopback reachability")
	}
}
