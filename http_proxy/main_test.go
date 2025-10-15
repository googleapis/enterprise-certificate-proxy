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
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"testing"
)

const (
	testPort = 8080
)

var (
	testPath       = fmt.Sprintf("http://localhost:%d/some/path", testPort)
	localhostRegex = regexp.MustCompile(`^127\.0\.0\.1:(\d{1,5})$`)
)

func TestAppConfigFromFlags(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr bool
		want    *AppConfig
	}{
		{
			name: "Happy Path",
			args: []string{"-port", "8080", "-enterprise_certificate_file_path", "/path/to/cert.json"},
			want: &AppConfig{
				Port:                          8080,
				EnterpriseCertificateFilePath: "/path/to/cert.json",
			},
		},
		{
			name:    "Missing Port",
			args:    []string{"-enterprise_certificate_file_path", "/path/to/cert.json"},
			wantErr: true,
		},
		{
			name:    "Invalid Port (zero)",
			args:    []string{"-port", "0", "-enterprise_certificate_file_path", "/path/to/cert.json"},
			wantErr: true,
		},
		{
			name:    "Invalid Port (negative)",
			args:    []string{"-port", "-1", "-enterprise_certificate_file_path", "/path/to/cert.json"},
			wantErr: true,
		},
		{
			name:    "Missing Certificate Path",
			args:    []string{"-port", "8080"},
			wantErr: true,
		},
		{
			name: "Happy Path with Optional Proxy URL",
			args: []string{"-port", "8080", "-enterprise_certificate_file_path", "/path/to/cert.json", "-gcloud_configured_proxy_url", "http://proxy.example.com"},
			want: &AppConfig{
				Port:                          8080,
				EnterpriseCertificateFilePath: "/path/to/cert.json",
				GcloudConfiguredProxyURL:      "http://proxy.example.com",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Each test needs its own flag set.
			fs := flag.NewFlagSet(tt.name, flag.ContinueOnError)
			// Discard output to avoid polluting test logs.
			fs.SetOutput(os.Stderr)

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
				if got.GcloudConfiguredProxyURL != tt.want.GcloudConfiguredProxyURL {
					t.Errorf("newProxyConfigFromFlags() GcloudConfiguredProxyURL = %v, want %v", got.GcloudConfiguredProxyURL, tt.want.GcloudConfiguredProxyURL)
				}
			}
		})
	}
}

func TestIsAllowedHost(t *testing.T) {
	tests := []struct {
		name                string
		isAllowedHostsRegex *regexp.Regexp
		host                string
		want                bool
	}{
		{
			name:                "allowed host storage.mtls.googleapis.com",
			isAllowedHostsRegex: mtlsGoogleapisHostRegex,
			host:                "storage.mtls.googleapis.com",
			want:                true,
		},
		{
			name:                "allowed host storage.mtls.sandbox.googleapis.com",
			isAllowedHostsRegex: mtlsGoogleapisHostRegex,
			host:                "storage.mtls.sandbox.googleapis.com",
			want:                true,
		},
		{
			name:                "allowed host with numbers",
			isAllowedHostsRegex: mtlsGoogleapisHostRegex,
			host:                "my-service-123.mtls.googleapis.com",
			want:                true,
		},
		{
			name:                "disallowed host google.com rejected",
			isAllowedHostsRegex: mtlsGoogleapisHostRegex,
			host:                "google.com",
			want:                false,
		},
		{
			name:                "disallowed host evil.com rejected",
			isAllowedHostsRegex: mtlsGoogleapisHostRegex,
			host:                "evil.com",
			want:                false,
		},
		{
			name:                "disallowed host with fake subdomain rejected",
			isAllowedHostsRegex: mtlsGoogleapisHostRegex,
			host:                "storage.mtls.googleapis.com.fake.com",
			want:                false,
		},
		{
			name:                "disallowed host with fake prefix rejected",
			isAllowedHostsRegex: mtlsGoogleapisHostRegex,
			host:                "a/b/c/storage.mtls.googleapis.com.",
			want:                false,
		},
		{
			name:                "allowed host with numbers",
			isAllowedHostsRegex: mtlsGoogleapisHostRegex,
			host:                "my-service-123.mtls.sandbox.googleapis.com",
			want:                true,
		},
		{
			name:                "disallowed host sandbox.google.com rejected",
			isAllowedHostsRegex: mtlsGoogleapisHostRegex,
			host:                "sandbox.google.com",
			want:                false,
		},
		{
			name:                "disallowed host sandbox.evil.com rejected",
			isAllowedHostsRegex: mtlsGoogleapisHostRegex,
			host:                "sandbox.evil.com",
			want:                false,
		},
		{
			name:                "disallowed host with fake subdomain rejected",
			isAllowedHostsRegex: mtlsGoogleapisHostRegex,
			host:                "storage.mtls.sandbox.googleapis.com.fake.com",
			want:                false,
		},
		{
			name:                "disallowed host with fake prefix rejected",
			isAllowedHostsRegex: mtlsGoogleapisHostRegex,
			host:                "a/b/c/storage.mtls.sandbox.googleapis.com.",
			want:                false,
		},
		{
			name:                "disallowed host - empty string",
			isAllowedHostsRegex: mtlsGoogleapisHostRegex,
			host:                "",
			want:                false,
		},
		{
			name:                "localhost regex rejects googleapis",
			isAllowedHostsRegex: localhostRegex,
			host:                "storage.googleapis.com",
			want:                false,
		},
		{
			name:                "localhost regex allows localhost",
			isAllowedHostsRegex: localhostRegex,
			host:                "127.0.0.1:8080",
			want:                true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isAllowedHost(tt.isAllowedHostsRegex, tt.host); got != tt.want {
				t.Errorf("isAllowedHost(%s, %q) = %v, want %v", tt.isAllowedHostsRegex.String(), tt.host, got, tt.want)
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
	proxyConfig.AllowedHostsRegex = mtlsGoogleapisHostRegex
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
			name:               "Valid Request",
			targetHostHeader:   "storage.mtls.googleapis.com",
			expectedStatusCode: http.StatusOK,
			expectErrorHeader:  false,
			validateDirector:   true,
		},
		{
			name:               "Missing Target Host Header",
			targetHostHeader:   "",
			expectedStatusCode: http.StatusBadRequest,
			expectErrorHeader:  true,
		},
		{
			name:               "Disallowed Target Host",
			targetHostHeader:   "example.com",
			expectedStatusCode: http.StatusForbidden,
			expectErrorHeader:  true,
		},
		{
			name:               "ReverseProxy Error Handling",
			targetHostHeader:   "storage.mtls.googleapis.com",
			expectedStatusCode: http.StatusBadGateway,
			expectErrorHeader:  true,
			roundTripperError:  fmt.Errorf("mock transport error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proxyConfig := NewProxyConfigForTest()

			mockRT := &mockRoundTripper{
				roundTripError: tt.roundTripperError,
			}
			handler := newECPProxyHandler(proxyConfig, mockRT)

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
	proxyConfig := NewProxyConfigForTest()
	mockRT := &mockRoundTripper{}

	targetHost := "another.mtls.googleapis.com"
	originalPath := "/api/v1/data?param=value"
	req := httptest.NewRequest(http.MethodGet, "http://localhost:8080"+originalPath, nil)
	req.Header.Set(targetHostHeader, targetHost)

	rr := httptest.NewRecorder()
	handler := newECPProxyHandler(proxyConfig, mockRT)
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
	proxyConfig := NewProxyConfigForTest()
	mockRT := &mockRoundTripper{
		roundTripError: fmt.Errorf("simulated transport error"),
	}

	req := httptest.NewRequest(http.MethodGet, "http://localhost:8080/test", nil)
	req.Header.Set(targetHostHeader, "valid.mtls.googleapis.com")
	rr := httptest.NewRecorder()

	handler := newECPProxyHandler(proxyConfig, mockRT)
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
