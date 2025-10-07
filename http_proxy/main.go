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

// Package main implements a local forwarding proxy (LocalECPProxy) that uses
// an Enterprise Certificate Proxy (ECP) client to handle mTLS handshakes.
// The proxy listens for HTTP requests, validates them, and forwards them to
// a target host specified in a custom HTTP header. It is designed to run
// locally and can be configured via command-line flags.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os/signal"
	"regexp"
	"syscall"
	"time"

	"github.com/googleapis/enterprise-certificate-proxy/client"
)

const (
	// targetHostHeader is the custom HTTP header used by clients to specify the
	// destination host for the proxy to forward the request to.
	targetHostHeader = "X-Goog-EcpProxy-Target-Host"
	// ecpInternalErrorHeader is a custom HTTP header added to error responses
	// to indicate that the error originated within the LocalECPProxy.
	ecpInternalErrorHeader = "X-Goog-EcpProxy-Error"
)

// Default timeouts and configurations for the HTTP client and server.
const (
	defaultTLSHandshakeTimeout = 10 * time.Second
	defaultProxyRequestTimeout = 15 * time.Second
	defaultDialTimeout         = 5 * time.Second
	defaultKeepAlivePeriod     = 30 * time.Second
	defaultIdleConnTimeout     = 30 * time.Second
	defaultShutdownTimeout     = 5 * time.Second
)

// mtlsGoogleapisHostRegex is a regular expression that validates whether a target
// host conforms to the "*.mtls.googleapis.com" pattern. This is a security
// measure to ensure the proxy only connects to allowed endpoints.
var mtlsGoogleapisHostRegex = regexp.MustCompile(`^[a-z0-9-]+\.mtls\.googleapis\.com$`)

// AppConfig holds the application configuration parsed from command-line flags.
type AppConfig struct {
	Port                          int
	EnterpriseCertificateFilePath string
	GcloudConfiguredProxyURL      string
}

func (cfg *AppConfig) validate() error {
	if cfg.Port <= 0 {
		return errors.New("port is required and must be a positive integer")
	}
	if cfg.EnterpriseCertificateFilePath == "" {
		return errors.New("enterprise_certificate_file_path is required")
	}
	return nil
}

// newAppConfigFromFlags parses command-line flags, validates them, and returns a new AppConfig.
func newAppConfigFromFlags() (*AppConfig, error) {
	cfg := &AppConfig{}
	flag.IntVar(&cfg.Port, "port", 0, "The port to listen on for HTTP requests. (Required)")
	flag.StringVar(&cfg.EnterpriseCertificateFilePath, "enterprise_certificate_file_path", "", "The path to the enterprise certificate file. (Required)")
	flag.StringVar(&cfg.GcloudConfiguredProxyURL, "gcloud_configured_proxy_url", "", "The URL that gcloud is configured to use for the proxy.")
	flag.Parse()

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// ProxyConfig holds the configuration for the proxy server.
type ProxyConfig struct {
	Port                int // The port for the proxy server to listen on.
	AllowedHostsRegex   *regexp.Regexp
	TlsConfig           *tls.Config
	ProxyURL            *url.URL
	TLSHandshakeTimeout time.Duration // Max duration for TLS handshake to the target.
	ProxyRequestTimeout time.Duration // Max duration for the entire proxy request.
	DialTimeout         time.Duration // Max duration for establishing a TCP connection.
	KeepAlivePeriod     time.Duration // Period for TCP keep-alives.
	IdleConnTimeout     time.Duration // Max duration an idle connection is kept alive.
	ShutdownTimeout     time.Duration // Max duration to wait for graceful shutdown.
}

// newDefaultProxyConfig creates a new ProxyConfig with default values for timeouts.
func newDefaultProxyConfig() *ProxyConfig {
	return &ProxyConfig{
		TLSHandshakeTimeout: defaultTLSHandshakeTimeout,
		ProxyRequestTimeout: defaultProxyRequestTimeout,
		DialTimeout:         defaultDialTimeout,
		KeepAlivePeriod:     defaultKeepAlivePeriod,
		IdleConnTimeout:     defaultIdleConnTimeout,
		ShutdownTimeout:     defaultShutdownTimeout,
	}
}

// ErrorResponse defines the structure for a JSON error response sent to the client.
type ErrorResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Error   string `json:"error"`
}

// writeError formats an error into the standard JSON ErrorResponse structure
// and writes it to the http.ResponseWriter with the specified status code.
// It also sets a custom header to indicate the error originated from this proxy.
func writeError(w http.ResponseWriter, originalError error, errorMsg string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set(ecpInternalErrorHeader, "true")
	w.WriteHeader(statusCode)

	resp := ErrorResponse{
		Message: errorMsg,
		Code:    statusCode,
		Error:   originalError.Error(),
	}

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("Failed to write error response: %v", err)
	}
}

// isAllowedHost checks if the provided host string matches the predefined
// regular expression for allowed hosts.
func isAllowedHost(allowedHostsRegex *regexp.Regexp, host string) bool {
	return allowedHostsRegex.MatchString(host)
}

// newECPProxyTransport creates an http.RoundTripper (specifically, an http.Transport)
// configured to perform mTLS using a credential loaded from the ECP client.
// It also configures an optional upstream proxy if one is provided in the configuration.
func newECPProxyTransport(proxyConfig *ProxyConfig) http.RoundTripper {
	transport := &http.Transport{
		TLSClientConfig:       proxyConfig.TlsConfig,
		TLSHandshakeTimeout:   proxyConfig.TLSHandshakeTimeout,
		ResponseHeaderTimeout: proxyConfig.ProxyRequestTimeout,
		DialContext: (&net.Dialer{
			Timeout:   proxyConfig.DialTimeout,
			KeepAlive: proxyConfig.KeepAlivePeriod,
		}).DialContext,
		IdleConnTimeout: proxyConfig.IdleConnTimeout,
	}

	// If an upstream proxy is configured, set it on the transport.
	if proxyConfig.ProxyURL != nil {
		transport.Proxy = http.ProxyURL(proxyConfig.ProxyURL)
		log.Printf("Using gcloud-configured proxy URL: %s", proxyConfig.ProxyURL)
	}
	return transport
}

// newECPProxyHandler creates the primary http.Handler for the ECP Proxy server.
// It uses httputil.ReverseProxy to forward requests. Before forwarding, it
// performs validation on the incoming request to ensure it is well-formed
// and targeting an allowed host.
func newECPProxyHandler(proxyConfig *ProxyConfig, transport http.RoundTripper) http.Handler {
	proxy := &httputil.ReverseProxy{
		// Director modifies the request just before it is sent to the target.
		// It reads the target host from our custom header, sets the request URL,
		// and removes the custom header to avoid leaking it.
		Director: func(req *http.Request) {
			targetHost := req.Header.Get(targetHostHeader)
			// We clear the header so it's not sent to the destination.
			req.Header.Del(targetHostHeader)

			// Set the URL and Host for the outgoing request.
			req.URL.Scheme = "https"
			req.URL.Host = targetHost
			req.Host = targetHost
		},
		// Transport is the http.RoundTripper that executes the request. We use
		// our custom ECP transport to handle the mTLS handshake.
		Transport: transport,
		// ErrorHandler provides a custom function to handle errors that occur
		// during the proxying process, ensuring a consistent error format.
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("Proxy error: %v", err)
			writeError(w, err, "Failed to forward request", http.StatusBadGateway)
		},
	}

	// We wrap the ReverseProxy in our own handler to perform validation first.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHost := r.Header.Get(targetHostHeader)
		if targetHost == "" {
			writeError(w, fmt.Errorf("missing %s header", targetHostHeader), "Bad Request", http.StatusBadRequest)
			return
		}

		if !isAllowedHost(proxyConfig.AllowedHostsRegex, targetHost) {
			writeError(w, fmt.Errorf("target host %q is not allowed", targetHost), "Forbidden", http.StatusForbidden)
			return
		}

		// If validation passes, let the ReverseProxy handle the request.
		proxy.ServeHTTP(w, r)
	})
}

// runServer starts the HTTP server with the given handler and configuration.
// It listens for OS signals from the provided context to perform a graceful shutdown.
func runServer(ctx context.Context, proxyConfig *ProxyConfig, handler http.Handler) error {
	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", proxyConfig.Port),
		Handler: handler,
	}

	// Channel to receive errors from the server's ListenAndServe goroutine.
	errChan := make(chan error, 1)

	// Run the server in a goroutine.
	go func() {
		log.Printf("Starting proxy server on port %d", proxyConfig.Port)
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			errChan <- fmt.Errorf("failed to start proxy server: %w", err)
		}
	}()

	// Block until we receive an error or a shutdown signal from the context.
	select {
	case err := <-errChan:
		return err
	case <-ctx.Done():
		log.Println("Shutdown signal received, shutting down server gracefully...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), proxyConfig.ShutdownTimeout)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("server shutdown failed: %w", err)
		}
		log.Println("Server shut down gracefully")
	}

	return nil
}

// run is the main application logic. It initializes the configuration, ECP client,
// HTTP transport, and proxy handler, then starts the server.
func run(ctx context.Context, cfg *AppConfig) error {
	log.Print("Starting ECP Proxy...")

	proxyConfig := newDefaultProxyConfig()
	proxyConfig.AllowedHostsRegex = mtlsGoogleapisHostRegex
	proxyConfig.Port = cfg.Port

	// Create tlsConfig
	log.Println("Loading ECP credential...")
	key, err := client.Cred(cfg.EnterpriseCertificateFilePath)
	if err != nil {
		return fmt.Errorf("failed to get ECP credential: %w", err)
	}
	defer key.Close()

	// The tls.Certificate is configured with the certificate chain and a custom
	// crypto.Signer (the ECP client.Key) for the private key operations.
	proxyConfig.TlsConfig = &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: key.CertificateChain(),
				PrivateKey:  key,
			},
		},
	}

	if cfg.GcloudConfiguredProxyURL != "" {
		proxyURL, err := url.Parse(cfg.GcloudConfiguredProxyURL)
		if err != nil {
			return fmt.Errorf("failed to parse gcloud_configured_proxy_url: %w", err)
		}
		proxyConfig.ProxyURL = proxyURL
	}

	// Create Proxy Transport
	ecpProxyTransport := newECPProxyTransport(proxyConfig)
	// Create Proxy Handler
	ecpProxyHandler := newECPProxyHandler(proxyConfig, ecpProxyTransport)
	// Run the server
	return runServer(ctx, proxyConfig, ecpProxyHandler)
}

// main is the entry point of the application. It parses flags, sets up a context
// that listens for interrupt signals (SIGINT, SIGTERM) to enable graceful
// shutdown, and then calls the main run function.
func main() {
	cfg, err := newAppConfigFromFlags()
	if err != nil {
		log.Fatalf("ECP Proxy initialization failed due to invalid configuration: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, cfg); err != nil {
		log.Fatalf("ECP Proxy failed: %v", err)
	}
}
