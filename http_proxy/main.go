package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os/signal"
	"regexp"
	"syscall"
	"time"

	"github.com/googleapis/enterprise-certificate-proxy/client"
)

const (
	targetHostHeader       = "X-Goog-EcpProxy-Target-Host"
	ecpInternalErrorHeader = "X-Goog-EcpProxy-Error"
)

// Default timeouts and configurations
const (
	defaultTLSHandshakeTimeout = 10 * time.Second
	defaultProxyRequestTimeout = 15 * time.Second
	defaultDialTimeout         = 5 * time.Second
	defaultKeepAlivePeriod     = 30 * time.Second
	defaultIdleConnTimeout     = 30 * time.Second
	defaultShutdownTimeout     = 1 * time.Second
)

var mtlsGoogleapisHostRegex = regexp.MustCompile(`^[a-z0-9-]+\.mtls\.googleapis\.com$`)

// ProxyConfig holds the configuration for the proxy server.
type ProxyConfig struct {
	Port                          int
	EnterpriseCertificateFilePath string
	GcloudConfiguredProxyURL      string
	TLSHandshakeTimeout           time.Duration
	ProxyRequestTimeout           time.Duration
	DialTimeout                   time.Duration
	KeepAlivePeriod               time.Duration
	IdleConnTimeout               time.Duration
	ShutdownTimeout               time.Duration
}

// newConfigFromFlags creates a new ProxyConfig from default values, command line flags, then validates it.
func newConfigFromFlags() (*ProxyConfig, error) {
	config := &ProxyConfig{
		TLSHandshakeTimeout: defaultTLSHandshakeTimeout,
		ProxyRequestTimeout: defaultProxyRequestTimeout,
		DialTimeout:         defaultDialTimeout,
		KeepAlivePeriod:     defaultKeepAlivePeriod,
		IdleConnTimeout:     defaultIdleConnTimeout,
		ShutdownTimeout:     defaultShutdownTimeout,
	}

	flag.IntVar(&config.Port, "port", 0, "The port to listen on for HTTP requests. (Required)")
	flag.StringVar(&config.EnterpriseCertificateFilePath, "enterprise_certificate_file_path", "", "The path to the enterprise certificate file. (Required)")
	flag.StringVar(&config.GcloudConfiguredProxyURL, "gcloud_configured_proxy_url", "", "The URL that gcloud is configured to use for the proxy.")
	flag.Parse()

	if config.Port <= 0 {
		return nil, errors.New("port is required and must be a positive integer")
	}
	if config.EnterpriseCertificateFilePath == "" {
		return nil, errors.New("enterprise_certificate_file_path is required")
	}
	return config, nil
}

// ErrorResponse defines the structure for a JSON error response.
type ErrorResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Error   string `json:"error"`
}

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

// ECPProxy is a simple HTTP proxy that forwards requests to a target server.
type ECPProxy struct {
	client http.RoundTripper
}

// isAllowedHost checks if the host is allowed.
func isAllowedHost(host string) bool {
	return mtlsGoogleapisHostRegex.MatchString(host)
}

func (p *ECPProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	targetHost := r.Header.Get(targetHostHeader)
	if targetHost == "" {
		writeError(w, fmt.Errorf("missing %s header", targetHostHeader), "Proxy error", http.StatusBadRequest)
		return
	}

	if !isAllowedHost(targetHost) {
		writeError(w, fmt.Errorf("target host %q is not allowed", targetHost), "Proxy error", http.StatusForbidden)
		return
	}

	// Create a new outgoing request to avoid modifying the original.
	outReq := r.Clone(r.Context())
	outReq.Host = targetHost
	outReq.URL.Scheme = "https"
	outReq.URL.Host = targetHost
	// Retain the original request URI
	outReq.URL.Path = r.URL.Path
	outReq.URL.RawQuery = r.URL.RawQuery

	resp, err := p.client.RoundTrip(outReq)
	if err != nil {
		log.Printf("Failed to round trip request: %v", err)
		writeError(w, err, "Failed to forward request", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy headers from the response to the writer.
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// newECPProxy creates a new ECPProxy instance with the given configuration.
func newECPProxy(client http.RoundTripper) (*ECPProxy, error) {
	return &ECPProxy{
		client: client,
	}, nil
}

// newECPTransport creates a new HTTP transport using the provided client key.
// If gcloudConfiguredProxyURL is set, it configures the transport to use that proxy.
func newECPTransport(proxyConfig *ProxyConfig, key *client.Key) (*http.Transport, error) {
	tlsCert := &tls.Certificate{
		Certificate: key.CertificateChain(),
		PrivateKey:  key,
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{*tlsCert},
		},
		TLSHandshakeTimeout:   proxyConfig.TLSHandshakeTimeout,
		ResponseHeaderTimeout: proxyConfig.ProxyRequestTimeout,
		DialContext: (&net.Dialer{
			Timeout:   proxyConfig.DialTimeout,
			KeepAlive: proxyConfig.KeepAlivePeriod,
		}).DialContext,
		IdleConnTimeout: proxyConfig.IdleConnTimeout,
	}

	if proxyConfig.GcloudConfiguredProxyURL != "" {
		proxyURL, err := url.Parse(proxyConfig.GcloudConfiguredProxyURL)
		if err != nil {
			return nil, fmt.Errorf("failed to parse gcloud_configured_proxy_url: %w", err)
		}
		transport.Proxy = http.ProxyURL(proxyURL)
		log.Printf("Using gcloud-configured proxy URL: %s", proxyConfig.GcloudConfiguredProxyURL)
	}
	return transport, nil
}

// runServer starts the HTTP server and handles graceful shutdown.
// This function contains the server lifecycle logic.
func runServer(ctx context.Context, config *ProxyConfig, handler http.Handler) error {
	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", config.Port),
		Handler: handler,
	}

	// Channel to listen for errors from the server
	errChan := make(chan error, 1)

	// Start the server in a goroutine
	go func() {
		log.Printf("Starting proxy server on port %d", config.Port)
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			errChan <- fmt.Errorf("failed to start proxy server: %w", err)
		}
	}()

	// Wait for context cancellation (from signal) or a server error
	select {
	case err := <-errChan:
		return err
	case <-ctx.Done():
		log.Println("Shutdown signal received, shutting down server gracefully...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), config.ShutdownTimeout)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("server shutdown failed: %w", err)
		}
		log.Println("Server shut down gracefully")
	}

	return nil
}

// run function contains the application's core logic
func run(ctx context.Context) error {
	log.Print("Starting ECP Proxy...")
	config, err := newConfigFromFlags()
	if err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	log.Println("Loading ECP credential...")
	key, err := client.Cred(config.EnterpriseCertificateFilePath)
	if err != nil {
		return fmt.Errorf("failed to get ECP credential: %w", err)
	}
	defer key.Close()

	transport, err := newECPTransport(config, key)
	if err != nil {
		return fmt.Errorf("failed to create ECP transport: %w", err)
	}

	// Create the ECP proxy handler
	ecpProxy, err := newECPProxy(transport)
	if err != nil {
		return fmt.Errorf("failed to create ECP Proxy: %w", err)
	}

	return runServer(ctx, config, ecpProxy)
}

func main() {
	// Create a context that is canceled on an interrupt signal.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := run(ctx); err != nil {
		log.Fatalf("ECP Proxy failed: %v", err)
	}
}
