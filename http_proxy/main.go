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
	defaultShutdownTimeout     = 5 * time.Second
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

// newProxyConfigFromFlags creates a new ProxyConfig and populates it from command-line flags.
func newProxyConfigFromFlags() (*ProxyConfig, error) {
	cfg := &ProxyConfig{
		TLSHandshakeTimeout: defaultTLSHandshakeTimeout,
		ProxyRequestTimeout: defaultProxyRequestTimeout,
		DialTimeout:         defaultDialTimeout,
		KeepAlivePeriod:     defaultKeepAlivePeriod,
		IdleConnTimeout:     defaultIdleConnTimeout,
		ShutdownTimeout:     defaultShutdownTimeout,
	}

	flag.IntVar(&cfg.Port, "port", 0, "The port to listen on for HTTP requests. (Required)")
	flag.StringVar(&cfg.EnterpriseCertificateFilePath, "enterprise_certificate_file_path", "", "The path to the enterprise certificate file. (Required)")
	flag.StringVar(&cfg.GcloudConfiguredProxyURL, "gcloud_configured_proxy_url", "", "The URL that gcloud is configured to use for the proxy.")
	flag.Parse()

	if cfg.Port <= 0 {
		return nil, errors.New("port is required and must be a positive integer")
	}
	if cfg.EnterpriseCertificateFilePath == "" {
		return nil, errors.New("enterprise_certificate_file_path is required")
	}
	return cfg, nil
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

// isAllowedHost checks if the host is allowed.
func isAllowedHost(host string) bool {
	return mtlsGoogleapisHostRegex.MatchString(host)
}

// newECPTransport creates http.Transport needed for mTLS.
func newECPTransport(proxyConfig *ProxyConfig, key *client.Key) (http.RoundTripper, error) {
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

// newProxyHandler creates a proxy handler using httputil.ReverseProxy.
func newProxyHandler(transport http.RoundTripper) http.Handler {
	proxy := &httputil.ReverseProxy{
		// The Director is called for every request and is responsible for
		// modifying it before it's sent to the target.
		Director: func(req *http.Request) {
			targetHost := req.Header.Get(targetHostHeader)
			// We clear the header so it's not sent to the destination.
			req.Header.Del(targetHostHeader)

			// Set the URL and Host for the outgoing request.
			req.URL.Scheme = "https"
			req.URL.Host = targetHost
			req.Host = targetHost
		},
		// Use our custom transport that handles the mTLS handshake.
		Transport: transport,
		// Define a custom error handler to maintain our JSON error format.
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("Proxy error: %v", err)
			writeError(w, err, "Failed to forward request", http.StatusBadGateway)
		},
	}

	// We wrap the ReverseProxy in our own handler to perform validation first.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHost := r.Header.Get(targetHostHeader)
		if targetHost == "" {
			writeError(w, fmt.Errorf("missing %s header", targetHostHeader), "Proxy error", http.StatusBadRequest)
			return
		}

		if !isAllowedHost(targetHost) {
			writeError(w, fmt.Errorf("target host %q is not allowed", targetHost), "Proxy error", http.StatusForbidden)
			return
		}

		// If validation passes, let the ReverseProxy do the work.
		proxy.ServeHTTP(w, r)
	})
}

func runServer(ctx context.Context, config *ProxyConfig, handler http.Handler) error {
	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", config.Port),
		Handler: handler,
	}

	errChan := make(chan error, 1)

	go func() {
		log.Printf("Starting proxy server on port %d", config.Port)
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			errChan <- fmt.Errorf("failed to start proxy server: %w", err)
		}
	}()

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

func run(ctx context.Context) error {
	log.Print("Starting ECP Proxy...")
	config, err := newProxyConfigFromFlags()
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
	proxyHandler := newProxyHandler(transport)

	return runServer(ctx, config, proxyHandler)
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := run(ctx); err != nil {
		log.Fatalf("ECP Proxy failed: %v", err)
	}
}
