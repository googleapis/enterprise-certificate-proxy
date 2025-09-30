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
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/googleapis/enterprise-certificate-proxy/client"
)

const (
	targetHostHeader         = "X-Goog-EcpProxy-Target-Host"
	proxyTLSHandshakeTimeout = 10 * time.Second
	proxyRequestTimeout      = 15 * time.Second
	proxyDialTimeout         = 5 * time.Second
	proxyKeepAlivePeriod     = 30 * time.Second
	proxyIdleConnTimeout     = 30 * time.Second
	proxyShutdownTimeout     = 1 * time.Second
)

// ProxyConfig holds the configuration for the proxy server.
type ProxyConfig struct {
	// Port is the port to listen on for HTTP requests.
	Port int
	// EnterpriseCertificateFilePath is the path to the enterprise certificate file.
	EnterpriseCertificateFilePath string

	// Controls the maximum time to wait for a TLS handshake.
	TLSHandshakeTimeout time.Duration
	// Timeout for the entire proxy request, including connection,
	// request writing, and response header reading.
	// Timeout for the entire proxy request.
	ProxyRequestTimeout time.Duration
	// Controls the time to wait for a connection to be established.
	DialTimeout time.Duration
	// Keep-alive period for TCP connections.
	KeepAlivePeriod time.Duration
	// Timeout to keep idle connections for reuse.
	IdleConnTimeout time.Duration

	// Timeout for server shutdown.
	ShutdownTimeout time.Duration
}

// validate checks if the configuration is valid.
func (c *ProxyConfig) validate() error {
	if c.Port <= 0 {
		return errors.New("port is required and must be a positive integer")
	}
	if c.EnterpriseCertificateFilePath == "" {
		return errors.New("enterprise_certificate_file_path is required")
	}
	return nil
}

// initConfig initializes the configuration from command-line flags.
func initConfigFromFlags() (*ProxyConfig, error) {
	proxy_config := &ProxyConfig{}
	flag.IntVar(&proxy_config.Port, "port", 0, "The port to listen on for HTTP requests. (Required)")
	flag.StringVar(&proxy_config.EnterpriseCertificateFilePath, "enterprise_certificate_file_path", "", "The path to the enterprise certificate file. (Required)")
	flag.Parse()

	proxy_config.TLSHandshakeTimeout = proxyTLSHandshakeTimeout
	proxy_config.ProxyRequestTimeout = proxyRequestTimeout
	proxy_config.DialTimeout = proxyDialTimeout
	proxy_config.KeepAlivePeriod = proxyKeepAlivePeriod
	proxy_config.IdleConnTimeout = proxyIdleConnTimeout
	proxy_config.ShutdownTimeout = proxyShutdownTimeout

	if err := proxy_config.validate(); err != nil {
		return nil, err
	}
	return proxy_config, nil
}

type TLSErrorResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Error   string `json:"error"`
}

func writeTLSError(w http.ResponseWriter, originalErrorStr string, errorMsg string, statusCode int) {
	log.Printf("writeTLSError: Writing TLS error response: %s (status %d)", errorMsg, statusCode)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Goog-EcpProxy-Error", "mtls_connection_error")
	w.WriteHeader(statusCode)

	resp := TLSErrorResponse{
		Message: errorMsg,
		Code:    statusCode,
		Error:   originalErrorStr,
	}

	json.NewEncoder(w).Encode(resp)
}

func (p *ECPProxy) handleError(w http.ResponseWriter, err error) {
	writeTLSError(w, err.Error(), "ECP Proxy error: "+err.Error(), http.StatusBadGateway)
}

// ECPProxy is a simple HTTP proxy that forwards requests to a target server.
type ECPProxy struct {
	Transport http.RoundTripper
}

func (p *ECPProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	targetHost := r.Header.Get(targetHostHeader)
	if targetHost == "" {
		p.handleError(w, fmt.Errorf("%s header is required", targetHostHeader))
		return
	}

	// Set this to the desired Host header for the final destination
	// (i.e., the original Host requested by gcloud, like storage.mtls.googleapis.com).
	r.Host = targetHost
	r.URL.Scheme = "https"
	r.URL.Host = targetHost

	resp, err := p.Transport.RoundTrip(r)
	if err != nil {
		log.Printf("Failed to round trip request: %v", err)
		p.handleError(w, err)
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
func newECPProxy(proxy_config *ProxyConfig, key *client.Key) *ECPProxy {
	tlsCert := &tls.Certificate{
		Certificate: key.CertificateChain(),
		PrivateKey:  key,
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{*tlsCert},
		},
		// Controls the maximum time to wait for a TLS handshake.
		TLSHandshakeTimeout: proxy_config.TLSHandshakeTimeout,

		// Timeout for the entire request, including connection,
		// request writing, and response header reading.
		ResponseHeaderTimeout: proxy_config.ProxyRequestTimeout,

		// Controls the time to wait for a connection to be established.
		// Use DialContext for modern Go, which also allows for cancellation.
		DialContext: (&net.Dialer{
			Timeout:   proxy_config.DialTimeout,     // Timeout for establishing connections
			KeepAlive: proxy_config.KeepAlivePeriod, // Keep-alive period for TCP connections
		}).DialContext,
		IdleConnTimeout: proxy_config.IdleConnTimeout, // Keep idle connections for reuse
	}
	return &ECPProxy{
		Transport: transport,
	}
}

func runProxyWrapper(proxy_config *ProxyConfig, ecp_proxy *ECPProxy, shutdownChan chan struct{}) {
	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", proxy_config.Port),
		Handler: ecp_proxy,
	}

	// Start a goroutine that listens for shutdown signal.
	go func() {
		<-shutdownChan
		log.Println("Shutting down proxy server...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), proxy_config.ShutdownTimeout)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			log.Printf("Failed to shutdown proxy server: %v", err)
		}
	}()

	log.Printf("Starting proxy server on port %d", proxy_config.Port)
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("Failed to start proxy server: %v", err)
	}
}

func main() {
	log.Print("Starting ECP Proxy...")
	proxy_config, err := initConfigFromFlags()
	if err != nil {
		log.Fatalf("Failed to initialize ECP Proxy: %v", err)
	}

	log.Println("Loading ECP credential...")
	// Create a client that uses the ECP signer.
	key, err := client.Cred(proxy_config.EnterpriseCertificateFilePath)
	if err != nil {
		log.Fatalf("Failed to get ECP credential: %v", err)
	}
	defer key.Close()
	ecp_proxy := newECPProxy(proxy_config, key)

	// Create a channel to listen for OS signals.
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

	// Create a channel to signal shutdown.
	shutdownChan := make(chan struct{})

	// Start a goroutine to listen for OS signals.
	go func() {
		<-signalChan
		log.Println("Received interrupt signal, initiating shutdown...")
		close(shutdownChan)
	}()

	runProxyWrapper(proxy_config, ecp_proxy, shutdownChan)
	log.Println("Proxy server shut down gracefully.")
}
