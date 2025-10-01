package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"
)

// ProxyHandler is the main handler for all incoming proxy requests.
// It decides whether to handle an HTTPS tunnel or a standard HTTP request.
func ProxyHandler(w http.ResponseWriter, r *http.Request) {
	// Log the incoming request
	log.Printf("Received request: %s %s %s", r.Method, r.Host, r.URL.String())

	if r.Method == http.MethodConnect {
		// Handle HTTPS requests using a tunnel
		handleTunneling(w, r)
	} else {
		// Handle standard HTTP requests
		handleHTTP(w, r)
	}
}

// handleHTTP forwards a standard HTTP request to the target server.
func handleHTTP(w http.ResponseWriter, r *http.Request) {
	// Create a new request to the target URL
	// For a forward proxy, the full URL is in r.RequestURI
	req, err := http.NewRequest(r.Method, r.RequestURI, r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("Proxy error: %v", err), http.StatusInternalServerError)
		return
	}

	// Copy headers from the original request
	req.Header = r.Header

	// Execute the request
	client := &http.Client{
		// Disable following redirects to match Python `allow_redirects=False`
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error forwarding request: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy response headers to the client
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// Send the status code
	w.WriteHeader(resp.StatusCode)

	// Copy the response body to the client
	written, err := io.Copy(w, resp.Body)
	if err != nil {
		log.Printf("Error copying response body: %v", err)
	}
	log.Printf("Copied %d bytes to client", written)
}

// handleTunneling handles CONNECT requests for setting up an HTTPS tunnel.
func handleTunneling(w http.ResponseWriter, r *http.Request) {
	// Establish a TCP connection to the target host
	destConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	// Respond to the client that the connection is established
	w.WriteHeader(http.StatusOK)

	// Hijack the client's connection to get direct access to the underlying TCP connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	// Start goroutines to transfer data in both directions
	go transfer(destConn, clientConn)
	go transfer(clientConn, destConn)
}

// transfer copies data from src to dst and closes dst when done.
func transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()
	io.Copy(destination, source)
}
