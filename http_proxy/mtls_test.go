package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/signal"
	"syscall"
	"testing"
	"time"
)

const (
	successMessage = "successful response!"
	errorMessage   = "error message!"
)

var (
	certs1 = NewMTLSInMemoryCerts()
	certs2 = NewMTLSInMemoryCerts()
)

func generateCert(ca *x509.Certificate, caKey *rsa.PrivateKey, cn string, isClient bool) (tls.Certificate, []byte, crypto.PrivateKey) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{cn},                       // important for hostname match
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")}, // allow IP connect
	}
	if isClient {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		template.DNSNames = nil // clients don’t need SANs
		template.IPAddresses = nil
	}

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	certDER, _ := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	tlsCert, _ := tls.X509KeyPair(certPEM, keyPEM)
	return tlsCert, certPEM, key
}

// Struct holding all generated certs/pools
type MTLSInMemoryCerts struct {
	CAPool     *x509.CertPool
	ServerCert tls.Certificate
	ServerKey  crypto.PrivateKey
	ClientCert tls.Certificate
	ClientKey  crypto.PrivateKey
}

// Factory function: creates CA, server, and client certs in memory
func NewMTLSInMemoryCerts() *MTLSInMemoryCerts {
	// 1. Generate CA
	ca := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caDER, _ := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)

	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caPEM)

	// 2. Generate server cert (signed by CA, includes SANs)
	serverCert, _, serverKey := generateCert(ca, caKey, "localhost", false)

	// 3. Generate client cert (signed by CA)
	clientCert, _, clientKey := generateCert(ca, caKey, "TestClient", true)

	return &MTLSInMemoryCerts{
		CAPool:     caPool,
		ServerCert: serverCert,
		ServerKey:  serverKey,
		ClientCert: clientCert,
		ClientKey:  clientKey,
	}
}

func createTLSBackendServer(expectedResponse string, expectedStatusCode int, certs *MTLSInMemoryCerts) *httptest.Server {
	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if expectedStatusCode == http.StatusOK {
			fmt.Fprint(w, expectedResponse)
		} else {
			// Write error
			http.Error(w, expectedResponse, expectedStatusCode)
		}
	}))
	backend.TLS = &tls.Config{
		Certificates: []tls.Certificate{certs.ServerCert},
		ClientCAs:    certs.CAPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}
	return backend
}

// Send HTTP requests to ECP Proxy. Validate responses.
func TestECPProxyWithHTTPClient(t *testing.T) {
	// Init MTLS backendServer
	validMTLSBackendServer := createTLSBackendServer(successMessage, http.StatusOK, certs1)
	validMTLSBackendServer.StartTLS()
	defer validMTLSBackendServer.Close()

	// Init MTLS backend server that always returns an (non-mtls related) error
	backendServerReturnsError := createTLSBackendServer(errorMessage, http.StatusInternalServerError, certs1)
	backendServerReturnsError.StartTLS()
	defer backendServerReturnsError.Close()

	// Init a passthrough proxy, to test proxy chaining
	passthroughProxyServer := httptest.NewServer(http.HandlerFunc(ProxyHandler))
	defer passthroughProxyServer.Close()

	validMTLSBackendServerHost := validMTLSBackendServer.Listener.Addr().String()       // e.g. "127.0.0.1:12345"
	backendServerReturnsErrorHost := backendServerReturnsError.Listener.Addr().String() // e.g. "127.0.0.1:12345"
	validPassthroughURL := passthroughProxyServer.URL
	invalidPassthroughURL := "1234-bad-server.com"

	testCases := []struct {
		name                    string
		ecpMTLSCerts            *MTLSInMemoryCerts
		targetHostHeader        string
		passthroughProxyAddress string
		wantStatusCode          int
		expectedResponseBody    string
		wantECPProxyError       bool
	}{
		{
			name:                    "successful request",
			ecpMTLSCerts:            certs1,
			targetHostHeader:        validMTLSBackendServerHost,
			passthroughProxyAddress: "",
			wantStatusCode:          http.StatusOK,
			expectedResponseBody:    successMessage,
			wantECPProxyError:       false,
		},
		{
			name:                    "target header is not allowed",
			ecpMTLSCerts:            certs1,
			targetHostHeader:        "127.0.0.0:1",
			passthroughProxyAddress: "",
			wantStatusCode:          http.StatusForbidden,
			wantECPProxyError:       true,
		},
		{
			name:                    "invalid target header",
			ecpMTLSCerts:            certs1,
			targetHostHeader:        "123-not-allowed.com",
			passthroughProxyAddress: "",
			wantStatusCode:          http.StatusForbidden,
			wantECPProxyError:       true,
		},
		{
			name:                    "empty target header",
			ecpMTLSCerts:            certs1,
			targetHostHeader:        "",
			passthroughProxyAddress: "",
			wantStatusCode:          http.StatusBadRequest,
			wantECPProxyError:       true,
		},
		{
			name:                    "ecp proxy server is using invalid mtls certs, unable to complete handshake",
			ecpMTLSCerts:            certs2, // these do not match validMTLSBackendServer's mTLS certs (certs1)
			targetHostHeader:        validMTLSBackendServerHost,
			passthroughProxyAddress: "",
			wantStatusCode:          http.StatusBadGateway,
			wantECPProxyError:       true,
		},
		{
			name:                    "backend server returns an error",
			ecpMTLSCerts:            certs1,
			targetHostHeader:        backendServerReturnsErrorHost,
			passthroughProxyAddress: "",
			wantStatusCode:          http.StatusInternalServerError,
			wantECPProxyError:       false, // no ecp internal error, just forward the response
		},
		// tests that use proxy Chaining
		{
			name:                    "successful request, with proxy chain",
			ecpMTLSCerts:            certs1,
			targetHostHeader:        validMTLSBackendServerHost,
			passthroughProxyAddress: validPassthroughURL,
			wantStatusCode:          http.StatusOK,
			expectedResponseBody:    successMessage,
			wantECPProxyError:       false,
		},
		{
			name:                    "target header is not allowed, with proxy chain",
			ecpMTLSCerts:            certs1,
			targetHostHeader:        "127.0.0.0:1",
			passthroughProxyAddress: validPassthroughURL,
			wantStatusCode:          http.StatusForbidden,
			wantECPProxyError:       true,
		},
		{
			name:                    "target header not allowed header with proxy chain",
			ecpMTLSCerts:            certs1,
			targetHostHeader:        "123-not-allowed.com",
			passthroughProxyAddress: validPassthroughURL,
			wantStatusCode:          http.StatusForbidden,
			wantECPProxyError:       true,
		},
		{
			name:                    "empty target header with proxy chain",
			ecpMTLSCerts:            certs1,
			targetHostHeader:        "",
			passthroughProxyAddress: validPassthroughURL,
			wantStatusCode:          http.StatusBadRequest,
			wantECPProxyError:       true,
		},
		{
			name:                    "ecp proxy server is using invalid mtls certs, unable to complete handshake with proxy chain",
			ecpMTLSCerts:            certs2, // these do not match validMTLSBackendServer's mTLS certs (certs1)
			targetHostHeader:        validMTLSBackendServerHost,
			passthroughProxyAddress: validPassthroughURL,
			wantStatusCode:          http.StatusBadGateway,
			wantECPProxyError:       true,
		},
		{
			name:                    "backend server returns an error with proxy chain",
			ecpMTLSCerts:            certs1,
			targetHostHeader:        backendServerReturnsErrorHost,
			passthroughProxyAddress: validPassthroughURL,
			wantStatusCode:          http.StatusInternalServerError,
			wantECPProxyError:       false, // no ecp internal error, just forward the response
		},
		{
			name:                    "passthrough proxy doesnt exist",
			ecpMTLSCerts:            certs1,
			targetHostHeader:        validMTLSBackendServerHost,
			passthroughProxyAddress: invalidPassthroughURL,
			wantStatusCode:          http.StatusBadGateway,
			wantECPProxyError:       true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ecpProxyPort := 8080

			tlsConfig := &tls.Config{
				Certificates: []tls.Certificate{
					{
						Certificate: tc.ecpMTLSCerts.ClientCert.Certificate,
						PrivateKey:  tc.ecpMTLSCerts.ClientKey,
					},
				},
				RootCAs: tc.ecpMTLSCerts.CAPool,
			}

			proxyConfig := &ProxyConfig{
				Port:              ecpProxyPort,
				AllowedHostsRegex: localhostRegex,
				TlsConfig:         tlsConfig,
			}

			if tc.passthroughProxyAddress != "" {
				passthroughProxyServerURL, err := url.Parse(tc.passthroughProxyAddress)
				if err != nil {
					t.Fatalf("Failed to parse passthrough proxy URL: %v", err)
				}
				proxyConfig.ProxyURL = passthroughProxyServerURL
			}

			transport := newECPProxyTransport(proxyConfig)
			handler := newECPProxyHandler(proxyConfig, transport)
			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			go runServer(ctx, proxyConfig, handler)
			// Wait a short time for the server to become ready.
			time.Sleep(100 * time.Millisecond)

			expProxyURL := fmt.Sprintf("http://127.0.0.1:%d/", ecpProxyPort)
			req, err := http.NewRequest("GET", expProxyURL, nil)
			if err != nil {
				t.Fatalf("failed to create request: %v", err)
			}

			req.Header.Set("X-Goog-EcpProxy-Target-Host", tc.targetHostHeader)

			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("request via proxy failed: %v", err)
			}
			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("failed to read response body: %v", err)
			}

			// Assert on status code first, as it's always expected
			if resp.StatusCode != tc.wantStatusCode {
				t.Errorf("expected status code %d, got %d", tc.wantStatusCode, resp.StatusCode)
			}

			if tc.wantStatusCode == http.StatusOK {
				// We expect a plain text success response
				gotBody := string(body)
				if gotBody != tc.expectedResponseBody {
					t.Errorf("expected body %q, got %q", tc.expectedResponseBody, gotBody)
				}
			} else {
				if tc.wantECPProxyError {
					if resp.Header.Get(ecpInternalErrorHeader) == "" {
						t.Errorf("missing error response header")
					}
					var gotError ErrorResponse
					if err := json.Unmarshal(body, &gotError); err != nil {
						t.Fatalf("failed to unmarshal JSON error response: %v", err)
					}
					if gotError.Code != tc.wantStatusCode {
						t.Errorf("incorrect status code %d, got %d", tc.wantStatusCode, gotError.Code)
					}
					if gotError.Error == "" {
						t.Errorf("error message field `Error` is empty")

					}
					if gotError.Message == "" {
						t.Errorf("error message field `Message` is empty")
					}
				} else {
					if resp.Header.Get(ecpInternalErrorHeader) != "" {
						t.Errorf("unexpected error header included")
					}
				}
			}
		})
	}
}
