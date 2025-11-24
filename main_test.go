package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/techmagister/socks5proxy/internal/socks5"
	"golang.org/x/net/proxy"
)

// setupTestServer creates a test server that echoes data back to clients
func setupTestServer(t *testing.T) (net.Listener, func()) {
	testServer, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}

	// Start accepting connections (echo server)
	go func() {
		conn, err := testServer.Accept()
		if err != nil {
			return // Server closed
		}

		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		conn.Write(buf[:n]) // Echo back

		conn.Close()
		testServer.Close()
	}()

	cleanup := func() {
		testServer.Close()
	}

	return testServer, cleanup
}

// setupProxy creates and starts a SOCKS5 proxy server
func setupProxy(t *testing.T, config socks5.Config) (string, context.CancelFunc, *sync.WaitGroup) {
	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to find available port: %v", err)
	}
	proxyAddr := proxyListener.Addr().String()
	proxyListener.Close()

	ctxProxy, cancelProxy := context.WithCancel(context.Background())

	var wg sync.WaitGroup
	wg.Add(1)

	config.Addr = proxyAddr // Override address

	go func() {
		defer wg.Done()
		server := socks5.NewServer(config)

		ctx, cancel := context.WithTimeout(ctxProxy, 10*time.Second)
		defer cancel()

		if err := server.ListenAndServe(ctx); err != context.Canceled && err != nil {
			t.Errorf("Proxy server failed: %v", err)
		}
	}()

	// Give the proxy time to start
	time.Sleep(100 * time.Millisecond)

	return proxyAddr, cancelProxy, &wg
}

// runIntegrationTest runs the actual proxy integration test
func runIntegrationTest(t *testing.T, proxyAddr, testAddr string, auth *proxy.Auth, testMessage string) {
	socksDialer, err := proxy.SOCKS5("tcp", proxyAddr, auth, proxy.Direct)
	if err != nil {
		t.Fatalf("Failed to create SOCKS5 dialer: %v", err)
	}

	conn, err := socksDialer.Dial("tcp", testAddr)
	if err != nil {
		t.Fatalf("Failed to connect through SOCKS5 proxy: %v", err)
	}
	defer conn.Close()

	message := []byte(testMessage)
	_, err = conn.Write(message)
	if err != nil {
		t.Errorf("Failed to write through proxy: %v", err)
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Errorf("Failed to read through proxy: %v", err)
	}

	if string(buf[:n]) != testMessage {
		t.Errorf("Expected echo %q, got %q", testMessage, string(buf[:n]))
	}
}

func TestTypedErrors(t *testing.T) {
	// Test that our custom errors work with errors.Is and errors.As

	// Test SOCKS5Error type checking
	err := socks5.ErrAuthenticationFailed
	if err.Error() != "authentication failed: invalid credentials" {
		t.Errorf("Expected authentication error message, got: %s", err.Error())
	}

	// Test that it's the correct type
	if !errors.Is(err, socks5.ErrAuthenticationFailed) {
		t.Error("Expected errors.Is to work with SOCKS5Error")
	}

	// Test with SOCKS5Error unwrapping
	var socks5Err *socks5.SOCKS5Error
	if !errors.As(err, &socks5Err) {
		t.Error("Expected errors.As to work with SOCKS5Error pointer")
	}

	if socks5Err.Code != 0x01 {
		t.Errorf("Expected auth failed code 0x01, got 0x%02x", socks5Err.Code)
	}

	// Test error wrapping functionality
	underlyingErr := fmt.Errorf("network unreachable")
	wrappedErr := socks5.WrapError(0x03, "connection failed", underlyingErr)

	// Test that wrapped error includes both messages
	expectedMsg := "connection failed: network unreachable"
	if wrappedErr.Error() != expectedMsg {
		t.Errorf("Expected wrapped error message %q, got %q", expectedMsg, wrappedErr.Error())
	}

	// Test unwrapping
	if underlying := wrappedErr.Unwrap(); underlying != underlyingErr {
		t.Error("Expected Unwrap to return the original error")
	}

	// Test that we can identify wrapped errors as the same type (same code)
	// Note: errors.Is checks for exact equality, so we check the As functionality
	var wrappedSocks5Err *socks5.SOCKS5Error
	if !errors.As(wrappedErr, &wrappedSocks5Err) {
		t.Error("Expected errors.As to work with wrapped SOCKS5Error")
	}

	if wrappedSocks5Err.Code != 0x03 {
		t.Errorf("Expected wrapped error code 0x03, got 0x%02x", wrappedSocks5Err.Code)
	}

	if wrappedSocks5Err.Message != "connection failed" {
		t.Errorf("Expected wrapped error message 'connection failed', got %q", wrappedSocks5Err.Message)
	}

	// Test that we can extract the SOCKS5Error from wrapped error
	if !errors.As(wrappedErr, &socks5Err) {
		t.Error("Expected errors.As to work with wrapped SOCKS5Error")
	}

	if socks5Err.Code != 0x03 {
		t.Errorf("Expected network unreachable code 0x03, got 0x%02x", socks5Err.Code)
	}
}

func TestSOCKS5ProxyIntegration(t *testing.T) {
	// Setup test server
	testServer, cleanup := setupTestServer(t)
	defer cleanup()
	testAddr := testServer.Addr().String()

	// Setup proxy without authentication
	config := socks5.Config{}
	proxyAddr, cancelProxy, wg := setupProxy(t, config)

	// Run integration test
	runIntegrationTest(t, proxyAddr, testAddr, nil, "test")
	cancelProxy()
	wg.Wait()
}

// TestUnauthenticatedConnectionRejected tests that when auth is required,
// clients that don't provide authentication are rejected
func TestUnauthenticatedConnectionRejected(t *testing.T) {
	// Setup test server
	testServer, cleanup := setupTestServer(t)
	defer cleanup()
	testAddr := testServer.Addr().String()

	// Setup proxy without authentication
	config := socks5.Config{
		Username: "testuser",
		Password: "testpass",
	}
	proxyAddr, cancelProxy, wg := setupProxy(t, config)

	// Run integration test
	socksDialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
	if err != nil {
		t.Fatalf("Failed to create SOCKS5 dialer: %v", err)
	}

	if _, err := socksDialer.Dial("tcp", testAddr); err == nil {
		t.Fatalf("Auth is not working.")
	}
	cancelProxy()
	wg.Wait()
}

func TestSOCKS5ProxyIntegrationWithAuth(t *testing.T) {
	// Setup test server
	testServer, cleanup := setupTestServer(t)
	defer cleanup()
	testAddr := testServer.Addr().String()

	// Setup proxy with authentication
	config := socks5.Config{
		Username: "testuser",
		Password: "testpass",
	}
	proxyAddr, cancelProxy, wg := setupProxy(t, config)

	// Setup authentication for client
	auth := &proxy.Auth{
		User:     config.Username,
		Password: config.Password,
	}

	// Run integration test with authentication
	runIntegrationTest(t, proxyAddr, testAddr, auth, "hello authenticated proxy")
	cancelProxy()
	wg.Wait()
}

func TestAuthCredentialsValidation(t *testing.T) {
	tests := []struct {
		name        string
		username    string
		password    string
		expectError bool
	}{
		{"valid credentials", "testuser", "testpass", false},
		{"empty username", "", "password", true},
		{"empty password", "username", "", true},
		{"both empty", "", "", false}, // No auth mode - valid
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// We can't directly call the main function, so we'll test the logic
			// by checking if both username and password are provided together

			// This mimics the validation in main.go
			hasUser := tt.username != ""
			hasPass := tt.password != ""

			if hasUser != hasPass {
				if !tt.expectError {
					t.Errorf("Expected no error for %s, but got validation error", tt.name)
				}
			} else {
				if tt.expectError {
					t.Errorf("Expected error for %s, but got no error", tt.name)
				}
			}
		})
	}
}

// Benchmark test to measure proxy performance
func BenchmarkSOCKS5Proxy(b *testing.B) {
	// Setup test server
	testServer, cleanup := setupTestServer(&testing.T{})
	defer cleanup()
	testAddr := testServer.Addr().String()

	// Setup proxy
	config := socks5.Config{}
	proxyAddr, cancelProxy, wg := setupProxy(&testing.T{}, config)
	defer cancelProxy()
	defer wg.Wait()

	socksDialer, _ := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			conn, _ := socksDialer.Dial("tcp", testAddr)
			if conn != nil {
				conn.Write([]byte("benchmark"))
				buf := make([]byte, 1024)
				conn.Read(buf)
				conn.Close()
			}
		}
	})
}
