package main

import (
	"testing"
	"time"

	"github.com/techmagister/socks5proxy/internal/socks5"
	"golang.org/x/net/proxy"
)

func TestConnectionLimit(t *testing.T) {
	// Test that connection limit works properly
	testServer, cleanup := setupTestServer(t)
	defer cleanup()
	testAddr := testServer.Addr().String()

	// Setup proxy with connection limit of 1
	config := socks5.Config{
		ConnectionLimit: 1, // Only allow 1 concurrent connection
	}
	proxyAddr, cancelProxy, wg := setupProxy(t, config)
	defer wg.Wait()
	defer cancelProxy()

	socksDialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
	if err != nil {
		t.Fatalf("Failed to create SOCKS5 dialer: %v", err)
	}

	// First connection should succeed
	conn1, err1 := socksDialer.Dial("tcp", testAddr)
	if err1 != nil {
		t.Fatalf("First connection should succeed: %v", err1)
	}
	defer conn1.Close()

	// Give the proxy a moment to establish the connection
	time.Sleep(100 * time.Millisecond)

	// Second connection should fail due to limit
	conn2, err2 := socksDialer.Dial("tcp", testAddr)
	if err2 == nil {
		t.Errorf("Second connection should fail due to connection limit")
		// Clean up if it unexpectedly succeeded
		if conn2 != nil {
			conn2.Close()
		}
	}
}
