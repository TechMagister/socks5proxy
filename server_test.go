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

func TestAllowedIPs(t *testing.T) {
	// Test IP filtering functionality
	testServer, cleanup := setupTestServer(t)
	defer cleanup()
	testAddr := testServer.Addr().String()

	// Setup proxy with AllowedIPs restriction (only allow 127.0.0.1)
	config := socks5.Config{
		AllowedIPs: []string{"127.0.0.1/32"}, // Only allow localhost
	}
	proxyAddr, cancelProxy, wg := setupProxy(t, config)
	defer wg.Wait()
	defer cancelProxy()

	socksDialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
	if err != nil {
		t.Fatalf("Failed to create SOCKS5 dialer: %v", err)
	}

	// Connection from 127.0.0.1 should be allowed
	conn1, err1 := socksDialer.Dial("tcp", testAddr)
	if err1 != nil {
		t.Errorf("Connection from allowed IP (127.0.0.1) should succeed: %v", err1)
	} else {
		conn1.Close()
	}
}

func TestAllowedIPsCIDR(t *testing.T) {
	// Test CIDR notation in AllowedIPs
	testServer, cleanup := setupTestServer(t)
	defer cleanup()
	testAddr := testServer.Addr().String()

	// Setup proxy with AllowedIPs using CIDR notation
	config := socks5.Config{
		AllowedIPs: []string{"127.0.0.0/8"}, // Allow entire 127.x.x.x range
	}
	proxyAddr, cancelProxy, wg := setupProxy(t, config)
	defer wg.Wait()
	defer cancelProxy()

	socksDialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
	if err != nil {
		t.Fatalf("Failed to create SOCKS5 dialer: %v", err)
	}

	// Connection from 127.0.0.1 should be allowed by CIDR
	conn1, err1 := socksDialer.Dial("tcp", testAddr)
	if err1 != nil {
		t.Errorf("Connection from IP in allowed CIDR (127.0.0.1 in 127.0.0.0/8) should succeed: %v", err1)
	} else {
		conn1.Close()
	}
}

func TestAllowedIPsDeny(t *testing.T) {
	// Test that IPs outside the allowed list are denied
	testServer, cleanup := setupTestServer(t)
	defer cleanup()
	testAddr := testServer.Addr().String()

	// Setup proxy with AllowedIPs that doesn't include localhost
	config := socks5.Config{
		AllowedIPs: []string{"192.168.1.0/24"}, // Only allow 192.168.1.x range
	}
	proxyAddr, cancelProxy, wg := setupProxy(t, config)
	defer wg.Wait()
	defer cancelProxy()

	socksDialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
	if err != nil {
		t.Fatalf("Failed to create SOCKS5 dialer: %v", err)
	}

	// Connection from 127.0.0.1 should be denied
	conn1, err1 := socksDialer.Dial("tcp", testAddr)
	if err1 == nil {
		t.Errorf("Connection from non-allowed IP (127.0.0.1 not in 192.168.1.0/24) should fail")
		conn1.Close()
	}
}
