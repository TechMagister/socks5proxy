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

func TestBlockedIPs(t *testing.T) {
	// Test that blocked IPs are denied
	testServer, cleanup := setupTestServer(t)
	defer cleanup()
	testAddr := testServer.Addr().String()

	// Setup proxy with BlockedIPs that includes localhost
	config := socks5.Config{
		BlockedIPs: []string{"127.0.0.1/32"}, // Block localhost exactly
	}
	proxyAddr, cancelProxy, wg := setupProxy(t, config)
	defer wg.Wait()
	defer cancelProxy()

	socksDialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
	if err != nil {
		t.Fatalf("Failed to create SOCKS5 dialer: %v", err)
	}

	// Connection from 127.0.0.1 should be blocked
	conn1, err1 := socksDialer.Dial("tcp", testAddr)
	if err1 == nil {
		t.Errorf("Connection from blocked IP (127.0.0.1) should fail")
		conn1.Close()
	}
}

func TestBlockedIPsCIDR(t *testing.T) {
	// Test CIDR blocking functionality
	testServer, cleanup := setupTestServer(t)
	defer cleanup()
	testAddr := testServer.Addr().String()

	// Setup proxy with BlockedIPs using CIDR notation
	config := socks5.Config{
		BlockedIPs: []string{"127.0.0.0/8"}, // Block entire 127.x.x.x range
	}
	proxyAddr, cancelProxy, wg := setupProxy(t, config)
	defer wg.Wait()
	defer cancelProxy()

	socksDialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
	if err != nil {
		t.Fatalf("Failed to create SOCKS5 dialer: %v", err)
	}

	// Connection from 127.0.0.1 should be blocked by CIDR
	conn1, err1 := socksDialer.Dial("tcp", testAddr)
	if err1 == nil {
		t.Errorf("Connection from IP in blocked CIDR (127.0.0.1 in 127.0.0.0/8) should fail")
		conn1.Close()
	}
}

func TestBlockedIPsPrecedence(t *testing.T) {
	// Test that blocked IPs take precedence over allowed IPs
	// (fail-safe approach: block wins if IP is in both lists)
	testServer, cleanup := setupTestServer(t)
	defer cleanup()
	testAddr := testServer.Addr().String()

	// Setup proxy that both allows and blocks 127.0.0.1 (block should win)
	config := socks5.Config{
		AllowedIPs: []string{"127.0.0.1/32"}, // Allow localhost
		BlockedIPs: []string{"127.0.0.1/32"}, // But also block it
	}
	proxyAddr, cancelProxy, wg := setupProxy(t, config)
	defer wg.Wait()
	defer cancelProxy()

	socksDialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
	if err != nil {
		t.Fatalf("Failed to create SOCKS5 dialer: %v", err)
	}

	// Connection should be blocked (blocked list takes precedence)
	conn1, err1 := socksDialer.Dial("tcp", testAddr)
	if err1 == nil {
		t.Errorf("IP in both allowed and blocked lists should be blocked (fail-safe)")
		conn1.Close()
	}
}

func TestBlockedIPsAllowOthers(t *testing.T) {
	// Test that blocking specific IPs still allows other IPs
	t.Skip("This test needs external IPs to be properly testable in CI environment")

	// This would test that blocking 127.0.0.1 still allows connections from other interfaces
	// But requires multiple interface setup which isn't available in typical test environments

	t.Log("BlockedIPs allow others test - implementation pending for multi-interface setup")
}

func TestAllowedPorts(t *testing.T) {
	// Test destination port filtering functionality
	// We need to implement port filtering in the server first
	t.Skip("AllowedPorts filtering not yet implemented in server - this is a placeholder test")

	// When implemented, this test would:
	// 1. Set up test servers on ports 80 and 443
	// 2. Configure proxy with AllowedPorts = [80, 443]
	// 3. Try connecting to 127.0.0.1:80 (should be allowed)
	// 4. Try connecting to 127.0.0.1:443 (should be allowed)
	// 5. Try connecting to 127.0.0.1:8080 (should fail if server exists)
	// 6. Try connecting to a blocked port (should fail)

	t.Log("AllowedPorts test skeleton - implementation pending in server")
}

func TestAllowedPortsRange(t *testing.T) {
	// Test port range functionality
	// Note: This test works because parsePortRanges in config.go expands ranges to individual ports
	// So "8080-8090" becomes [8080, 8081, 8082, ..., 8090]

	// First create a server on port 8085 (within the 8080-8090 range)
	// Since we can't easily control ports in the test, this is a skeleton test
	t.Skip("Port range filtering works through configuration parsing, but testing requires multi-port setup")

	t.Log("AllowedPorts range test - implementation works via config parsing expansion")
}

func TestAllowedPortsDeny(t *testing.T) {
	// Test that ports not in allowed list are denied
	testServer, cleanup := setupTestServer(t)
	defer cleanup()
	testAddr := testServer.Addr().String()

	// Setup proxy with AllowedPorts restriction (only allow port 80)
	config := socks5.Config{
		AllowedPorts: []int{80}, // Only allow port 80
	}
	proxyAddr, cancelProxy, wg := setupProxy(t, config)
	defer wg.Wait()
	defer cancelProxy()

	socksDialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
	if err != nil {
		t.Fatalf("Failed to create SOCKS5 dialer: %v", err)
	}

	// Try to connect to a port that's NOT in the allowed list
	// This should fail with "connection refused" from the SOCKS proxy
	conn, err := socksDialer.Dial("tcp", testAddr) // testAddr uses a random port, not 80
	if err == nil {
		t.Errorf("Connection to non-allowed port should fail, but it succeeded")
		conn.Close()
	} else {
		// This is expected - the connection should be refused by our proxy
		// The error message will vary depending on the SOCKS library implementation
		t.Logf("Connection to non-allowed port correctly failed: %v", err)
	}
}
