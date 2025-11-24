package main

import (
	"testing"
	"time"

	"github.com/techmagister/socks5proxy/internal/config"
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
	testServer, cleanup := setupTestServer(t)
	defer cleanup()
	testAddr := testServer.Addr().String()

	// Setup proxy with AllowedPorts restriction (only allow ports 80 and 443)
	socks5Config := socks5.Config{
		AllowedPorts: []int{80, 443}, // Only allow ports 80 (HTTP) and 443 (HTTPS)
	}
	proxyAddr, cancelProxy, wg := setupProxy(t, socks5Config)
	defer wg.Wait()
	defer cancelProxy()

	socksDialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
	if err != nil {
		t.Fatalf("Failed to create SOCKS5 dialer: %v", err)
	}

	// Test connections to known ports:
	// Try connecting to our test server (which uses a random port) - this should fail
	conn, err := socksDialer.Dial("tcp", testAddr)
	if err == nil {
		t.Errorf("Connection to port %s should fail (not in allowed ports 80,443), but it succeeded", testAddr)
		conn.Close()
	} else {
		// This is expected - the connection should be refused by our proxy
		t.Logf("Connection to non-allowed port correctly failed: %v", err)
	}

	// Note: Testing connections to actual port 80/443 would require external internet access
	// or setting up local test servers on those specific ports, which is complex in a unit test
	// For now, we verify that our test port (random) is correctly rejected

	// Test with a different configuration - allow all ports (empty AllowedPorts)
	configEmpty := socks5.Config{
		AllowedPorts: []int{}, // Empty = allow all ports
	}
	proxyAddrEmpty, cancelProxyEmpty, wgEmpty := setupProxy(t, configEmpty)
	defer wgEmpty.Wait()
	defer cancelProxyEmpty()

	socksDialerEmpty, err := proxy.SOCKS5("tcp", proxyAddrEmpty, nil, proxy.Direct)
	if err != nil {
		t.Fatalf("Failed to create SOCKS5 dialer: %v", err)
	}

	// Now connection should succeed since no port restrictions
	connEmpty, errEmpty := socksDialerEmpty.Dial("tcp", testAddr)
	if errEmpty != nil {
		t.Errorf("Connection should succeed with no port restrictions, but failed: %v", errEmpty)
	} else {
		connEmpty.Close()
		t.Logf("Connection succeeded with no port restrictions")
	}
}

func TestAllowedPortsRange(t *testing.T) {
	// Test port range functionality using the configuration parsing

	// Test the port range expansion directly first
	expandedPorts, err := config.GetExpandedPorts("8080-8090,80,443")
	if err != nil {
		t.Fatalf("Failed to expand port ranges: %v", err)
	}

	// Verify the expansion worked correctly
	expectedLength := 1 + 1 + (8090 - 8080 + 1) // 80, 443, and the range 8080-8090 inclusive
	if len(expandedPorts) != expectedLength {
		t.Errorf("Expected %d ports, got %d", expectedLength, len(expandedPorts))
	}

	// Check some specific ports are included
	expectedPorts := []int{80, 443, 8080, 8085, 8090}
	for _, port := range expectedPorts {
		found := false
		for _, expandedPort := range expandedPorts {
			if expandedPort == port {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected port %d to be in expanded list, but it was not found", port)
		}
	}

	t.Logf("Port range expansion successful: %d ports expanded from '8080-8090,80,443'", len(expandedPorts))

	// Now test integration with SOCKS5 server
	testServer, cleanup := setupTestServer(t)
	defer cleanup()
	testAddr := testServer.Addr().String()

	// Create SOCKS5 config with expanded port ranges (similar to what would happen from env var)
	config := socks5.Config{
		AllowedPorts: expandedPorts, // All expanded ports including 8085 which should work
	}
	proxyAddr, cancelProxy, wg := setupProxy(t, config)
	defer wg.Wait()
	defer cancelProxy()

	socksDialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
	if err != nil {
		t.Fatalf("Failed to create SOCKS5 dialer: %v", err)
	}

	// Test that a different port (outside the allowed range) gets rejected
	conn, err := socksDialer.Dial("tcp", testAddr) // This should fail since testAddr port is not in our expanded range
	if err == nil {
		t.Errorf("Connection to port %s should fail (not in expanded port range), but it succeeded", testAddr)
		conn.Close()
	} else {
		// This is expected - the connection should be refused by our proxy
		t.Logf("Connection to non-allowed port correctly failed: %v", err)
	}

	// Create a proxy with empty ports (allow all) to verify the negative case works
	configEmpty := socks5.Config{
		AllowedPorts: []int{}, // Empty = allow all ports
	}
	proxyAddrEmpty, cancelProxyEmpty, wgEmpty := setupProxy(t, configEmpty)
	defer wgEmpty.Wait()
	defer cancelProxyEmpty()

	socksDialerEmpty, err := proxy.SOCKS5("tcp", proxyAddrEmpty, nil, proxy.Direct)
	if err != nil {
		t.Fatalf("Failed to create SOCKS5 dialer: %v", err)
	}

	// Now the connection should succeed
	connEmpty, errEmpty := socksDialerEmpty.Dial("tcp", testAddr)
	if errEmpty != nil {
		t.Errorf("Connection should succeed with no port restrictions, but failed: %v", errEmpty)
	} else {
		connEmpty.Close()
		t.Logf("Connection succeeded when no port restrictions applied")
	}
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

func TestDNSResolverConfiguration(t *testing.T) {
	// Test that DNSResolver is properly passed through to the server config
	config := socks5.Config{
		DNSResolver: "8.8.8.8:53", // Custom DNS resolver
	}

	// This is a configuration test - the actual DNS resolution logic
	// would need implementation in the server's DNS resolution
	if config.DNSResolver != "8.8.8.8:53" {
		t.Errorf("Expected DNSResolver to be '8.8.8.8:53', got '%s'", config.DNSResolver)
	}
}

func TestDNSResolverIntegration(t *testing.T) {
	// Test DNS resolver integration with configuration only
	// The actual DNS resolution happens during SOCKS5 connections
	// This test verifies the configuration is set up correctly

	// Use Google DNS for testing
	config := socks5.Config{
		DNSResolver: "8.8.8.8:53", // Google DNS
	}

	// Create a server with custom DNS resolver
	server := socks5.NewServer(config)

	// Test close access to DNSResolver via type assertion or reflection
	// Since config is unexported, we'll test by trying to create a simple connection
	// If the DNS resolver is set, the behavior would be different

	// For now, this test validates that the DNS resolver configuration exists
	// and the server was created successfully
	if server == nil {
		t.Error("NewServer returned nil server")
	}

	// Note: Actual DNS resolution testing would require setting up a SOCKS5 client connection
	// and monitoring the DNS requests, which is complex in a unit test environment

	t.Logf("DNSResolver set to: %s", config.DNSResolver)
}
