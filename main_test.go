package main

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/techmagister/socks5proxy/internal/socks5"
	"golang.org/x/net/proxy"
)

var testData = []byte("test")

func TestSOCKS5ProxyIntegration(t *testing.T) {
	// 1. Create a test server that just accepts connections (like a mock target server)
	testServer, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}
	defer testServer.Close()

	testAddr := testServer.Addr().String()

	ctxProxy, cancelProxy := context.WithCancel(context.Background())

	// Start accepting connections on test server
	go func() {
		for {
			conn, err := testServer.Accept()
			if err != nil {
				return // Server closed
			}

			// read string data from connection
			buf := make([]byte, 1024)
			n, err := conn.Read(buf)
			if err != nil {
				return // Connection closed
			}

			// buff to string
			msg := string(buf[:n])
			t.Logf("Received message from proxy: %s", msg)

			conn.Write(buf[:n])

			conn.Close() // Just close - we only care about connection establishment
		}
	}()

	// Find an available port for the proxy
	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to find available port: %v", err)
	}
	proxyAddr := proxyListener.Addr().String()
	proxyListener.Close()

	// 2. Start the proxy in a goroutine
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()

		config := socks5.Config{Addr: proxyAddr}
		server := socks5.NewServer(config)

		ctx, cancel := context.WithTimeout(ctxProxy, 10*time.Second)
		defer cancel()

		if err := server.ListenAndServe(ctx); err != context.Canceled && err != nil {
			t.Errorf("Proxy server failed: %v", err)
		}
	}()

	// Give the proxy time to start
	time.Sleep(200 * time.Millisecond)

	// 3. Use golang.org/x/net/proxy to create SOCKS5 dialer and test connection
	socksDialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
	if err != nil {
		t.Fatalf("Failed to create SOCKS5 dialer: %v", err)
	}

	// 4. Test connecting to our test server through the proxy
	conn, err := socksDialer.Dial("tcp", testAddr)
	if err != nil {
		t.Fatalf("Failed to connect through SOCKS5 proxy: %v", err)
	}
	defer conn.Close()

	// 5. Verify the connection worked by writing something and checking it doesn't fail
	_, err = conn.Write(testData)
	if err != nil {
		t.Errorf("Failed to write to connection through proxy: %v", err)
	}

	// receive data
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Errorf("Failed to read from connection through proxy: %v", err)
	}

	if string(buf[:n]) != string(testData) {
		t.Errorf("Received data does not contain test data")
	}
	cancelProxy()

	wg.Wait() // Wait for proxy to shut down
}

// TestSOCKS5ProxyIntegrationWithAuth tests integration with authentication enabled
func TestSOCKS5ProxyIntegrationWithAuth(t *testing.T) {
	// Setup similar to TestSOCKS5ProxyIntegration but with auth

	// 1. Create a test server
	testServer, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}
	defer testServer.Close()

	testAddr := testServer.Addr().String()

	ctxProxy, cancelProxy := context.WithCancel(context.Background())

	// Start accepting connections (simple echo server)
	go func() {
		for {
			conn, err := testServer.Accept()
			if err != nil {
				return // Server closed
			}

			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					c.Write(buf[:n]) // Echo back
				}
			}(conn)
		}
	}()

	// 2. Start proxy with authentication
	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to find available port: %v", err)
	}
	proxyAddr := proxyListener.Addr().String()
	proxyListener.Close()

	config := socks5.Config{
		Addr:     proxyAddr,
		Username: "testuser",
		Password: "testpass",
	}

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		server := socks5.NewServer(config)

		ctx, cancel := context.WithTimeout(ctxProxy, 10*time.Second)
		defer cancel()

		if err := server.ListenAndServe(ctx); err != context.Canceled && err != nil {
			t.Errorf("Proxy server failed: %v", err)
		}
	}()

	time.Sleep(200 * time.Millisecond)

	// 3. Create SOCKS5 dialer with authentication credentials
	auth := &proxy.Auth{
		User:     config.Username,
		Password: config.Password,
	}

	socksDialer, err := proxy.SOCKS5("tcp", proxyAddr, auth, proxy.Direct)
	if err != nil {
		t.Fatalf("Failed to create SOCKS5 dialer: %v", err)
	}

	// 4. Test connection through authenticated proxy
	conn, err := socksDialer.Dial("tcp", testAddr)
	if err != nil {
		t.Fatalf("Failed to connect through authenticated SOCKS5 proxy: %v", err)
	}
	defer conn.Close()

	// 5. Verify data can be sent and received
	testMessage := []byte("hello authenticated proxy")
	_, err = conn.Write(testMessage)
	if err != nil {
		t.Errorf("Failed to write through authenticated proxy: %v", err)
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Errorf("Failed to read through authenticated proxy: %v", err)
	}

	if string(buf[:n]) != string(testMessage) {
		t.Errorf("Expected echo %s, got %s", string(testMessage), string(buf[:n]))
	}

	cancelProxy()

	wg.Wait()
}
