package main

import (
	"testing"

	"github.com/techmagister/socks5proxy/internal/socks5"
	"golang.org/x/net/proxy"
)

// Benchmark test to measure proxy performance
func BenchmarkSOCKS5Proxy(b *testing.B) {
	// Setup test server
	testServer, cleanup := setupTestServer(&testing.T{})
	defer cleanup()
	testAddr := testServer.Addr().String()

	// Setup proxy
	config := socks5.Config{}
	proxyAddr, cancelProxy, wg := setupProxy(&testing.T{}, config)
	defer wg.Wait()
	defer cancelProxy()

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
