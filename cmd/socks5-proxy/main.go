package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/techmagister/socks5proxy/internal/socks5"
)

func main() {
	addr := flag.String("addr", ":1080", "address to listen on")
	username := flag.String("username", "", "username for authentication (optional)")
	password := flag.String("password", "", "password for authentication (optional)")
	flag.Parse()

	// Validate that both username and password are provided together
	if (*username != "" && *password == "") || (*username == "" && *password != "") {
		log.Fatal("Both username and password must be provided together, or neither for no authentication")
	}

	config := socks5.Config{
		Addr:     *addr,
		Username: *username,
		Password: *password,
	}

	server := socks5.NewServer(config)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		sig := <-sigChan
		log.Printf("Received signal %v, shutting down...", sig)
		cancel()
	}()

	if err := server.ListenAndServe(ctx); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
