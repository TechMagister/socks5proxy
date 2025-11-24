package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/techmagister/socks5proxy/internal/socks5"
)

var addr string
var username string
var password string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "socks5-proxy",
	Short: "A high-performance SOCKS5 proxy server implementation",
	Long: `A SOCKS5 proxy server written in Go that supports username/password authentication.
Complete documentation is available at https://github.com/techmagister/socks5proxy`,
	RunE: runServer,
}

func init() {
	rootCmd.PersistentFlags().StringVar(&addr, "addr", ":1080", "address to listen on")
	rootCmd.PersistentFlags().StringVar(&username, "username", "", "username for authentication (optional)")
	rootCmd.PersistentFlags().StringVar(&password, "password", "", "password for authentication (optional)")
}

func runServer(cmd *cobra.Command, args []string) error {
	// Validate that both username and password are provided together
	if (username != "" && password == "") || (username == "" && password != "") {
		return fmt.Errorf("both username and password must be provided together, or neither for no authentication")
	}

	config := socks5.Config{
		Addr:     addr,
		Username: username,
		Password: password,
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

	log.Printf("Starting SOCKS5 proxy server on %s", addr)
	if err := server.ListenAndServe(ctx); err != nil {
		return fmt.Errorf("server failed: %w", err)
	}

	return nil
}

func main() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}
