package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/techmagister/socks5proxy/internal/config"
	"github.com/techmagister/socks5proxy/internal/socks5"
)

var configFile string
var addr string
var username string
var password string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "socks5-proxy",
	Short: "A high-performance SOCKS5 proxy server implementation",
	Long: `A SOCKS5 proxy server written in Go that supports username/password authentication and advanced configuration.

Configuration can be provided via:
- Command-line flags (highest priority)
- Configuration file (--config)
- Environment variables (lowest priority)

Complete documentation is available at https://github.com/techmagister/socks5proxy`,
	RunE: runServer,
}

// genConfigCmd generates a default configuration file
var genConfigCmd = &cobra.Command{
	Use:   "gen-config",
	Short: "Generate a default configuration file",
	Long:  `Create a default configuration file with all available options.`,
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		filename := "config.yaml"
		if len(args) > 0 {
			filename = args[0]
		}

		cfg := config.DefaultConfig()
		if err := cfg.SaveToFile(filename); err != nil {
			return fmt.Errorf("failed to save config file: %w", err)
		}

		fmt.Printf("Generated default configuration file: %s\n", filename)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(genConfigCmd)

	rootCmd.PersistentFlags().StringVar(&configFile, "config", "", "configuration file (YAML or JSON)")
	rootCmd.PersistentFlags().StringVar(&addr, "addr", "", "address to listen on")
	rootCmd.PersistentFlags().StringVar(&username, "username", "", "username for authentication")
	rootCmd.PersistentFlags().StringVar(&password, "password", "", "password for authentication")
}

func runServer(cmd *cobra.Command, args []string) error {
	// Load configuration based on priority order: flags > config file > env vars
	cfg, err := loadConfiguration()
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// Apply command-line overrides
	if addr != "" {
		cfg.Addr = addr
	}
	if username != "" {
		cfg.Username = username
	}
	if password != "" {
		cfg.Password = password
	}

	// Final validation
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	// Configure logging
	if err := configureLogging(cfg); err != nil {
		return fmt.Errorf("failed to configure logging: %w", err)
	}

	slog.Info("Starting SOCKS5 proxy server", "config", cfg.String())

	server := socks5.NewServer(socks5.Config{
		Addr:     cfg.GetAddress(),
		Username: cfg.Username,
		Password: cfg.Password,
	})

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		sig := <-sigChan
		slog.Info("Received signal, shutting down", "signal", sig.String())
		cancel()
	}()

	if err := server.ListenAndServe(ctx); err != nil {
		return fmt.Errorf("server failed: %w", err)
	}

	return nil
}

// loadConfiguration loads configuration from multiple sources with priority order
func loadConfiguration() (*config.Config, error) {
	var cfg *config.Config
	var err error

	if configFile != "" {
		// Load from file
		cfg, err = config.LoadFromFile(configFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load config file %s: %w", configFile, err)
		}
	} else {
		// Load from environment variables only
		cfg, err = config.LoadFromEnv()
		if err != nil {
			return nil, fmt.Errorf("failed to load environment config: %w", err)
		}
	}

	return cfg, nil
}

// configureLogging sets up the slog logger based on configuration
func configureLogging(cfg *config.Config) error {
	var level slog.Level
	switch strings.ToLower(cfg.LogLevel) {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	var handler slog.Handler
	opts := &slog.HandlerOptions{
		Level: level,
	}

	if strings.ToLower(cfg.LogFormat) == "text" {
		handler = slog.NewTextHandler(os.Stdout, opts)
	} else {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	}

	logger := slog.New(handler)
	slog.SetDefault(logger)

	return nil
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		// Error is already formatted by cobra
		os.Exit(1)
	}
}
