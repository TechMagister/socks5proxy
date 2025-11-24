package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config represents the SOCKS5 proxy server configuration
type Config struct {
	// Server configuration
	Addr     string `json:"addr" yaml:"addr" env:"SOCKS5_ADDR"`
	ListenIP string `json:"listen_ip" yaml:"listen_ip" env:"SOCKS5_LISTEN_IP"`
	Port     int    `json:"port" yaml:"port" env:"SOCKS5_PORT"`

	// Authentication
	Username string `json:"username,omitempty" yaml:"username,omitempty" env:"SOCKS5_USERNAME"`
	Password string `json:"password,omitempty" yaml:"password,omitempty" env:"SOCKS5_PASSWORD"`

	// Logging
	LogLevel  string `json:"log_level" yaml:"log_level" env:"SOCKS5_LOG_LEVEL"`
	LogFormat string `json:"log_format" yaml:"log_format" env:"SOCKS5_LOG_FORMAT"`

	// Performance
	Timeout int `json:"timeout" yaml:"timeout" env:"SOCKS5_TIMEOUT"`

	// Connection limiting (0 = unlimited)
	ConnectionLimit int `json:"connection_limit" yaml:"connection_limit" env:"SOCKS5_CONNECTION_LIMIT"`

	// Advanced options
	AllowedIPs   []string `json:"allowed_ips,omitempty" yaml:"allowed_ips,omitempty"`
	BlockedIPs   []string `json:"blocked_ips,omitempty" yaml:"blocked_ips,omitempty"`
	AllowedPorts []int    `json:"allowed_ports,omitempty" yaml:"allowed_ports,omitempty"`
	DNSResolver  string   `json:"dns_resolver,omitempty" yaml:"dns_resolver,omitempty"`
}

// DefaultConfig returns a configuration with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		Addr:      ":1080",
		ListenIP:  "0.0.0.0",
		Port:      1080,
		LogLevel:  "info",
		LogFormat: "json",
		Timeout:   30,
	}
}

// LoadFromFile loads configuration from a file (supports YAML and JSON)
func LoadFromFile(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %w", filename, err)
	}

	config := DefaultConfig()

	// Try YAML first
	if err := yaml.Unmarshal(data, config); err != nil {
		// Try JSON if YAML fails
		if jsonErr := json.Unmarshal(data, config); jsonErr != nil {
			return nil, fmt.Errorf("failed to parse config file %s: yaml: %v, json: %v", filename, err, jsonErr)
		}
	}

	// Apply environment variable overrides
	if err := config.loadFromEnv(); err != nil {
		return nil, fmt.Errorf("failed to load environment variables: %w", err)
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return config, nil
}

// LoadFromEnv loads configuration from environment variables only
func LoadFromEnv() (*Config, error) {
	config := DefaultConfig()
	if err := config.loadFromEnv(); err != nil {
		return nil, err
	}
	return config, nil
}

// loadFromEnv reads configuration values from environment variables
func (c *Config) loadFromEnv() error {
	getEnvInt := func(key string, defaultValue int) (int, error) {
		if value := os.Getenv(key); value != "" {
			return strconv.Atoi(value)
		}
		return defaultValue, nil
	}

	// Apply environment variables
	if addr := os.Getenv("SOCKS5_ADDR"); addr != "" {
		c.Addr = addr
	}
	if listenIP := os.Getenv("SOCKS5_LISTEN_IP"); listenIP != "" {
		c.ListenIP = listenIP
	}
	if port, err := getEnvInt("SOCKS5_PORT", c.Port); err == nil {
		c.Port = port
	}

	if username := os.Getenv("SOCKS5_USERNAME"); username != "" {
		c.Username = username
	}
	if password := os.Getenv("SOCKS5_PASSWORD"); password != "" {
		c.Password = password
	}

	if logLevel := os.Getenv("SOCKS5_LOG_LEVEL"); logLevel != "" {
		c.LogLevel = logLevel
	}
	if logFormat := os.Getenv("SOCKS5_LOG_FORMAT"); logFormat != "" {
		c.LogFormat = logFormat
	}

	if timeout, err := getEnvInt("SOCKS5_TIMEOUT", c.Timeout); err == nil {
		c.Timeout = timeout
	}

	// Load connection limit
	if connLimit, err := getEnvInt("SOCKS5_CONNECTION_LIMIT", 0); err == nil {
		c.ConnectionLimit = connLimit
	}

	// Load slice values from environment
	if allowedIPs := os.Getenv("SOCKS5_ALLOWED_IPS"); allowedIPs != "" {
		c.AllowedIPs = strings.Split(allowedIPs, ",")
	}
	if blockedIPs := os.Getenv("SOCKS5_BLOCKED_IPS"); blockedIPs != "" {
		c.BlockedIPs = strings.Split(blockedIPs, ",")
	}

	// Parse port ranges (e.g., "80,443,8080-8090")
	if allowedPorts := os.Getenv("SOCKS5_ALLOWED_PORTS"); allowedPorts != "" {
		ports, err := parsePortRanges(allowedPorts)
		if err != nil {
			return fmt.Errorf("invalid SOCKS5_ALLOWED_PORTS: %w", err)
		}
		c.AllowedPorts = ports
	}

	if dnsResolver := os.Getenv("SOCKS5_DNS_RESOLVER"); dnsResolver != "" {
		c.DNSResolver = dnsResolver
	}

	return nil
}

// parsePortRanges parses port ranges like "80,443,8080-8090"
func parsePortRanges(portStr string) ([]int, error) {
	var ports []int
	ranges := strings.Split(portStr, ",")

	for _, r := range ranges {
		r = strings.TrimSpace(r)
		if strings.Contains(r, "-") {
			// Parse range like "8080-8090"
			parts := strings.Split(r, "-")
			if len(parts) != 2 {
				return nil, fmt.Errorf("invalid port range: %s", r)
			}
			start, err := strconv.Atoi(strings.TrimSpace(parts[0]))
			if err != nil {
				return nil, fmt.Errorf("invalid port range start: %s", parts[0])
			}
			end, err := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err != nil {
				return nil, fmt.Errorf("invalid port range end: %s", parts[1])
			}
			for port := start; port <= end; port++ {
				ports = append(ports, port)
			}
		} else {
			// Parse single port
			port, err := strconv.Atoi(r)
			if err != nil {
				return nil, fmt.Errorf("invalid port: %s", r)
			}
			ports = append(ports, port)
		}
	}

	return ports, nil
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("invalid port: %d (must be 1-65535)", c.Port)
	}

	if c.Timeout < 1 {
		return fmt.Errorf("timeout must be positive, got %d", c.Timeout)
	}

	// Validate log level
	validLogLevels := map[string]bool{
		"debug": true,
		"info":  true,
		"warn":  true,
		"error": true,
	}
	if !validLogLevels[c.LogLevel] {
		return fmt.Errorf("invalid log_level: %s (must be debug, info, warn, or error)", c.LogLevel)
	}

	// Validate log format
	validLogFormats := map[string]bool{
		"json": true,
		"text": true,
	}
	if !validLogFormats[c.LogFormat] {
		return fmt.Errorf("invalid log_format: %s (must be json or text)", c.LogFormat)
	}

	// Validate authentication: both username and password must be set together or neither
	if (c.Username == "" && c.Password != "") || (c.Username != "" && c.Password == "") {
		return fmt.Errorf("both username and password must be provided together, or neither for no authentication")
	}

	return nil
}

// GetAddress returns the full address to listen on
func (c *Config) GetAddress() string {
	if c.Addr != "" {
		return c.Addr
	}
	return fmt.Sprintf("%s:%d", c.ListenIP, c.Port)
}

// SaveToFile saves the current configuration to a file
func (c *Config) SaveToFile(filename string) error {
	var data []byte
	var err error

	if strings.HasSuffix(filename, ".yaml") || strings.HasSuffix(filename, ".yml") {
		data, err = yaml.Marshal(c)
		if err != nil {
			return fmt.Errorf("failed to marshal config to YAML: %w", err)
		}
	} else {
		data, err = json.MarshalIndent(c, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal config to JSON: %w", err)
		}
	}

	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// String returns a human-readable representation of the configuration
func (c *Config) String() string {
	return fmt.Sprintf("Config{Addr: %s, Auth: %s, LogLevel: %s, Timeout: %ds}",
		c.GetAddress(),
		c.getAuthStatus(),
		c.LogLevel,
		c.Timeout,
	)
}

func (c *Config) getAuthStatus() string {
	if c.Username != "" {
		return "enabled"
	}
	return "disabled"
}
