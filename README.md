# SOCKS5 Proxy Server

A high-performance SOCKS5 proxy server implementation in Go that follows best practices and RFC 1928 specification.

## Features

- **SOCKS5 Protocol Compliance**: Full implementation of RFC 1928 and RFC 1929
- **Authentication**: Supports no-authentication (0x00) and username/password (0x02) methods
- **IPv4, IPv6, and Domain Name Resolution**: Handles all SOCKS5 address types
- **CONNECT Command Support**: Establishes TCP connections to target hosts
- **Concurrent Connections**: Configurable connection limits to prevent resource exhaustion
- **IP Filtering**: Advanced whitelist/blacklist filtering with CIDR support
- **Graceful Shutdown**: Proper cleanup and context-based cancellation
- **Comprehensive Logging**: Structured logging for monitoring and debugging
- **Enterprise Security**: Multi-layer protection (limits + IP filtering + auth)
- **Configurable**: Multiple configuration sources with clear priority order

## Requirements

- Go 1.19 or later
- Linux/macOS/Windows

## Installation

```bash
go build -o socks5-proxy cmd/socks5-proxy/main.go
```

## Usage

The proxy server uses the modern Cobra CLI framework for powerful command-line parsing.

```bash
# Run on default port 1080
./socks5-proxy

# Run on custom port
./socks5-proxy --addr=:8080

# Run with authentication
./socks5-proxy --username=myuser --password=mypass

# Show help
./socks5-proxy --help
```

### Command Line Options

- `--addr`: Address to listen on (default ":1080")
- `--username`: Username for authentication (optional)
- `--password`: Password for authentication (optional)

**Authentication Requirements:** Both username and password must be provided together, or neither for no-authentication mode.

### Configuration Management

The proxy supports multiple configuration sources with clear priority order:

1. **Command-line flags** (highest priority - override everything else)
2. **Configuration files** (--config flag - YAML or JSON format)
3. **Environment variables** (lowest priority - defaults)

#### Configuration Sources

- **YAML Configuration:**
```yaml
addr: ":1080"
username: "testuser"
password: "testpass"
log_level: "info"
log_format: "text"
timeout: 30
connection_limit: 100  # 0 = unlimited
allowed_ips:
  - "192.168.1.0/24"
  - "10.0.0.0/8"
allowed_ports:
  - 80
  - 443
  - 8080
dns_resolver: "8.8.8.8:53"
```

- **JSON Configuration:**
```json
{
  "addr": ":1080",
  "username": "testuser",
  "password": "testpass",
  "log_level": "info",
  "log_format": "text",
  "timeout": 30,
  "connection_limit": 100,
  "allowed_ips": ["192.168.1.0/24", "10.0.0.0/8"],
  "blocked_ips": ["192.168.1.100/32", "203.0.113.0/24"],
  "allowed_ports": [80, 443, 8080],
  "dns_resolver": "8.8.8.8:53"
}
```

- **Environment Variables:**
```bash
export SOCKS5_ADDR=":1080"
export SOCKS5_USERNAME="testuser"
export SOCKS5_PASSWORD="testpass"
export SOCKS5_LOG_LEVEL="info"
export SOCKS5_LOG_FORMAT="text"
export SOCKS5_CONNECTION_LIMIT="100"
export SOCKS5_TIMEOUT="30"
export SOCKS5_ALLOWED_IPS="192.168.1.0/24,10.0.0.0/8"
export SOCKS5_BLOCKED_IPS="192.168.1.100/32,203.0.113.0/24"
export SOCKS5_ALLOWED_PORTS="80,443,8080,8088-8090"
export SOCKS5_DNS_RESOLVER="8.8.8.8:53"
```

#### Commands

- **Generate config file:**
```bash
./socks5-proxy gen-config          # Generate config.yaml
./socks5-proxy gen-config myconfig.json  # Generate JSON config
```

- **Using config file:**
```bash
./socks5-proxy --config config.yaml
./socks5-proxy --config config.json
```

#### Configuration Priority

1. Command-line flags override config file and environment variables
2. Config file overrides environment variables
3. Environment variables provide defaults

### Help Output

```bash
$ ./socks5-proxy --help

A SOCKS5 proxy server written in Go that supports username/password authentication.
Complete documentation is available at https://github.com/techmagister/socks5proxy

Usage:
  socks5-proxy [flags]

Flags:
      --addr string       address to listen on (default ":1080")
  -h, --help              help for socks5-proxy
      --password string   password for authentication (optional)
      --username string   username for authentication (optional)
```

### Error Handling

The CLI provides clear error messages for invalid configurations:

```bash
$ ./socks5-proxy --username=test
Error: both username and password must be provided together, or neither for no authentication
```

## Protocol Implementation

This server implements the core SOCKS5 features:

1. **Handshake Negotiation**: Supports version 5 with no-authentication method
2. **Request Handling**: Processes CONNECT requests for TCP connections
3. **Address Resolution**: Handles IPv4, IPv6, and domain name destinations
4. **Bidirectional Forwarding**: Efficiently forwards data between client and destination

### Supported Commands

- **CONNECT (0x01)**: Establishes a TCP connection to the target host
- **BIND (0x02)**: Not implemented (returns command not supported)
- **UDP ASSOCIATE (0x03)**: Not implemented (returns command not supported)

### Supported Address Types

- **IPv4 (0x01)**: Direct IPv4 addresses
- **Domain Name (0x03)**: Hostnames with DNS resolution
- **IPv6 (0x04)**: IPv6 addresses

## Testing

Run the test suite:

```bash
go test -v
```

## Configuration

The server accepts configuration via command-line flags:

```go
type Config struct {
    Addr     string // Listen address (host:port)
    Username string // Username for authentication (optional)
    Password string // Password for authentication (optional)
}
```

## Architecture

The server follows modern Go practices with typed errors for enhanced error handling:

- **Server Struct**: Encapsulates configuration and state
- **Context-Based Cancellation**: Proper shutdown handling
- **Goroutine-Based Concurrency**: Handles multiple connections concurrently
- **Typed Errors**: Custom SOCKS5-specific error types for better error introspection
- **Resource Management**: Proper cleanup of connections

### Key Components

- `Server`: Main server struct with configuration
- `negotiate()`: Handles SOCKS5 handshake protocol with authentication selection
- `handleRequest()`: Processes client requests with protocol validation
- `handleConnect()`: Implements CONNECT command with data forwarding
- `readAddress()`: Parses SOCKS5 address formats with error handling
- `sendReply()`: Sends replies according to protocol specification

### Typed Errors

The implementation uses custom error types for better error handling and introspection:

```go
// Predefined SOCKS5 error instances
var (
    ErrAuthenticationFailed      // Invalid username/password
    ErrNoAcceptableMethods       // No negotiation methods accepted
    ErrUnsupportedVersion        // Wrong SOCKS protocol version
    ErrAddressTypeNotSupported   // Invalid address type
    ErrCommandNotSupported       // Unsupported SOCKS command
    // ... more errors
)
```

**Usage with Go 1.13+ error checking:**

```go
import "errors"

err := socks5.Server.ListenAndServe(ctx)
if errors.Is(err, socks5.ErrAuthenticationFailed) {
    // Handle authentication error specifically
} else if errors.Is(err, socks5.ErrNoAcceptableMethods) {
    // Handle negotiation failure
}

// Or unwrap for more details
var socks5Err *socks5.SOCKS5Error
if errors.As(err, &socks5Err) {
    fmt.Printf("Error code: 0x%02x, message: %s", socks5Err.Code, socks5Err.Message)
}
```

This enables calling code to handle different error conditions appropriately while maintaining type safety.

### Error Wrapping and Chaining

```go
// The WrapError function allows wrapping underlying errors with SOCKS5 context
networkErr := fmt.Errorf("connection timeout")
socks5Err := socks5.WrapError(socks5.ErrConnectionRefused.Code, "failed to connect to target", networkErr)

// Result: "failed to connect to target: connection timeout"
fmt.Println(socks5Err.Error())

// Unwrap to access the original error
if origErr := socks5Err.Unwrap(); origErr != nil {
    // origErr is "connection timeout"
}
```

## Examples

### Basic Usage

```bash
# Start the proxy
./socks5-proxy

# In another terminal, test with curl
curl --socks5 localhost:1080 http://httpbin.org/get
```

### Using with Browser

Configure your browser to use SOCKS5 proxy at `localhost:1080`.

### Using with Applications

Most applications that support SOCKS5 proxies can be configured to use this server.

## Logging

The server uses the modern Go `slog` structured logging package (Go 1.21+) for comprehensive observability.

### Log Levels

- **INFO**: Server lifecycle events and successful connections
- **WARN**: Authentication failures and protocol errors
- **ERROR**: Connection acceptance errors

### Structured Log Examples

```bash
# Server startup
2025/11/24 14:47:56 INFO SOCKS5 proxy listening addr=127.0.0.1:45204

# Successful connection
2025/11/24 14:47:56 INFO Connected client=127.0.0.1:47089 destination=127.0.0.1:45114

# Authentication
2025/11/24 14:47:57 INFO Authentication successful user=testuser

# Security violation
2025/11/24 14:47:57 WARN No acceptable authentication methods
```

### Log Configuration

By default, uses JSON format to stderr. Configure slog globally for different outputs:

```go
import "log/slog"

// Text format with INFO level
slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
    Level: slog.LevelInfo,
})))
```

## Performance Considerations

- Uses efficient `io.Copy` for data forwarding
- Minimal memory allocation
- Context-based timeouts prevent hanging connections
- Concurrent handling scales with available CPU cores

## Security

The SOCKS5 proxy implements **enterprise-grade security** with multi-layer protection:

### Connection Limiting

Control concurrent connections to prevent resource exhaustion:

```yaml
connection_limit: 100  # Maximum 100 simultaneous connections (0 = unlimited)
```

```bash
export SOCKS5_CONNECTION_LIMIT=50
```

### IP Filtering

Advanced whitelist/blacklist filtering with CIDR support:

#### Allow-Only Mode (Whitelist)
```yaml
allowed_ips:
  - "192.168.1.0/24"  # Allow private network
  - "10.0.0.0/8"      # Allow internal IPs
```
All IPs not in the `allowed_ips` list are rejected.

#### Block Mode (Blacklist)
```yaml
blocked_ips:
  - "203.0.113.0/24"  # Block malicious subnet
  - "192.168.1.100/32" # Block specific IP
```
Explicitly blocked IPs are rejected, others are allowed.

#### Combined Security (Recommended)
```yaml
# Allow internal networks, block specific threats
allowed_ips:
  - "192.168.0.0/16"
  - "10.0.0.0/8"
blocked_ips:
  - "192.168.1.100/32"  # Even if in allowed range, block wins
  - "203.0.113.0/24"   # Block known malicious range
```

### Filtering Logic (Fail-Safe)

The server uses **fail-safe precedence** to maximize security:

```
1. BLOCKED IPs (deny) ← Highest precedence
2. ALLOWED IPs required (whitelist check)
3. No filters (allow all) ← Lowest precedence
```

**Behavior Matrix:**
| BlockedIPs | AllowedIPs | IP in both lists | Result |
|------------|------------|------------------|---------|
| ✅ Match | ❌ Empty | N/A | ❌ **Block** |
| ❌ Empty | ✅ Match | N/A | ✅ Allow |
| ❌ Empty | ❌ Empty | N/A | ✅ Allow |
| ✅ Match | ✅ Match | ❌ Block wins | ❌ **Block** |

### Authentication

Username/password authentication (RFC 1929):

```yaml
username: "proxyuser"
password: "securepass"
```

**Requirements:** Both fields must be set together or neither.

### Future Enhancements

- **TLS encryption**: Certificate-based secure connections
- **Advanced rate limiting**: Request-based throttling
- **Geo-blocking**: Country-based IP restrictions
- **Time-based access**: Schedule-based access control

### Production Recommendations

1. **Always set `connection_limit`** to prevent DoS attacks
2. **Use IP filtering** instead of relying on network firewalls alone
3. **Combine whitelisting with blacklisting** for defense in depth
4. **Enable authentication** for sensitive deployments
5. **Monitor logs** for security events

## Future Enhancements

Planned features (not yet implemented):

- UDP ASSOCIATE command support
- BIND command support
- Metrics and monitoring
- TLS support
- Advanced authentication methods
- Access control lists
- Rate limiting

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## License

This project is open source. Please see LICENSE file for details.

## References

- [RFC 1928: SOCKS Protocol Version 5](https://tools.ietf.org/html/rfc1928)
- [RFC 1929: Username/Password Authentication for SOCKS V5](https://tools.ietf.org/html/rfc1929)
