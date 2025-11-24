package socks5

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"
)

const (
	socksVersion = 5

	// SOCKS5 Commands
	connectCommand      = 1
	bindCommand         = 2
	udpAssociateCommand = 3

	// SOCKS5 Authentication Methods
	noAuthRequired      = 0
	userPassAuth        = 2
	noAcceptableMethods = 0xFF

	// SOCKS5 Address Types
	ipv4Address   = 1
	domainAddress = 3
	ipv6Address   = 4

	// SOCKS5 Reply Codes
	replySuccess                 = 0
	replyGeneralFailure          = 1
	replyConnectionNotAllowed    = 2
	replyNetworkUnreachable      = 3
	replyHostUnreachable         = 4
	replyConnectionRefused       = 5
	replyTTLExpired              = 6
	replyCommandNotSupported     = 7
	replyAddressTypeNotSupported = 8

	// Username/Password Authentication Codes
	authSuccess = 0
	authFailure = 1
)

// SOCKS5-specific errors for better error handling and introspection
type SOCKS5Error struct {
	Code    byte
	Message string
	Cause   error // Underlying error that caused this SOCKS5 error
}

func (e *SOCKS5Error) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Cause)
	}
	return e.Message
}

// WrapError creates a new SOCKS5Error that wraps an underlying error
func WrapError(code byte, message string, cause error) *SOCKS5Error {
	return &SOCKS5Error{
		Code:    code,
		Message: message,
		Cause:   cause,
	}
}

// Unwrap returns the underlying cause error
func (e *SOCKS5Error) Unwrap() error {
	return e.Cause
}

// Predefined SOCKS5 error instances
var (
	ErrNoAcceptableMethods = &SOCKS5Error{
		Code:    0xFF,
		Message: "no acceptable authentication methods",
	}

	ErrAuthenticationFailed = &SOCKS5Error{
		Code:    0x01,
		Message: "authentication failed: invalid credentials",
	}

	ErrUnsupportedVersion = &SOCKS5Error{
		Code:    0xFF,
		Message: "unsupported SOCKS version",
	}

	ErrNoMethodsProvided = &SOCKS5Error{
		Code:    0xFF,
		Message: "no authentication methods provided",
	}

	ErrCommandNotSupported = &SOCKS5Error{
		Code:    0x07,
		Message: "command not supported",
	}

	ErrAddressTypeNotSupported = &SOCKS5Error{
		Code:    0x08,
		Message: "address type not supported",
	}

	ErrUnsupportedAuthVersion = &SOCKS5Error{
		Code:    0x01,
		Message: "unsupported auth version",
	}

	ErrNetworkUnreachable = &SOCKS5Error{
		Code:    0x03,
		Message: "network unreachable",
	}

	ErrHostUnreachable = &SOCKS5Error{
		Code:    0x04,
		Message: "host unreachable",
	}

	ErrConnectionRefused = &SOCKS5Error{
		Code:    0x05,
		Message: "connection refused",
	}

	ErrTTLExpired = &SOCKS5Error{
		Code:    0x06,
		Message: "TTL expired",
	}

	ErrProtocolError = &SOCKS5Error{
		Code:    0x01,
		Message: "general SOCKS server failure",
	}
)

// Config holds the server configuration
type Config struct {
	Addr            string   // Listen address
	Username        string   // Username for authentication
	Password        string   // Password for authentication
	ConnectionLimit int      // Maximum concurrent connections (0 = unlimited)
	AllowedIPs      []string // List of allowed client IPs (CIDR notation)
	BlockedIPs      []string // List of blocked client IPs (CIDR notation)
}

// Server represents a SOCKS5 proxy server
type Server struct {
	config       Config
	connections  int64        // Current active connection count
	maxConnMutex sync.RWMutex // Protects connections counter
	connLimit    int64        // Maximum allowed connections (0 = unlimited)
}

// NewServer creates a new SOCKS5 server instance
func NewServer(config Config) *Server {
	return &Server{
		config:    config,
		connLimit: int64(config.ConnectionLimit),
	}
}

// ListenAndServe starts the SOCKS5 server and accepts connections
func (s *Server) ListenAndServe(ctx context.Context) error {
	listener, err := net.Listen("tcp", s.config.Addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", s.config.Addr, err)
	}
	defer listener.Close()

	slog.Info("SOCKS5 proxy listening", "addr", s.config.Addr)

	go func() {
		<-ctx.Done()
		slog.Info("Shutting down server")
		listener.Close()
	}()

	var wg sync.WaitGroup

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			slog.Error("Failed to accept connection", "error", err)
			continue
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			s.handleConnection(ctx, conn)
		}()
	}

	wg.Wait()
	return nil
}

// incrementConnections increments the active connection counter
func (s *Server) incrementConnections() bool {
	s.maxConnMutex.Lock()
	defer s.maxConnMutex.Unlock()

	// Check if we've reached the connection limit
	if s.connLimit > 0 && s.connections >= s.connLimit {
		return false // Limit reached
	}

	s.connections++
	slog.Debug("Connection count increased", "count", s.connections, "limit", s.connLimit)
	return true
}

// decrementConnections decrements the active connection counter
func (s *Server) decrementConnections() {
	s.maxConnMutex.Lock()
	defer s.maxConnMutex.Unlock()

	if s.connections > 0 {
		s.connections--
		slog.Debug("Connection count decreased", "count", s.connections)
	}
}

func (s *Server) handleConnection(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	slog.Debug("New connection", "remote_addr", conn.RemoteAddr().String())

	// Check connection limit before proceeding
	if !s.incrementConnections() {
		slog.Warn("Connection limit reached, rejecting connection", "limit", s.connLimit)
		return // Connection limit reached, silently close
	}
	defer s.decrementConnections()

	// Check IP filtering
	if !s.isClientAllowed(conn.RemoteAddr()) {
		slog.Warn("IP not allowed, rejecting connection", "remote_ip", conn.RemoteAddr().String())
		return // IP not allowed, silently close
	}

	if err := s.negotiate(conn); err != nil {
		slog.Warn("Handshake failed", "error", err)
		return
	}

	if err := s.handleRequest(ctx, conn); err != nil {
		slog.Warn("Request handling failed", "error", err)
		return
	}
}

func (s *Server) negotiate(conn net.Conn) error {
	// Read version and methods count
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return fmt.Errorf("failed to read handshake header: %w", err)
	}

	version := header[0]
	numMethods := header[1]

	if version != socksVersion {
		return ErrUnsupportedVersion
	}

	if numMethods == 0 {
		return ErrNoMethodsProvided
	}

	// Read methods
	methods := make([]byte, numMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return fmt.Errorf("failed to read methods: %w", err)
	}

	// Select authentication method
	selectedMethod := s.selectAuthMethod(methods)
	if selectedMethod == noAcceptableMethods {
		return ErrNoAcceptableMethods
	}

	// Send method selection response
	response := []byte{socksVersion, selectedMethod}
	if _, err := conn.Write(response); err != nil {
		return fmt.Errorf("failed to send method selection: %w", err)
	}

	// If username/password authentication was selected, perform authentication
	if selectedMethod == userPassAuth {
		if err := s.authenticate(conn); err != nil {
			slog.Warn("Authentication failed", "error", err)
			return fmt.Errorf("authentication failed: %w", err)
		}
	}

	return nil
}

// selectAuthMethod chooses the best authentication method from the client's offered methods
func (s *Server) selectAuthMethod(methods []byte) byte {
	// Check if authentication is required (username and password are configured)
	authRequired := s.config.Username != "" && s.config.Password != ""

	if authRequired {
		// When authentication is required, ONLY allow username/password auth
		for _, method := range methods {
			if method == userPassAuth {
				return userPassAuth
			}
		}
		// If username/password auth method not offered by client, reject connection
		return noAcceptableMethods
	} else {
		// When no authentication is configured, prefer no authentication (0x00)
		for _, method := range methods {
			if method == noAuthRequired {
				return noAuthRequired
			}
		}
		// If no-auth method not offered, reject connection
		return noAcceptableMethods
	}
}

// authenticate handles username/password authentication according to RFC 1929
func (s *Server) authenticate(conn net.Conn) error {
	// Username/password authentication sub-negotiation

	// Read auth version (should be 0x01 for username/password auth)
	authVersion := make([]byte, 1)
	if _, err := io.ReadFull(conn, authVersion); err != nil {
		return fmt.Errorf("failed to read auth version: %w", err)
	}

	if authVersion[0] != 0x01 {
		// Send failure response
		response := []byte{0x01, authFailure}
		conn.Write(response)
		return ErrUnsupportedAuthVersion
	}

	// Read username length
	userLenBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, userLenBuf); err != nil {
		return fmt.Errorf("failed to read username length: %w", err)
	}
	userLen := userLenBuf[0]

	// Read username
	username := make([]byte, userLen)
	if _, err := io.ReadFull(conn, username); err != nil {
		return fmt.Errorf("failed to read username: %w", err)
	}

	// Read password length
	passLenBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, passLenBuf); err != nil {
		return fmt.Errorf("failed to read password length: %w", err)
	}
	passLen := passLenBuf[0]

	// Read password
	password := make([]byte, passLen)
	if _, err := io.ReadFull(conn, password); err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}

	// Authenticate
	if string(username) == s.config.Username && string(password) == s.config.Password {
		// Send success response
		response := []byte{0x01, authSuccess}
		if _, err := conn.Write(response); err != nil {
			return fmt.Errorf("failed to send auth success: %w", err)
		}
		slog.Info("Authentication successful", "user", string(username))
		return nil
	} else {
		// Send failure response
		response := []byte{0x01, authFailure}
		conn.Write(response)
		return ErrAuthenticationFailed
	}
}

func (s *Server) handleRequest(ctx context.Context, conn net.Conn) error {
	// Read request header: version, command, reserved, address type
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return WrapError(replyGeneralFailure, "failed to read request header", err)
	}

	version := header[0]
	command := header[1]
	addressType := header[3]

	if version != socksVersion {
		return ErrUnsupportedVersion
	}

	// Read destination address and port
	destAddr, destPort, err := s.readAddress(conn, addressType)
	if err != nil {
		return s.sendReply(conn, replyAddressTypeNotSupported, net.IPv4zero, 0)
	}

	switch command {
	case connectCommand:
		return s.handleConnect(ctx, conn, destAddr, destPort)
	case bindCommand:
		return s.sendReplyError(conn, ErrCommandNotSupported)
	case udpAssociateCommand:
		return s.sendReplyError(conn, ErrCommandNotSupported)
	default:
		return s.sendReplyError(conn, ErrCommandNotSupported)
	}
}

func (s *Server) handleConnect(ctx context.Context, conn net.Conn, destAddr string, destPort int) error {
	// Establish connection to destination
	destConn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", destAddr, destPort), 30*time.Second)
	if err != nil {
		var replyCode byte
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			replyCode = replyTTLExpired
		} else {
			replyCode = replyHostUnreachable
		}
		return s.sendReply(conn, replyCode, net.IPv4zero, 0)
	}
	defer destConn.Close()

	// Get the bind address for the reply
	localAddr := destConn.LocalAddr().(*net.TCPAddr)

	// Send success reply
	if err := s.sendReply(conn, replySuccess, localAddr.IP, uint16(localAddr.Port)); err != nil {
		return fmt.Errorf("failed to send success reply: %w", err)
	}

	slog.Info("Connected",
		"client", conn.RemoteAddr().String(),
		"destination", fmt.Sprintf("%s:%d", destAddr, destPort))

	// Start forwarding data
	return s.forward(ctx, conn, destConn)
}

func (s *Server) readAddress(conn net.Conn, addressType byte) (string, int, error) {
	var destAddr string
	var destPort int

	switch addressType {
	case ipv4Address:
		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return "", 0, err
		}
		destAddr = net.IP(buf).String()

	case domainAddress:
		buf := make([]byte, 1)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return "", 0, err
		}
		domainLen := buf[0]

		domain := make([]byte, domainLen)
		if _, err := io.ReadFull(conn, domain); err != nil {
			return "", 0, err
		}
		destAddr = string(domain)

	case ipv6Address:
		buf := make([]byte, 16)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return "", 0, err
		}
		destAddr = net.IP(buf).String()

	default:
		return "", 0, ErrAddressTypeNotSupported
	}

	// Read port
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return "", 0, err
	}
	destPort = int(binary.BigEndian.Uint16(portBuf))

	return destAddr, destPort, nil
}

func (s *Server) sendReply(conn net.Conn, replyCode byte, bindIP net.IP, bindPort uint16) error {
	var addressType byte
	var address []byte

	if bindIP.To4() != nil {
		addressType = ipv4Address
		address = bindIP.To4()
	} else {
		addressType = ipv6Address
		address = bindIP.To16()
	}

	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, bindPort)

	reply := []byte{
		socksVersion,
		replyCode,
		0, // Reserved
		addressType,
	}
	reply = append(reply, address...)
	reply = append(reply, portBytes...)

	_, err := conn.Write(reply)
	return err
}

// sendReplyError sends a SOCKS5 reply based on a SOCKS5Error
func (s *Server) sendReplyError(conn net.Conn, socks5Err *SOCKS5Error) error {
	return s.sendReply(conn, socks5Err.Code, net.IPv4zero, 0)
}

// isClientAllowed checks if the given network address (IP:port) is allowed based on both BlockedIPs and AllowedIPs configuration
// Block rules take precedence (fail-safe approach)
func (s *Server) isClientAllowed(addr net.Addr) bool {
	// Extract IP address from the network address
	ip, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		slog.Warn("Failed to parse client IP address", "addr", addr.String(), "error", err)
		return false
	}

	clientIP := net.ParseIP(ip)
	if clientIP == nil {
		slog.Warn("Invalid client IP address", "ip", ip)
		return false
	}

	// First, check if IP is explicitly blocked (highest precedence)
	for _, cidr := range s.config.BlockedIPs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			slog.Warn("Invalid CIDR range in blocked IPs", "cidr", cidr, "error", err)
			continue
		}

		if network.Contains(clientIP) {
			slog.Debug("Client IP blocked", "ip", ip, "cidr", cidr)
			return false // Explicitly blocked
		}
	}

	// If no IP filtering is configured, allow all connections
	if len(s.config.AllowedIPs) == 0 && len(s.config.BlockedIPs) == 0 {
		return true
	}

	// If allowed IPs are configured, check if client IP is in the allowed list
	if len(s.config.AllowedIPs) > 0 {
		for _, cidr := range s.config.AllowedIPs {
			_, network, err := net.ParseCIDR(cidr)
			if err != nil {
				slog.Warn("Invalid CIDR range in allowed IPs", "cidr", cidr, "error", err)
				continue
			}

			if network.Contains(clientIP) {
				slog.Debug("Client IP allowed", "ip", ip, "cidr", cidr)
				return true
			}
		}

		// IP not in allowed list
		slog.Debug("Client IP denied", "ip", ip, "allowed_cidrs", s.config.AllowedIPs)
		return false
	}

	// No filtering restrictions apply
	slog.Debug("Client IP allowed (no filters)", "ip", ip)
	return true
}

func (s *Server) forward(ctx context.Context, conn1, conn2 net.Conn) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	errChan := make(chan error, 2)

	copyConn := func(dst, src net.Conn) {
		_, err := io.Copy(dst, src)
		errChan <- err
	}

	go copyConn(conn1, conn2)
	go copyConn(conn2, conn1)

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errChan:
		if err != io.EOF {
			return err
		}
	}

	return nil
}
