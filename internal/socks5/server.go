package socks5

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
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

// Config holds the server configuration
type Config struct {
	Addr     string
	Username string
	Password string
}

// Server represents a SOCKS5 proxy server
type Server struct {
	config Config
	logger *log.Logger
}

// NewServer creates a new SOCKS5 server instance
func NewServer(config Config) *Server {
	return &Server{
		config: config,
		logger: log.New(os.Stderr, "[SOCKS5] ", log.LstdFlags),
	}
}

// ListenAndServe starts the SOCKS5 server and accepts connections
func (s *Server) ListenAndServe(ctx context.Context) error {
	listener, err := net.Listen("tcp", s.config.Addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", s.config.Addr, err)
	}
	defer listener.Close()

	s.logger.Printf("SOCKS5 proxy listening on %s", s.config.Addr)

	go func() {
		<-ctx.Done()
		s.logger.Println("Shutting down server...")
		listener.Close()
	}()

	var wg sync.WaitGroup

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			s.logger.Printf("Failed to accept connection: %v", err)
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

func (s *Server) handleConnection(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	s.logger.Printf("New connection from %s", conn.RemoteAddr())

	if err := s.negotiate(conn); err != nil {
		s.logger.Printf("Handshake failed: %v", err)
		return
	}

	if err := s.handleRequest(ctx, conn); err != nil {
		s.logger.Printf("Request handling failed: %v", err)
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
		return fmt.Errorf("unsupported SOCKS version: %d", version)
	}

	if numMethods == 0 {
		return errors.New("no authentication methods provided")
	}

	// Read methods
	methods := make([]byte, numMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return fmt.Errorf("failed to read methods: %w", err)
	}

	// Select authentication method
	selectedMethod := s.selectAuthMethod(methods)
	if selectedMethod == noAcceptableMethods {
		return errors.New("no acceptable authentication methods")
	}

	// Send method selection response
	response := []byte{socksVersion, selectedMethod}
	if _, err := conn.Write(response); err != nil {
		return fmt.Errorf("failed to send method selection: %w", err)
	}

	// If username/password authentication was selected, perform authentication
	if selectedMethod == userPassAuth {
		if err := s.authenticate(conn); err != nil {
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
		return errors.New("unsupported auth version")
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
		s.logger.Printf("Authentication successful for user: %s", string(username))
		return nil
	} else {
		// Send failure response
		response := []byte{0x01, authFailure}
		conn.Write(response)
		return errors.New("authentication failed: invalid credentials")
	}
}

func (s *Server) handleRequest(ctx context.Context, conn net.Conn) error {
	// Read request header: version, command, reserved, address type
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return fmt.Errorf("failed to read request header: %w", err)
	}

	version := header[0]
	command := header[1]
	addressType := header[3]

	if version != socksVersion {
		return s.sendReply(conn, replyGeneralFailure, net.IPv4zero, 0)
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
		return s.sendReply(conn, replyCommandNotSupported, net.IPv4zero, 0)
	case udpAssociateCommand:
		return s.sendReply(conn, replyCommandNotSupported, net.IPv4zero, 0)
	default:
		return s.sendReply(conn, replyCommandNotSupported, net.IPv4zero, 0)
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

	s.logger.Printf("Connected %s -> %s:%d", conn.RemoteAddr(), destAddr, destPort)

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
		return "", 0, fmt.Errorf("unsupported address type: %d", addressType)
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
