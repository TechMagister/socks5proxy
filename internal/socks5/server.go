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
)

// Config holds the server configuration
type Config struct {
	Addr string
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

	// Find no authentication method (0x00)
	var selectedMethod byte = 0xFF
	for _, method := range methods {
		if method == 0x00 { // No authentication
			selectedMethod = 0x00
			break
		}
	}

	if selectedMethod == 0xFF {
		selectedMethod = 0xFF // No acceptable methods
	}

	// Send response
	response := []byte{socksVersion, selectedMethod}
	if _, err := conn.Write(response); err != nil {
		return fmt.Errorf("failed to send method selection: %w", err)
	}

	if selectedMethod == 0xFF {
		return errors.New("no acceptable authentication methods")
	}

	return nil
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
