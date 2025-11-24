package main

import (
	"errors"
	"fmt"
	"testing"

	"github.com/techmagister/socks5proxy/internal/socks5"
)

func TestTypedErrors(t *testing.T) {
	// Test that our custom errors work with errors.Is and errors.As

	// Test SOCKS5Error type checking
	err := socks5.ErrAuthenticationFailed
	if err.Error() != "authentication failed: invalid credentials" {
		t.Errorf("Expected authentication error message, got: %s", err.Error())
	}

	// Test that it's the correct type
	if !errors.Is(err, socks5.ErrAuthenticationFailed) {
		t.Error("Expected errors.Is to work with SOCKS5Error")
	}

	// Test with SOCKS5Error unwrapping
	var socks5Err *socks5.SOCKS5Error
	if !errors.As(err, &socks5Err) {
		t.Error("Expected errors.As to work with SOCKS5Error pointer")
	}

	if socks5Err.Code != 0x01 {
		t.Errorf("Expected auth failed code 0x01, got 0x%02x", socks5Err.Code)
	}

	// Test error wrapping functionality
	underlyingErr := fmt.Errorf("network unreachable")
	wrappedErr := socks5.WrapError(0x03, "connection failed", underlyingErr)

	// Test that wrapped error includes both messages
	expectedMsg := "connection failed: network unreachable"
	if wrappedErr.Error() != expectedMsg {
		t.Errorf("Expected wrapped error message %q, got %q", expectedMsg, wrappedErr.Error())
	}

	// Test unwrapping
	if underlying := wrappedErr.Unwrap(); underlying != underlyingErr {
		t.Error("Expected Unwrap to return the original error")
	}

	// Test that we can identify wrapped errors as the same type (same code)
	// Note: errors.Is checks for exact equality, so we check the As functionality
	var wrappedSocks5Err *socks5.SOCKS5Error
	if !errors.As(wrappedErr, &wrappedSocks5Err) {
		t.Error("Expected errors.As to work with wrapped SOCKS5Error")
	}

	if wrappedSocks5Err.Code != 0x03 {
		t.Errorf("Expected wrapped error code 0x03, got 0x%02x", wrappedSocks5Err.Code)
	}

	if wrappedSocks5Err.Message != "connection failed" {
		t.Errorf("Expected wrapped error message 'connection failed', got %q", wrappedSocks5Err.Message)
	}

	// Test that we can extract the SOCKS5Error from wrapped error
	if !errors.As(wrappedErr, &socks5Err) {
		t.Error("Expected errors.As to work with wrapped SOCKS5Error")
	}

	if socks5Err.Code != 0x03 {
		t.Errorf("Expected network unreachable code 0x03, got 0x%02x", socks5Err.Code)
	}
}
