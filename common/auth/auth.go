package auth

import (
	"context"
)

// AuthResult represents the result of an authentication attempt
type AuthResult struct {
	OK     bool
	UserID string
}

// Authenticator defines the interface for authentication services
type Authenticator interface {
	// Authenticate validates the given credentials
	// auth: the authentication credential (password or uuid)
	// addr: client IP address
	Authenticate(ctx context.Context, auth string, addr string) AuthResult
}
