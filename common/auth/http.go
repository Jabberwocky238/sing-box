package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/sagernet/sing/common/logger"
)

type httpAuthRequest struct {
	Auth      string `json:"auth"`
	Addr      string `json:"addr"`
	Timestamp int64  `json:"ts"`
}

type httpAuthResponse struct {
	OK bool   `json:"ok"`
	ID string `json:"id"`
}

type cachedAuthResult struct {
	id        string
	timestamp time.Time
}

// HTTPAuthenticator implements Authenticator using HTTP API
type HTTPAuthenticator struct {
	endpoint    string
	client      *http.Client
	logger      logger.ContextLogger
	cacheExpiry time.Duration

	cache map[string]cachedAuthResult
}

// NewHTTPAuthenticator creates a new HTTP-based authenticator
func NewHTTPAuthenticator(endpoint string, logger logger.ContextLogger, cacheExpiry time.Duration) *HTTPAuthenticator {
	return &HTTPAuthenticator{
		endpoint: endpoint,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
		logger:      logger,
		cacheExpiry: cacheExpiry,
		cache:       make(map[string]cachedAuthResult),
	}
}

// Authenticate validates credentials via HTTP API
func (a *HTTPAuthenticator) Authenticate(ctx context.Context, auth string, addr string) AuthResult {
	// Check cache first
	if a.cacheExpiry > 0 {
		if cached, found := a.cache[auth]; found {
			if time.Since(cached.timestamp) < a.cacheExpiry {
				a.logger.DebugContext(ctx, "auth cache hit: ", addr, " auth=", auth[:min(8, len(auth))], "...")
				return AuthResult{
					OK:     true,
					UserID: cached.id,
				}
			}
		}
	}

	reqBody := httpAuthRequest{
		Auth:      auth,
		Addr:      addr,
		Timestamp: time.Now().Unix(),
	}

	a.logger.DebugContext(ctx, "auth request: ", addr, " auth=", auth[:min(8, len(auth))], "...")

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		a.logger.ErrorContext(ctx, "marshal auth request: ", err)
		return AuthResult{OK: false}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint, bytes.NewReader(jsonData))
	if err != nil {
		a.logger.ErrorContext(ctx, "create auth request: ", err)
		return AuthResult{OK: false}
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		a.logger.ErrorContext(ctx, "auth API request failed: ", err)
		return AuthResult{OK: false}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		a.logger.ErrorContext(ctx, "auth API returned status: ", resp.StatusCode)
		return AuthResult{OK: false}
	}

	var authResp httpAuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		a.logger.ErrorContext(ctx, "decode auth API response: ", err)
		return AuthResult{OK: false}
	}

	if authResp.OK {
		a.logger.InfoContext(ctx, "auth success: ", addr, " user=", authResp.ID)
	} else {
		a.logger.WarnContext(ctx, "auth failed: ", addr, " auth=", auth[:min(8, len(auth))], "...")
	}

	return AuthResult{
		OK:     authResp.OK,
		UserID: authResp.ID,
	}
}
