// Package auth implements external (HTTP API) user authentication for inbounds.
package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/sagernet/sing/common/logger"
)

type httpAuthRequest struct {
	Auth string `json:"auth"`
	Addr string `json:"addr"`
	// kept as "tx" for compatibility with the enzyme auth endpoint
	Timestamp int64 `json:"tx"`
}

type httpAuthResponse struct {
	OK bool   `json:"ok"`
	ID string `json:"id"`
}

type cacheEntry struct {
	user    string
	expires time.Time
}

// HTTPAuthenticator validates credentials by POSTing them to an HTTP API that
// answers {"ok": bool, "id": "<user>"}. Successful results may be cached.
type HTTPAuthenticator struct {
	endpoint string
	client   *http.Client
	logger   logger.ContextLogger
	cacheTTL time.Duration

	access sync.Mutex
	cache  map[string]cacheEntry
}

func NewHTTPAuthenticator(endpoint string, logger logger.ContextLogger, cacheTTL time.Duration) *HTTPAuthenticator {
	return &HTTPAuthenticator{
		endpoint: endpoint,
		client:   &http.Client{Timeout: 5 * time.Second},
		logger:   logger,
		cacheTTL: cacheTTL,
		cache:    make(map[string]cacheEntry),
	}
}

func maskCredential(credential string) string {
	return credential[:min(8, len(credential))] + "..."
}

// Authenticate returns the user id for the credential, or ok=false.
func (a *HTTPAuthenticator) Authenticate(ctx context.Context, credential string, addr string) (user string, ok bool) {
	if a.cacheTTL > 0 {
		a.access.Lock()
		entry, loaded := a.cache[credential]
		if loaded && time.Now().After(entry.expires) {
			delete(a.cache, credential)
			loaded = false
		}
		a.access.Unlock()
		if loaded {
			return entry.user, true
		}
	}
	body, err := json.Marshal(httpAuthRequest{Auth: credential, Addr: addr, Timestamp: time.Now().Unix()})
	if err != nil {
		a.logger.ErrorContext(ctx, "marshal auth request: ", err)
		return "", false
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint, bytes.NewReader(body))
	if err != nil {
		a.logger.ErrorContext(ctx, "create auth request: ", err)
		return "", false
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := a.client.Do(request)
	if err != nil {
		a.logger.ErrorContext(ctx, "auth API request failed: ", err)
		return "", false
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		a.logger.WarnContext(ctx, "auth rejected (", response.StatusCode, "): ", addr, " auth=", maskCredential(credential))
		return "", false
	}
	var authResponse httpAuthResponse
	err = json.NewDecoder(response.Body).Decode(&authResponse)
	if err != nil {
		a.logger.ErrorContext(ctx, "decode auth API response: ", err)
		return "", false
	}
	if !authResponse.OK || authResponse.ID == "" {
		a.logger.WarnContext(ctx, "auth failed: ", addr, " auth=", maskCredential(credential))
		return "", false
	}
	a.logger.InfoContext(ctx, "auth success: ", addr, " user=", authResponse.ID)
	if a.cacheTTL > 0 {
		a.access.Lock()
		a.cache[credential] = cacheEntry{user: authResponse.ID, expires: time.Now().Add(a.cacheTTL)}
		a.access.Unlock()
	}
	return authResponse.ID, true
}

// Invalidate drops cached credentials of user so the next connection re-checks the API.
func (a *HTTPAuthenticator) Invalidate(user string) {
	a.access.Lock()
	defer a.access.Unlock()
	for credential, entry := range a.cache {
		if entry.user == user {
			delete(a.cache, credential)
		}
	}
}
