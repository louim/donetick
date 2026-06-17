// Package oidcmock provides a tiny, self-contained fake OpenID Connect /
// OAuth2 provider for exercising Donetick's OIDC login flow without any
// network access or a real IdP.
//
// Donetick uses explicit OAuth2 endpoints (no discovery document), so a fake
// only needs three routes:
//
//	GET  /authorize   – redirects back to the app's redirect_uri with ?code&state
//	POST /token       – exchanges an auth code for an access token (RFC 6749)
//	GET  /userinfo    – returns the OIDC claims for the bearer access token
//
// The same Mux backs both the in-process integration tests (wrapped in an
// httptest.Server) and the standalone `cmd/mock-oidc` dev server used by
// docker-compose.dev.yml.
package oidcmock

import (
	"encoding/json"
	"net/http"
	"net/url"
	"sync"
)

// Claims is the set of OIDC claims the fake provider returns from /userinfo.
type Claims struct {
	Sub               string   `json:"sub"`
	PreferredUsername string   `json:"preferred_username,omitempty"`
	Name              string   `json:"name,omitempty"`
	Email             string   `json:"email,omitempty"`
	Picture           string   `json:"picture,omitempty"`
	Groups            []string `json:"groups,omitempty"`
}

// Provider is a fake OIDC provider. Its claims can be swapped at runtime so a
// single instance can simulate different users across logins.
type Provider struct {
	mu          sync.RWMutex
	claims      Claims
	accessToken string
}

// New returns a fake provider that serves the given claims and hands out the
// given opaque access token from /token.
func New(claims Claims, accessToken string) *Provider {
	if accessToken == "" {
		accessToken = "mock-access-token"
	}
	return &Provider{claims: claims, accessToken: accessToken}
}

// SetClaims swaps the claims returned by the next /userinfo call.
func (p *Provider) SetClaims(c Claims) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.claims = c
}

// AccessToken returns the opaque access token the provider issues.
func (p *Provider) AccessToken() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.accessToken
}

// Handler returns an http.Handler implementing the three OAuth2 routes.
func (p *Provider) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", p.handleAuthorize)
	mux.HandleFunc("/token", p.handleToken)
	mux.HandleFunc("/userinfo", p.handleUserinfo)
	return mux
}

// handleAuthorize emulates the IdP login page: it immediately redirects back
// to the supplied redirect_uri with a canned authorization code, echoing the
// state so the app's CSRF check passes.
func (p *Provider) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	redirectURI := q.Get("redirect_uri")
	state := q.Get("state")
	if redirectURI == "" {
		http.Error(w, "missing redirect_uri", http.StatusBadRequest)
		return
	}
	u, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}
	rq := u.Query()
	rq.Set("code", "mock-auth-code")
	if state != "" {
		rq.Set("state", state)
	}
	u.RawQuery = rq.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// handleToken implements the RFC 6749 token endpoint. It accepts any code and
// returns a standard JSON token response that golang.org/x/oauth2 understands.
func (p *Provider) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if r.PostForm.Get("code") == "" {
		// Mirror a real provider rejecting a missing/blank code.
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": p.AccessToken(),
		"token_type":   "Bearer",
		"expires_in":   3600,
	})
}

// handleUserinfo returns the configured claims to any bearer-authenticated
// request. The bearer token is not strictly validated — that's the IdP's job,
// not something the fake needs to enforce for these tests.
func (p *Provider) handleUserinfo(w http.ResponseWriter, r *http.Request) {
	p.mu.RLock()
	claims := p.claims
	p.mu.RUnlock()
	writeJSON(w, http.StatusOK, claims)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
