package auth

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"donetick.com/core/config"
	"golang.org/x/oauth2"
)

// oauth2HTTPTimeout bounds OIDC token-exchange and userinfo calls so a stuck
// IdP can never hang a login request indefinitely.
const oauth2HTTPTimeout = 30 * time.Second

// oauth2HTTPClient returns the HTTP client used for all outbound OIDC calls
// (token exchange, userinfo, profile-picture validation).
//
// HTTP/2 is disabled and a hard timeout is enforced: several IdPs fronted by
// Cloudflare leave Go's default HTTP/2 client hanging on the token POST while
// a plain HTTP/1.1 request (e.g. `wget`) completes instantly (#671). Forcing
// HTTP/1.1 plus a timeout makes the exchange reliable and bounded.
func oauth2HTTPClient() *http.Client {
	return oauth2HTTPClientWithTimeout(oauth2HTTPTimeout)
}

func oauth2HTTPClientWithTimeout(timeout time.Duration) *http.Client {
	transport := &http.Transport{
		Proxy:             http.ProxyFromEnvironment,
		ForceAttemptHTTP2: false,
		// A non-nil (but empty) TLSNextProto map disables the automatic HTTP/2
		// upgrade, pinning connections to HTTP/1.1.
		TLSNextProto:          map[string]func(authority string, c *tls.Conn) http.RoundTripper{},
		MaxIdleConns:          10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	return &http.Client{Timeout: timeout, Transport: transport}
}

type IdentityProviderUserInfo struct {
	Identifier  string
	Username    string
	DisplayName string
	Email       string
	Picture     string
	Groups      []string
}

type IdentityProvider struct {
	config    *config.OAuth2Config
	isEnabled bool
}

func NewIdentityProvider(cfg *config.Config) *IdentityProvider {
	if cfg.OAuth2Config.ClientID == "" || cfg.OAuth2Config.ClientSecret == "" {
		return &IdentityProvider{isEnabled: false}
	}
	return &IdentityProvider{config: &cfg.OAuth2Config, isEnabled: true}
}

func (i *IdentityProvider) ExchangeToken(ctx context.Context, code string, redirectURL string) (string, error) {
	if !i.isEnabled {
		return "", errors.New("identity provider is not enabled")
	}

	if code == "" {
		return "", errors.New("authorization code is empty")
	}

	// Use provided redirect URL if given, otherwise fall back to config
	redirect := i.config.RedirectURL
	if len(redirectURL) > 0 && redirectURL != "" {
		redirect = redirectURL
	}

	conf := &oauth2.Config{
		ClientID:     i.config.ClientID,
		ClientSecret: i.config.ClientSecret,
		RedirectURL:  redirect,
		Scopes:       i.config.Scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  i.config.AuthURL,
			TokenURL: i.config.TokenURL,
		},
	}

	// Use an HTTP/1.1 client with a timeout for the token POST (#671).
	ctx = context.WithValue(ctx, oauth2.HTTPClient, oauth2HTTPClient())
	token, err := conf.Exchange(ctx, code)
	if err != nil {
		// Enhanced error handling for OAuth2 errors
		switch {
		case strings.Contains(err.Error(), "invalid_grant"):
			return "", errors.New("oauth2: invalid_grant - The authorization code is invalid, expired, revoked, or does not match the redirect URI")
		case strings.Contains(err.Error(), "invalid_client"):
			return "", errors.New("oauth2: invalid_client - Client authentication failed")
		case strings.Contains(err.Error(), "invalid_request"):
			return "", errors.New("oauth2: invalid_request - The request is missing a required parameter or is otherwise malformed")
		default:
			return "", err
		}
	}

	accessToken, ok := token.AccessToken, token.Valid()
	if !ok {
		return "", errors.New("access token not found or invalid")
	}

	return accessToken, nil
}

func (i *IdentityProvider) GetUserInfo(ctx context.Context, accessToken string) (*IdentityProviderUserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", i.config.UserInfoURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := oauth2HTTPClient().Do(req)
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var claims map[string]any
	err = json.Unmarshal(body, &claims)
	if err != nil {
		return nil, errors.New("failed to unmarshal claims")
	}
	userInfo := IdentityProviderUserInfo{}
	if val, ok := claims["sub"]; ok {
		userInfo.Identifier = val.(string)
	}
	if val, ok := claims["preferred_username"]; ok {
		userInfo.Username, _ = val.(string)
	}
	if val, ok := claims["name"]; ok {
		userInfo.DisplayName = val.(string)
	}
	if val, ok := claims["email"]; ok {
		userInfo.Email = val.(string)
	}
	if val, ok := claims["picture"]; ok {
		pictureURL := val.(string)
		isValid := isPictureURLValid(pictureURL)
		if isValid {
			userInfo.Picture = pictureURL
		}
	}
	if val, ok := claims["groups"]; ok {
		if groups, ok := val.([]interface{}); ok {
			for _, g := range groups {
				if s, ok := g.(string); ok {
					userInfo.Groups = append(userInfo.Groups, s)
				}
			}
		}
	}
	return &userInfo, nil
}

// Check if the provided URL is reachable and returns a valid image
func isPictureURLValid(url string) bool {
	// Bounded client so a slow/hanging image host can't stall OIDC login.
	resp, err := oauth2HTTPClient().Get(url)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false
	}

	contentType := resp.Header.Get("Content-Type")
	return strings.HasPrefix(contentType, "image/")
}
