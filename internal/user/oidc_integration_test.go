package user

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"donetick.com/core/config"
	"donetick.com/core/internal/auth"
	"donetick.com/core/internal/auth/oidcmock"
	cRepo "donetick.com/core/internal/circle/repo"
	"donetick.com/core/internal/database"
	"donetick.com/core/internal/mfa"
	uRepo "donetick.com/core/internal/user/repo"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

// oidcTestHarness wires a real user.Handler (with in-memory DB, real JWT
// middleware, token service and identity provider) against a fake OIDC
// provider. It is the regression guard the OAuth flow was missing: it drives
// the real /auth/oauth2/callback and then immediately calls a protected route
// with the issued token — exactly the sequence that produced #254's
// "token contains an invalid number of segments" 401.
type oidcTestHarness struct {
	router   *gin.Engine
	provider *oidcmock.Provider
	userRepo *uRepo.UserRepository
	db       *gorm.DB
}

func newOIDCTestHarness(t *testing.T, claims oidcmock.Claims, singleCircle bool) *oidcTestHarness {
	t.Helper()
	gin.SetMode(gin.TestMode)

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := database.Migration(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	provider := oidcmock.New(claims, "mock-access-token")
	idpServer := httptest.NewServer(provider.Handler())
	t.Cleanup(idpServer.Close)

	cfg := &config.Config{
		Jwt: config.JwtConfig{
			// A strong secret so the develop-branch weak-secret guard is happy.
			Secret:      "test-secret-which-is-definitely-long-enough-32",
			SessionTime: time.Hour,
			MaxRefresh:  24 * time.Hour,
		},
		OAuth2Config: config.OAuth2Config{
			ClientID:     "donetick-test",
			ClientSecret: "donetick-test-secret",
			RedirectURL:  "http://localhost:5173/auth/oauth2",
			Scopes:       []string{"openid", "profile", "email"},
			AuthURL:      idpServer.URL + "/authorize",
			TokenURL:     idpServer.URL + "/token",
			UserInfoURL:  idpServer.URL + "/userinfo",
		},
		SingleCircleInstance: singleCircle,
	}

	userRepo := uRepo.NewUserRepository(db, cfg)
	circleRepo := cRepo.NewCircleRepository(db)
	mfaService := mfa.NewService(cfg)

	jwtAuth, err := auth.NewAuthMiddleware(cfg, userRepo, mfaService)
	if err != nil {
		t.Fatalf("jwt middleware: %v", err)
	}
	tokenService := auth.NewTokenService(userRepo, jwtAuth, cfg)
	idp := auth.NewIdentityProvider(cfg)

	h := &Handler{
		userRepo:             userRepo,
		circleRepo:           circleRepo,
		jwtAuth:              jwtAuth,
		tokenService:         tokenService,
		identityProvider:     idp,
		mfaService:           mfaService,
		oauth2Config:         cfg.OAuth2Config,
		singleCircleInstance: singleCircle,
	}

	r := gin.New()
	r.POST("/api/v1/auth/:provider/callback", h.thirdPartyAuthCallback)
	protected := r.Group("/api/v1/protected")
	protected.Use(jwtAuth.MiddlewareFunc())
	protected.GET("/me", func(c *gin.Context) {
		u := auth.MustCurrentUser(c)
		c.JSON(http.StatusOK, gin.H{"username": u.Username, "circleID": u.CircleID})
	})

	return &oidcTestHarness{router: r, provider: provider, userRepo: userRepo, db: db}
}

// loginViaOIDC drives the callback and returns the parsed token response.
func (h *oidcTestHarness) loginViaOIDC(t *testing.T) auth.TokenResponse {
	t.Helper()
	body := `{"code":"mock-auth-code","redirect_uri":"http://localhost:5173/auth/oauth2"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/oauth2/callback", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("oauth2 callback: got %d, body=%s", w.Code, w.Body.String())
	}
	var tr auth.TokenResponse
	if err := json.Unmarshal(w.Body.Bytes(), &tr); err != nil {
		t.Fatalf("decode token response: %v (body=%s)", err, w.Body.String())
	}
	return tr
}

// callProtected hits the protected route with the given bearer token.
func (h *oidcTestHarness) callProtected(token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/protected/me", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.router.ServeHTTP(w, req)
	return w
}

// TestOIDCCallbackIssuesUsableToken is the core #254/#393 regression guard:
// after a successful OIDC callback the issued session JWT must be well-formed
// AND immediately usable on a protected endpoint — no "invalid number of
// segments" 401, no refresh-and-retry required.
func TestOIDCCallbackIssuesUsableToken(t *testing.T) {
	h := newOIDCTestHarness(t, oidcmock.Claims{
		Sub:               "oidc-user-1",
		PreferredUsername: "alice",
		Name:              "Alice Example",
		Email:             "alice@example.com",
	}, false)

	tr := h.loginViaOIDC(t)

	// (a) The issued session JWT must be well-formed: header.payload.signature.
	if tr.Token == "" {
		t.Fatal("callback returned an empty session token")
	}
	if segs := strings.Split(tr.Token, "."); len(segs) != 3 {
		t.Fatalf("session token is not a well-formed JWT: %d segments (%q)", len(segs), tr.Token)
	}

	// (b) An immediately-following protected request with that token must
	// return 200 — this is precisely what failed in #254.
	w := h.callProtected(tr.Token)
	if w.Code != http.StatusOK {
		t.Fatalf("protected call with fresh OIDC token: got %d, body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"alice"`) {
		t.Fatalf("protected call did not resolve the OIDC user: %s", w.Body.String())
	}
}

// TestProtectedRejectsMalformedToken pins the backend behaviour that defines
// the #254 symptom: a malformed bearer value (what the frontend used to send
// when it persisted `undefined`) yields the exact 401 message.
func TestProtectedRejectsMalformedToken(t *testing.T) {
	h := newOIDCTestHarness(t, oidcmock.Claims{Sub: "x", Email: "x@example.com"}, false)
	for _, tok := range []string{"undefined", "null", "garbage"} {
		w := h.callProtected(tok)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("token %q: expected 401, got %d", tok, w.Code)
		}
		if !strings.Contains(w.Body.String(), "invalid number of segments") {
			t.Fatalf("token %q: expected 'invalid number of segments', got %s", tok, w.Body.String())
		}
	}
}

// TestOIDCProvisioningMapsDisplayName verifies #302/#645: the OIDC `name` and
// `preferred_username` claims are persisted on the provisioned user.
func TestOIDCProvisioningMapsDisplayName(t *testing.T) {
	h := newOIDCTestHarness(t, oidcmock.Claims{
		Sub:               "oidc-user-2",
		PreferredUsername: "bob",
		Name:              "Bob Builder",
		Email:             "bob@example.com",
	}, false)

	h.loginViaOIDC(t)

	u, err := h.userRepo.FindByEmail(context.Background(), "bob@example.com")
	if err != nil {
		t.Fatalf("find provisioned user: %v", err)
	}
	if u.DisplayName != "Bob Builder" {
		t.Errorf("display name: got %q, want %q", u.DisplayName, "Bob Builder")
	}
	if u.Username != "bob" {
		t.Errorf("username: got %q, want %q (preferred_username)", u.Username, "bob")
	}
}

// TestOIDCSingleCircleInstance verifies #690: with single_circle_instance on,
// every OIDC user joins the shared circle (ID 1) instead of getting their own.
func TestOIDCSingleCircleInstance(t *testing.T) {
	h := newOIDCTestHarness(t, oidcmock.Claims{
		Sub: "u1", PreferredUsername: "u1", Name: "User One", Email: "u1@example.com",
	}, true)

	tr1 := h.loginViaOIDC(t)
	w1 := h.callProtected(tr1.Token)
	if !strings.Contains(w1.Body.String(), `"circleID":1`) {
		t.Fatalf("first single-circle user not in circle 1: %s", w1.Body.String())
	}

	// Second, different OIDC user must also land in circle 1.
	h.provider.SetClaims(oidcmock.Claims{
		Sub: "u2", PreferredUsername: "u2", Name: "User Two", Email: "u2@example.com",
	})
	tr2 := h.loginViaOIDC(t)
	w2 := h.callProtected(tr2.Token)
	if !strings.Contains(w2.Body.String(), `"circleID":1`) {
		t.Fatalf("second single-circle user not in circle 1: %s", w2.Body.String())
	}
}
