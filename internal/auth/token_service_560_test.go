package auth

import (
	"context"
	"testing"
	"time"

	"donetick.com/core/config"
	"donetick.com/core/internal/database"
	"donetick.com/core/internal/mfa"
	uModel "donetick.com/core/internal/user/model"
	uRepo "donetick.com/core/internal/user/repo"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func newTokenServiceTest(t *testing.T) (*TokenService, *uRepo.UserRepository, *uModel.UserDetails) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := database.Migration(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	cfg := &config.Config{Jwt: config.JwtConfig{
		Secret:      "test-secret-which-is-definitely-long-enough-32",
		SessionTime: time.Hour,
		MaxRefresh:  24 * time.Hour,
	}}
	userRepo := uRepo.NewUserRepository(db, cfg)
	jwtAuth, err := NewAuthMiddleware(cfg, userRepo, mfa.NewService(cfg))
	if err != nil {
		t.Fatalf("jwt middleware: %v", err)
	}
	ts := NewTokenService(userRepo, jwtAuth, cfg)

	u, err := userRepo.CreateUser(context.Background(), &uModel.User{
		Username: "alice", Email: "alice@example.com", DisplayName: "Alice",
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	return ts, userRepo, &uModel.UserDetails{User: *u}
}

func canceledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

// TestGenerateTokensSurvivesCanceledRequest pins the core of #560: the refresh
// token must be persisted even when the originating request's context is
// already canceled (client disconnected / retried). On the old code the write
// rode that context and failed with "context canceled".
func TestGenerateTokensSurvivesCanceledRequest(t *testing.T) {
	ts, userRepo, user := newTokenServiceTest(t)

	tr, err := ts.GenerateTokens(canceledContext(), user)
	if err != nil {
		t.Fatalf("GenerateTokens with canceled request context failed: %v", err)
	}
	if tr.RefreshToken == "" {
		t.Fatal("no refresh token issued")
	}
	// The session must actually be in the DB, so a later refresh can find it.
	if _, err := userRepo.GetUserSessionByTokenHash(context.Background(), ts.hashToken(tr.RefreshToken)); err != nil {
		t.Fatalf("refresh token was not persisted: %v", err)
	}
}

// TestRefreshTokensSurvivesCancelAndRotatesSafely verifies that refresh also
// survives a canceled request, and that rotation is safe: the old token is
// only invalidated after the new one is durable, and the new token works.
func TestRefreshTokensSurvivesCancelAndRotatesSafely(t *testing.T) {
	ts, _, user := newTokenServiceTest(t)

	first, err := ts.GenerateTokens(context.Background(), user)
	if err != nil {
		t.Fatalf("seed GenerateTokens: %v", err)
	}

	// Refresh under a canceled request context — must still succeed.
	rotated, err := ts.RefreshTokens(canceledContext(), first.RefreshToken)
	if err != nil {
		t.Fatalf("RefreshTokens with canceled request context failed: %v", err)
	}
	if rotated.RefreshToken == first.RefreshToken {
		t.Fatal("refresh token was not rotated")
	}

	// The rotated token must be usable (check this before exercising reuse,
	// which intentionally revokes the whole token family).
	if _, err := ts.RefreshTokens(context.Background(), rotated.RefreshToken); err != nil {
		t.Fatalf("rotated refresh token did not work: %v", err)
	}

	// The original token was burned during rotation: reusing it must be
	// rejected (reuse detection).
	if _, err := ts.RefreshTokens(context.Background(), first.RefreshToken); err == nil {
		t.Fatal("expected the old refresh token to be rejected after rotation")
	}
}
