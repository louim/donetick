package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"donetick.com/core/config"
	uModel "donetick.com/core/internal/user/model"
	uRepo "donetick.com/core/internal/user/repo"
	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/google/uuid"
)

// TokenService handles JWT token generation and refresh token management
type TokenService struct {
	userRepo           *uRepo.UserRepository
	jwtAuth            *jwt.GinJWTMiddleware
	sessionTime        time.Duration
	refreshTokenExpiry time.Duration
}

// tokenOpTimeout bounds a detached token operation.
const tokenOpTimeout = 10 * time.Second

// detachedTokenContext returns a context for a refresh-token operation that
// survives cancellation of the originating request.
//
// Login and refresh handlers pass c.Request.Context(); if the client
// disconnects or retries mid-operation, that context is canceled and the
// session lookup or write fails with "context canceled" — the user is either
// not logged in or, mid-rotation, logged out (#560). Once the server has
// committed to issuing/rotating tokens the operation must run to completion, so
// we detach from the request's cancellation (keeping its values for
// logging/tracing) and apply our own timeout to stay bounded.
func detachedTokenContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(parent), tokenOpTimeout)
}

// TokenResponse represents the response containing both access and refresh tokens
type TokenResponse struct {
	AccessToken        string    `json:"access_token"`
	RefreshToken       string    `json:"refresh_token"`
	AccessTokenExpiry  time.Time `json:"access_token_expiry"`
	RefreshTokenExpiry time.Time `json:"refresh_token_expiry"`
	TokenType          string    `json:"token_type"`

	// Legacy fields for backward compatibility
	Token  string    `json:"token"`  // Same as access_token
	Expire time.Time `json:"expire"` // Same as access_token_expiry
}

// RefreshRequest represents the request to refresh tokens
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// NewTokenService creates a new token service
func NewTokenService(userRepo *uRepo.UserRepository, jwtAuth *jwt.GinJWTMiddleware, cfg *config.Config) *TokenService {
	return &TokenService{
		userRepo:           userRepo,
		jwtAuth:            jwtAuth,
		sessionTime:        cfg.Jwt.SessionTime,
		refreshTokenExpiry: cfg.Jwt.MaxRefresh,
	}
}

// GenerateTokens generates both access and refresh tokens for a user
func (s *TokenService) GenerateTokens(ctx context.Context, user *uModel.UserDetails) (*TokenResponse, error) {
	// Generate access token using existing JWT middleware
	accessToken, accessExpiry, err := s.jwtAuth.TokenGenerator(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// Generate refresh token
	refreshToken, err := s.generateRefreshToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Create token family ID for rotation tracking
	familyID := uuid.New().String()

	// Hash refresh token for storage
	tokenHash := s.hashToken(refreshToken)

	// Calculate expiry times using config
	accessTokenExpiry := time.Now().UTC().Add(s.sessionTime)
	refreshTokenExpiry := time.Now().UTC().Add(s.refreshTokenExpiry)

	// Store refresh token in database
	userSession := &uModel.UserSession{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		TokenHash: tokenHash,
		FamilyID:  familyID,
		CreatedAt: time.Now().UTC(),
		ExpiresAt: refreshTokenExpiry,
	}

	writeCtx, cancel := detachedTokenContext(ctx)
	defer cancel()
	if err := s.userRepo.CreateUserSession(writeCtx, userSession); err != nil {
		return nil, fmt.Errorf("failed to store refresh token: %w", err)
	}

	return &TokenResponse{
		AccessToken:        accessToken,
		RefreshToken:       refreshToken,
		AccessTokenExpiry:  accessTokenExpiry,
		RefreshTokenExpiry: refreshTokenExpiry,
		TokenType:          "Bearer",
		// Legacy fields for backward compatibility
		Token:  accessToken,
		Expire: accessExpiry,
	}, nil
}

// RefreshTokens validates refresh token and generates new token pair
func (s *TokenService) RefreshTokens(ctx context.Context, refreshToken string) (*TokenResponse, error) {
	// Run the whole rotation on a context detached from the request: once we
	// start validating/rotating, a client disconnect must not abort us partway
	// and leave the user without a usable refresh token (#560).
	ctx, cancel := detachedTokenContext(ctx)
	defer cancel()

	// Hash the provided refresh token
	tokenHash := s.hashToken(refreshToken)

	// Get session from database
	session, err := s.userRepo.GetUserSessionByTokenHash(ctx, tokenHash)
	if err != nil {
		return nil, fmt.Errorf("invalid or expired refresh token")
	}

	// Check if token was already used (reuse detection)
	if session.UsedAt != nil {
		// Token reuse detected - revoke entire family
		_ = s.userRepo.RevokeSessionFamily(ctx, session.FamilyID)
		return nil, fmt.Errorf("token reuse detected - please login again")
	}

	// Get user details for new token generation
	userData, err := s.userRepo.GetUserByID(ctx, session.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Convert to UserDetails
	user := &uModel.UserDetails{
		User: *userData,
		// WebhookURL will be nil for refresh tokens - that's ok
	}

	// Generate new access token
	accessToken, accessExpiry, err := s.jwtAuth.TokenGenerator(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate new access token: %w", err)
	}

	// Generate new refresh token
	newRefreshToken, err := s.generateRefreshToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate new refresh token: %w", err)
	}

	// Calculate new expiry times using config
	accessTokenExpiry := time.Now().UTC().Add(s.sessionTime)
	refreshTokenExpiry := time.Now().UTC().Add(s.refreshTokenExpiry)

	// Create new session with same family ID
	newTokenHash := s.hashToken(newRefreshToken)
	newSession := &uModel.UserSession{
		ID:        uuid.New().String(),
		UserID:    session.UserID,
		TokenHash: newTokenHash,
		FamilyID:  session.FamilyID, // Keep same family ID for rotation tracking
		CreatedAt: time.Now().UTC(),
		ExpiresAt: refreshTokenExpiry,
	}

	// Persist the new session BEFORE burning the old token. If we marked the
	// old token used first and the new write then failed (transient DB error),
	// the user would be left with no valid refresh token and get logged out.
	// Storing the new session first means a failure here leaves the old token
	// usable for a retry.
	if err := s.userRepo.CreateUserSession(ctx, newSession); err != nil {
		return nil, fmt.Errorf("failed to store new refresh token: %w", err)
	}

	// New session is durable; now invalidate the old token to complete rotation.
	if err := s.userRepo.MarkSessionUsed(ctx, session.ID); err != nil {
		return nil, fmt.Errorf("failed to mark token as used: %w", err)
	}

	return &TokenResponse{
		AccessToken:        accessToken,
		RefreshToken:       newRefreshToken,
		AccessTokenExpiry:  accessTokenExpiry,
		RefreshTokenExpiry: refreshTokenExpiry,
		TokenType:          "Bearer",
		// Legacy fields for backward compatibility
		Token:  accessToken,
		Expire: accessExpiry,
	}, nil
}

// RevokeToken revokes a specific refresh token
func (s *TokenService) RevokeToken(ctx context.Context, refreshToken string) error {
	tokenHash := s.hashToken(refreshToken)
	session, err := s.userRepo.GetUserSessionByTokenHash(ctx, tokenHash)
	if err != nil {
		return nil // Token not found - already invalid
	}
	return s.userRepo.RevokeSession(ctx, session.ID)
}

// RevokeAllUserTokens revokes all tokens for a user (logout from all devices)
func (s *TokenService) RevokeAllUserTokens(ctx context.Context, userID int) error {
	return s.userRepo.RevokeAllUserSessions(ctx, userID)
}

// RefreshTokenExpiry returns the configured refresh token expiry duration
func (s *TokenService) RefreshTokenExpiry() time.Duration {
	return s.refreshTokenExpiry
}

// generateRefreshToken creates a cryptographically secure random token
func (s *TokenService) generateRefreshToken() (string, error) {
	bytes := make([]byte, 32) // 256-bit token
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// hashToken creates a SHA-256 hash of the token for database storage
func (s *TokenService) hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}
