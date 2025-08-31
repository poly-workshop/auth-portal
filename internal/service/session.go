package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"time"

	"github.com/poly-workshop/auth-portal/configs"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type SessionService interface {
	CreateSession(ctx context.Context, userID string) (string, error)
	GetUserIDFromSession(ctx context.Context, sessionID string) (*string, error)
	RefreshSession(ctx context.Context, sessionID string) error
	GetSessionExpirationTime(ctx context.Context, sessionID string) (time.Time, error)
	DeleteSession(ctx context.Context, sessionID string) error
}

type sessionService struct {
	rdb redis.UniversalClient
	cfg configs.Config
}

func NewSessionService(rdb redis.UniversalClient, cfg configs.Config) SessionService {
	return &sessionService{
		rdb: rdb,
		cfg: cfg,
	}
}

// CreateSession creates a new login session and stores it in Redis
func (s *sessionService) CreateSession(ctx context.Context, userID string) (string, error) {
	// Generate session ID
	sessionBytes := make([]byte, 32)
	if _, err := rand.Read(sessionBytes); err != nil {
		slog.ErrorContext(ctx, "failed to generate session ID", "error", err, "user_id", userID)
		return "", status.Errorf(codes.Internal, "failed to generate session ID: %v", err)
	}
	sessionID := hex.EncodeToString(sessionBytes)

	// Store session in Redis with configured expiration
	sessionKey := fmt.Sprintf("session:%s", sessionID)
	err := s.rdb.Set(ctx, sessionKey, userID, s.cfg.Session.ExpirationDuration).
		Err()
	if err != nil {
		slog.ErrorContext(
			ctx,
			"failed to store session in redis",
			"error",
			err,
			"user_id",
			userID,
			"session_id",
			sessionID[:16],
		)
		return "", status.Errorf(codes.Internal, "failed to store session: %v", err)
	}

	slog.InfoContext(
		ctx,
		"session created successfully",
		"user_id",
		userID,
		"session_id",
		sessionID[:16],
		"expires_in_hours",
		24,
	)
	return sessionID, nil
}

// GetUserIDFromSession retrieves user ID from session and refreshes the session TTL
func (s *sessionService) GetUserIDFromSession(ctx context.Context, sessionID string) (*string, error) {
	sessionKey := fmt.Sprintf("session:%s", sessionID)
	userIDStr, err := s.rdb.Get(ctx, sessionKey).Result()
	if err != nil {
		slog.WarnContext(
			ctx,
			"session lookup failed",
			"error",
			"invalid or expired session",
			"session_id",
			sessionID[:min(16, len(sessionID))],
		)
		return nil, status.Errorf(codes.Unauthenticated, "invalid or expired session")
	}

	var userID string
	if _, err := fmt.Sscanf(userIDStr, "%s", &userID); err != nil {
		slog.ErrorContext(
			ctx,
			"invalid session data format",
			"error",
			err,
			"session_id",
			sessionID[:min(16, len(sessionID))],
		)
		return nil, status.Errorf(codes.Internal, "invalid session data")
	}

	// Automatically refresh session TTL when accessed
	if err := s.RefreshSession(ctx, sessionID); err != nil {
		// Log the error but don't fail the request - session is still valid
		slog.WarnContext(
			ctx,
			"session refresh failed but continuing",
			"error",
			err,
			"user_id",
			userID,
			"session_id",
			sessionID[:16],
		)
	} else {
		slog.DebugContext(ctx, "session refreshed successfully", "user_id", userID, "session_id", sessionID[:16])
	}

	return &userID, nil
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// RefreshSession extends the session TTL to configured expiration from now
func (s *sessionService) RefreshSession(ctx context.Context, sessionID string) error {
	sessionKey := fmt.Sprintf("session:%s", sessionID)
	return s.rdb.Expire(ctx, sessionKey, s.cfg.Session.ExpirationDuration).Err()
}

// GetSessionExpirationTime returns the expiration time of a session
func (s *sessionService) GetSessionExpirationTime(
	ctx context.Context,
	sessionID string,
) (time.Time, error) {
	sessionKey := fmt.Sprintf("session:%s", sessionID)
	ttl, err := s.rdb.TTL(ctx, sessionKey).Result()
	if err != nil {
		return time.Time{}, status.Errorf(codes.Internal, "failed to get session TTL: %v", err)
	}
	if ttl == -2 { // Key does not exist
		return time.Time{}, status.Errorf(codes.Unauthenticated, "session not found")
	}
	if ttl == -1 { // Key exists but has no expiration
		return time.Time{}, status.Errorf(codes.Internal, "session has no expiration")
	}
	return time.Now().Add(ttl), nil
}

// DeleteSession removes session from Redis
func (s *sessionService) DeleteSession(ctx context.Context, sessionID string) error {
	sessionKey := fmt.Sprintf("session:%s", sessionID)
	return s.rdb.Del(ctx, sessionKey).Err()
}
