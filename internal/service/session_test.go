package service

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/poly-workshop/auth-portal/configs"
	"github.com/redis/go-redis/v9"
)

func getTestConfig() configs.Config {
	return configs.Config{
		Session: configs.SessionConfig{
			ExpirationDuration: 24 * time.Hour,
		},
	}
}

func getTestConfigWithCustomDuration(duration time.Duration) configs.Config {
	return configs.Config{
		Session: configs.SessionConfig{
			ExpirationDuration: duration,
		},
	}
}

// TestSessionWithDifferentConfigurations tests if different session expiration configurations
// are correctly applied to the session TTL
func TestSessionWithDifferentConfigurations(t *testing.T) {
	// Use in-memory Redis client for testing
	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
		DB:   1, // Use a different DB for testing
	})

	// Skip test if Redis is not available
	ctx := context.Background()
	if err := rdb.Ping(ctx).Err(); err != nil {
		t.Skip("Redis not available, skipping test")
	}

	testCases := []struct {
		name     string
		duration time.Duration
	}{
		{
			name:     "1 hour session",
			duration: time.Hour,
		},
		{
			name:     "default 24 hours session",
			duration: 24 * time.Hour,
		},
		{
			name:     "48 hours session",
			duration: 48 * time.Hour,
		},
		{
			name:     "30 minutes session",
			duration: 30 * time.Minute,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create service with custom configuration
			cfg := getTestConfigWithCustomDuration(tc.duration)
			sessionService := NewSessionService(rdb, cfg)
			userID := uuid.New().String()

			// Create a session
			sessionID, err := sessionService.CreateSession(ctx, userID)
			if err != nil {
				t.Fatalf("Failed to create session: %v", err)
			}

			// Get session key
			sessionKey := "session:" + sessionID

			// Check initial TTL
			initialTTL, err := rdb.TTL(ctx, sessionKey).Result()
			if err != nil {
				t.Fatalf("Failed to get initial TTL: %v", err)
			}

			// Verify TTL is set correctly (allowing 1 second margin for test execution time)
			if initialTTL < tc.duration-time.Second || initialTTL > tc.duration {
				t.Errorf("Expected TTL around %v, got %v", tc.duration, initialTTL)
			}

			// Verify expiration time from service method
			expiresAt, err := sessionService.GetSessionExpirationTime(ctx, sessionID)
			if err != nil {
				t.Fatalf("Failed to get session expiration time: %v", err)
			}

			expectedExpiration := time.Now().Add(tc.duration)
			if expiresAt.Before(expectedExpiration.Add(-time.Second)) ||
				expiresAt.After(expectedExpiration.Add(time.Second)) {
				t.Errorf("Expected expiration around %v, got %v", expectedExpiration, expiresAt)
			}

			// Test refresh with the same duration
			err = sessionService.RefreshSession(ctx, sessionID)
			if err != nil {
				t.Fatalf("Failed to refresh session: %v", err)
			}

			// Check TTL after refresh
			refreshedTTL, err := rdb.TTL(ctx, sessionKey).Result()
			if err != nil {
				t.Fatalf("Failed to get refreshed TTL: %v", err)
			}

			// Verify refreshed TTL is set correctly
			if refreshedTTL < tc.duration-time.Second || refreshedTTL > tc.duration {
				t.Errorf("Expected refreshed TTL around %v, got %v", tc.duration, refreshedTTL)
			}

			// Clean up
			err = sessionService.DeleteSession(ctx, sessionID)
			if err != nil {
				t.Fatalf("Failed to delete session: %v", err)
			}
		})
	}
}

func TestSessionRefresh(t *testing.T) {
	// Use in-memory Redis client for testing
	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
		DB:   1, // Use a different DB for testing
	})

	// Skip test if Redis is not available
	ctx := context.Background()
	if err := rdb.Ping(ctx).Err(); err != nil {
		t.Skip("Redis not available, skipping test")
	}

	cfg := getTestConfig()
	sessionService := NewSessionService(rdb, cfg)
	userID := uuid.New().String()

	// Create a session
	sessionID, err := sessionService.CreateSession(ctx, userID)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Get session key
	sessionKey := "session:" + sessionID

	// Wait a bit to let some time pass
	time.Sleep(2 * time.Second)

	// Get TTL before refresh (should be less than initial due to time passing)
	ttlBeforeRefresh, err := rdb.TTL(ctx, sessionKey).Result()
	if err != nil {
		t.Fatalf("Failed to get TTL before refresh: %v", err)
	}

	// Refresh the session
	err = sessionService.RefreshSession(ctx, sessionID)
	if err != nil {
		t.Fatalf("Failed to refresh session: %v", err)
	}

	// Get TTL after refresh
	refreshedTTL, err := rdb.TTL(ctx, sessionKey).Result()
	if err != nil {
		t.Fatalf("Failed to get refreshed TTL: %v", err)
	}

	// The refreshed TTL should be approximately the configured duration
	expectedTTL := cfg.Session.ExpirationDuration
	if refreshedTTL < expectedTTL-time.Minute || refreshedTTL > expectedTTL {
		t.Errorf("Expected TTL around %v, got %v", expectedTTL, refreshedTTL)
	}

	// The refreshed TTL should be greater than the TTL before refresh
	if refreshedTTL <= ttlBeforeRefresh {
		t.Errorf(
			"Expected refreshed TTL (%v) to be greater than TTL before refresh (%v)",
			refreshedTTL,
			ttlBeforeRefresh,
		)
	}

	// Verify we can still get the user ID
	retrievedUserID, err := sessionService.GetUserIDFromSession(ctx, sessionID)
	if err != nil {
		t.Fatalf("Failed to get user ID from session: %v", err)
	}

	if *retrievedUserID != userID {
		t.Errorf("Expected user ID %s, got %s", userID, *retrievedUserID)
	}

	// Get session expiration time
	expiresAt, err := sessionService.GetSessionExpirationTime(ctx, sessionID)
	if err != nil {
		t.Fatalf("Failed to get session expiration time: %v", err)
	}

	// The expiration time should be approximately the configured duration from now
	expectedExpiration := time.Now().Add(cfg.Session.ExpirationDuration)
	if expiresAt.Before(expectedExpiration.Add(-time.Minute)) ||
		expiresAt.After(expectedExpiration.Add(time.Minute)) {
		t.Errorf("Expected expiration around %v, got %v", expectedExpiration, expiresAt)
	}

	// Clean up
	err = sessionService.DeleteSession(ctx, sessionID)
	if err != nil {
		t.Fatalf("Failed to delete session: %v", err)
	}
}

func TestGetUserIDFromSessionRefreshesSession(t *testing.T) {
	// Use in-memory Redis client for testing
	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
		DB:   1, // Use a different DB for testing
	})

	// Skip test if Redis is not available
	ctx := context.Background()
	if err := rdb.Ping(ctx).Err(); err != nil {
		t.Skip("Redis not available, skipping test")
	}

	cfg := getTestConfig()
	sessionService := NewSessionService(rdb, cfg)
	userID := uuid.New().String()

	// Create a session
	sessionID, err := sessionService.CreateSession(ctx, userID)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Get session key
	sessionKey := "session:" + sessionID

	// Wait a bit to let some time pass
	time.Sleep(2 * time.Second)

	// Get TTL before getting user ID
	ttlBeforeGet, err := rdb.TTL(ctx, sessionKey).Result()
	if err != nil {
		t.Fatalf("Failed to get TTL before get: %v", err)
	}

	// Get user ID from session (this should refresh the session)
	retrievedUserID, err := sessionService.GetUserIDFromSession(ctx, sessionID)
	if err != nil {
		t.Fatalf("Failed to get user ID from session: %v", err)
	}

	if *retrievedUserID != userID {
		t.Errorf("Expected user ID %s, got %s", userID, *retrievedUserID)
	}

	// Get TTL after GetUserIDFromSession call
	refreshedTTL, err := rdb.TTL(ctx, sessionKey).Result()
	if err != nil {
		t.Fatalf("Failed to get refreshed TTL: %v", err)
	}

	// The refreshed TTL should be greater than TTL before get due to automatic refresh
	if refreshedTTL <= ttlBeforeGet {
		t.Errorf(
			"Expected GetUserIDFromSession to refresh session: refreshed TTL (%v) should be greater than TTL before get (%v)",
			refreshedTTL,
			ttlBeforeGet,
		)
	}

	// Clean up
	err = sessionService.DeleteSession(ctx, sessionID)
	if err != nil {
		t.Fatalf("Failed to delete session: %v", err)
	}
}
