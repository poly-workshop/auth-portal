package utils

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/poly-workshop/auth-portal/internal/model"
)

func TestNewUserTokenWithExpiration(t *testing.T) {
	userID := uuid.New().String()
	role := model.UserRoleUser
	secret := "test-secret"
	customExpiration := time.Now().Add(2 * time.Hour)

	// Test the new function with custom expiration
	token, err := NewUserTokenWithExpiration(userID, role, secret, customExpiration)
	if err != nil {
		t.Fatalf("Failed to create user token with custom expiration: %v", err)
	}

	if token.Token == "" {
		t.Error("Expected token to be non-empty")
	}

	if token.ExpiresAt == nil {
		t.Error("Expected expires_at to be set")
	}

	// The token's expiration should match our custom expiration (within a few seconds)
	tokenExpiration := token.ExpiresAt.AsTime()
	if tokenExpiration.Before(customExpiration.Add(-5*time.Second)) ||
		tokenExpiration.After(customExpiration.Add(5*time.Second)) {
		t.Errorf("Expected token expiration around %v, got %v", customExpiration, tokenExpiration)
	}

	// Verify the token can be validated
	claims, err := ValidateUserToken(token.Token, secret)
	if err != nil {
		t.Fatalf("Failed to validate token: %v", err)
	}

	// Check the claims
	claimsUserID, ok := claims.MapClaims["user_id"].(string)
	if !ok {
		t.Error("Expected user_id in claims")
	}
	if claimsUserID != userID {
		t.Errorf("Expected user ID %s in claims, got %v", userID, claimsUserID)
	}

	// Check expiration in claims
	exp, err := claims.GetExpirationTime()
	if err != nil {
		t.Fatalf("Failed to get expiration time from claims: %v", err)
	}

	claimsExpiration := exp.Time
	if claimsExpiration.Before(customExpiration.Add(-5*time.Second)) ||
		claimsExpiration.After(customExpiration.Add(5*time.Second)) {
		t.Errorf("Expected claims expiration around %v, got %v", customExpiration, claimsExpiration)
	}
}

func TestNewUserTokenClaimsWithExpiration(t *testing.T) {
	userID := uuid.New().String()
	role := model.UserRoleAdmin
	customExpiration := time.Now().Add(3 * time.Hour)

	claims := NewUserTokenClaimsWithExpiration(userID, role, customExpiration)

	// Check user ID
	claimsUserID, ok := claims.MapClaims["user_id"].(string)
	if !ok {
		t.Error("Expected user_id in claims")
	}
	if claimsUserID != userID {
		t.Errorf("Expected user ID %s, got %s", userID, claimsUserID)
	}

	// Check role
	claimsRole, ok := claims.MapClaims["user_role"]
	if !ok {
		t.Error("Expected user_role in claims")
	}
	if claimsRole != role.ToPb() {
		t.Errorf("Expected role %v, got %v", role.ToPb(), claimsRole)
	}

	// Check expiration (as Unix timestamp)
	expUnix, ok := claims.MapClaims["exp"].(int64)
	if !ok {
		t.Error("Expected exp in claims")
	}

	claimsExpiration := time.Unix(expUnix, 0)
	if claimsExpiration.Before(customExpiration.Add(-5*time.Second)) ||
		claimsExpiration.After(customExpiration.Add(5*time.Second)) {
		t.Errorf("Expected expiration around %v, got %v", customExpiration, claimsExpiration)
	}
}

func TestBackwardsCompatibility(t *testing.T) {
	userID := uuid.New().String()
	role := model.UserRoleUser
	secret := "test-secret"

	// Test that the original function still works
	token, err := NewUserTokenWithExpiration(userID, role, secret, time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatalf("Failed to create user token: %v", err)
	}

	if token.Token == "" {
		t.Error("Expected token to be non-empty")
	}

	if token.ExpiresAt == nil {
		t.Error("Expected expires_at to be set")
	}

	// The token should expire in approximately 24 hours
	expectedExpiration := time.Now().Add(24 * time.Hour)
	tokenExpiration := token.ExpiresAt.AsTime()
	if tokenExpiration.Before(expectedExpiration.Add(-time.Minute)) ||
		tokenExpiration.After(expectedExpiration.Add(time.Minute)) {
		t.Errorf("Expected token expiration around %v, got %v", expectedExpiration, tokenExpiration)
	}

	// Verify the token can be validated
	claims, err := ValidateUserToken(token.Token, secret)
	if err != nil {
		t.Fatalf("Failed to validate token: %v", err)
	}

	// Check the claims
	claimsUserID, ok := claims.MapClaims["user_id"].(string)
	if !ok {
		t.Error("Expected user_id in claims")
	}
	if claimsUserID != userID {
		t.Errorf("Expected user ID %s in claims, got %v", userID, claimsUserID)
	}
}
