package auth

import (
	"testing"
)

// TestEnforcerExamples demonstrates the specific examples mentioned in the issue
func TestEnforcerExamples(t *testing.T) {
	enforcer, err := NewEnforcer()
	if err != nil {
		t.Fatalf("Failed to create enforcer: %v", err)
	}

	// Example from the issue: "user, /UserService/CreateUser" should return false
	t.Run("user cannot create user - should return false", func(t *testing.T) {
		allowed, err := CheckPermission(enforcer, "user", "/UserService/CreateUser")
		if err != nil {
			t.Errorf("CheckPermission error: %v", err)
			return
		}
		if allowed {
			t.Error("Expected false permission for user role on /UserService/CreateUser, got true")
		} else {
			t.Log("✓ Correctly denied: user role cannot access /UserService/CreateUser")
		}
	})

	// Verify that admin can create user
	t.Run("admin can create user - should return true", func(t *testing.T) {
		allowed, err := CheckPermission(enforcer, "admin", "/UserService/CreateUser")
		if err != nil {
			t.Errorf("CheckPermission error: %v", err)
			return
		}
		if !allowed {
			t.Error("Expected true permission for admin role on /UserService/CreateUser, got false")
		} else {
			t.Log("✓ Correctly allowed: admin role can access /UserService/CreateUser")
		}
	})

	// Additional verification for user role on allowed methods
	t.Run("user can get current user - should return true", func(t *testing.T) {
		allowed, err := CheckPermission(enforcer, "user", "/UserService/GetCurrentUser")
		if err != nil {
			t.Errorf("CheckPermission error: %v", err)
			return
		}
		if !allowed {
			t.Error(
				"Expected true permission for user role on /UserService/GetCurrentUser, got false",
			)
		} else {
			t.Log("✓ Correctly allowed: user role can access /UserService/GetCurrentUser")
		}
	})
}
