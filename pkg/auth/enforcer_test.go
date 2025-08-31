package auth

import (
	"testing"

	user_v1_pb "github.com/poly-workshop/auth-portal/gen/user/v1"
)

func TestEnforcer(t *testing.T) {
	enforcer, err := NewEnforcer()
	if err != nil {
		t.Fatalf("Failed to create enforcer: %v", err)
	}

	tests := []struct {
		name     string
		role     string
		method   string
		expected bool
	}{
		// Admin should have access to all methods
		{
			name:     "admin can create user",
			role:     "admin",
			method:   "/UserService/CreateUser",
			expected: true,
		},
		{
			name:     "admin can get user",
			role:     "admin",
			method:   "/UserService/GetUser",
			expected: true,
		},
		{
			name:     "admin can list users",
			role:     "admin",
			method:   "/UserService/ListUsers",
			expected: true,
		},
		{
			name:     "admin can update user",
			role:     "admin",
			method:   "/UserService/UpdateUser",
			expected: true,
		},
		{
			name:     "admin can delete user",
			role:     "admin",
			method:   "/UserService/DeleteUser",
			expected: true,
		},
		{
			name:     "admin can get current user",
			role:     "admin",
			method:   "/UserService/GetCurrentUser",
			expected: true,
		},
		// User should have limited access
		{
			name:     "user cannot create user",
			role:     "user",
			method:   "/UserService/CreateUser",
			expected: false,
		},
		{
			name:     "user can get user",
			role:     "user",
			method:   "/UserService/GetUser",
			expected: true,
		},
		{
			name:     "user cannot list users",
			role:     "user",
			method:   "/UserService/ListUsers",
			expected: false,
		},
		{
			name:     "user cannot update user",
			role:     "user",
			method:   "/UserService/UpdateUser",
			expected: false,
		},
		{
			name:     "user cannot delete user",
			role:     "user",
			method:   "/UserService/DeleteUser",
			expected: false,
		},
		{
			name:     "user can get current user",
			role:     "user",
			method:   "/UserService/GetCurrentUser",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed, err := CheckPermission(enforcer, tt.role, tt.method)
			if err != nil {
				t.Errorf("CheckPermission error: %v", err)
				return
			}
			if allowed != tt.expected {
				t.Errorf(
					"Expected %v, got %v for role %s and method %s",
					tt.expected,
					allowed,
					tt.role,
					tt.method,
				)
			}
		})
	}
}

func TestConvertRoleToString(t *testing.T) {
	tests := []struct {
		name     string
		role     user_v1_pb.UserRole
		expected string
	}{
		{
			name:     "admin role",
			role:     user_v1_pb.UserRole_USER_ROLE_ADMIN,
			expected: "admin",
		},
		{
			name:     "user role",
			role:     user_v1_pb.UserRole_USER_ROLE_USER,
			expected: "user",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := convertRoleToString(tt.role)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}
