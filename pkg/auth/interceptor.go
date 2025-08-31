package auth

import (
	"context"
	"strings"

	user_v1_pb "github.com/poly-workshop/auth-portal/gen/user/v1"
	"github.com/poly-workshop/auth-portal/internal/model"
	"github.com/poly-workshop/go-webmods/app"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	configKeyInternalToken = "auth.internal_token"

	ContextKeyUserInfo = app.ContextKey("user_info")
)

func BuildAuthInterceptor(
	publicMethodMap map[string]bool,
	jwtSecret string,
) grpc.UnaryServerInterceptor {
	// Initialize the Casbin enforcer
	enforcer, err := NewEnforcer()
	if err != nil {
		// Log error but don't fail - fallback to basic auth
		// In production, you might want to fail here
		enforcer = nil
	}

	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		if ok := publicMethodMap[info.FullMethod]; ok {
			return handler(ctx, req)
		}

		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "missing metadata")
		}
		tokenType := md.Get("x-token-type")
		if len(tokenType) == 0 {
			tokenType = []string{"user"} // Default to user token if not specified
		}
		authHeader := md.Get("authorization")
		if len(authHeader) == 0 {
			return nil, status.Error(codes.Unauthenticated, "missing authorization token")
		}

		switch tokenType[0] {
		case "internal":
			token := strings.TrimPrefix(authHeader[0], "Bearer ")
			internalToken := app.Config().GetString(configKeyInternalToken)
			if token != internalToken {
				return nil, status.Error(codes.Unauthenticated, "invalid internal token")
			}
			// Internal tokens bypass authorization checks
		default:
			token := strings.TrimPrefix(authHeader[0], "Bearer ")
			userInfo, err := ParseUserToken(token, jwtSecret)
			if err != nil {
				return nil, status.Error(codes.Unauthenticated, "invalid token")
			}
			ctx = context.WithValue(ctx, ContextKeyUserInfo, userInfo)

			// Perform authorization check using Casbin enforcer
			if enforcer != nil {
				// Convert protobuf role to string for enforcer
				roleStr := convertRoleToString(userInfo.Role)
				allowed, err := CheckPermission(enforcer, roleStr, info.FullMethod)
				if err != nil {
					return nil, status.Error(codes.Internal, "authorization check failed")
				}
				if !allowed {
					return nil, status.Error(codes.PermissionDenied, "insufficient permissions")
				}
			}
		}
		return handler(ctx, req)
	}
}

// convertRoleToString converts protobuf UserRole to string
func convertRoleToString(role user_v1_pb.UserRole) string {
	switch role {
	case user_v1_pb.UserRole_USER_ROLE_ADMIN:
		return string(model.UserRoleAdmin)
	case user_v1_pb.UserRole_USER_ROLE_USER:
		return string(model.UserRoleUser)
	default:
		return string(model.UserRoleUser) // Default to user
	}
}
