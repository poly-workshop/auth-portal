package auth

import (
	"github.com/golang-jwt/jwt/v5"
	user_v1_pb "github.com/poly-workshop/auth-portal/gen/user/v1"
	"github.com/poly-workshop/auth-portal/internal/utils"
)

type UserInfo struct {
	UserID string
	Role   user_v1_pb.UserRole
}

func ParseUserToken(tokenString, secret string) (*UserInfo, error) {
	claims, err := utils.ValidateUserToken(tokenString, secret)
	if err != nil {
		return nil, err
	}

	userID, ok := claims.MapClaims["user_id"].(string)
	if !ok {
		return nil, jwt.ErrTokenInvalidClaims
	}

	role, ok := claims.MapClaims["user_role"].(float64)
	if !ok {
		return nil, jwt.ErrTokenInvalidClaims
	}

	return &UserInfo{
		UserID: userID,
		Role:   user_v1_pb.UserRole(role),
	}, nil
}
