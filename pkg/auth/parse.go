package auth

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/poly-workshop/auth-portal/internal/utils"
	protopb "github.com/poly-workshop/auth-portal/pkg/proto"
)

type UserInfo struct {
	UserID string
	Role   protopb.UserRole
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
		Role:   protopb.UserRole(role),
	}, nil
}
