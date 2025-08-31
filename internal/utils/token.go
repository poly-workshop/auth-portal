package utils

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	auth_v1_pb "github.com/poly-workshop/auth-portal/gen/auth/v1"
	"github.com/poly-workshop/auth-portal/internal/model"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type UserTokenClaims struct {
	jwt.MapClaims
}

// NewUserTokenClaims creates a new UserTokenClaims with a default 24-hour expiration.
// Deprecated: This function uses a hardcoded 24-hour expiration time.
// Use NewUserTokenClaimsWithExpiration instead to specify a custom expiration time.
func NewUserTokenClaims(userID string, role model.UserRole) UserTokenClaims {
	return NewUserTokenClaimsWithExpiration(userID, role, time.Now().Add(24*time.Hour))
}

// NewUserTokenClaimsWithExpiration creates a new UserTokenClaims with a custom expiration time.
func NewUserTokenClaimsWithExpiration(
	userID string,
	role model.UserRole,
	expiresAt time.Time,
) UserTokenClaims {
	return UserTokenClaims{
		MapClaims: jwt.MapClaims{
			"user_id":   userID,
			"user_role": role.ToPb(),
			"exp":       expiresAt.Unix(),
		},
	}
}

func (c UserTokenClaims) GetExpirationTime() (*jwt.NumericDate, error) {
	return c.MapClaims.GetExpirationTime()
}

func (c UserTokenClaims) GetNotBefore() (*jwt.NumericDate, error) {
	return c.MapClaims.GetNotBefore()
}

func (c UserTokenClaims) GetIssuedAt() (*jwt.NumericDate, error) {
	return c.MapClaims.GetIssuedAt()
}

func (c UserTokenClaims) GetAudience() (jwt.ClaimStrings, error) {
	return c.MapClaims.GetAudience()
}

func (c UserTokenClaims) GetIssuer() (string, error) {
	return c.MapClaims.GetIssuer()
}

func (c UserTokenClaims) GetSubject() (string, error) {
	return c.MapClaims.GetSubject()
}

// NewUserTokenWithExpiration creates a new UserToken with a custom expiration time.
func NewUserTokenWithExpiration(
	userID string,
	role model.UserRole,
	secret string,
	expiresAt time.Time,
) (*auth_v1_pb.UserToken, error) {
	claims := NewUserTokenClaimsWithExpiration(userID, role, expiresAt)
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := jwtToken.SignedString([]byte(secret))
	if err != nil {
		return nil, err
	}

	return &auth_v1_pb.UserToken{
		Token:     signedToken,
		ExpiresAt: timestamppb.New(expiresAt),
	}, nil
}

func ValidateUserToken(tokenString, secret string) (*UserTokenClaims, error) {
	token, err := jwt.ParseWithClaims(
		tokenString,
		&UserTokenClaims{},
		func(token *jwt.Token) (interface{}, error) {
			return []byte(secret), nil
		},
	)
	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*UserTokenClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, jwt.ErrTokenInvalidClaims
}
