package configs

import (
	"time"

	"github.com/poly-workshop/go-webmods/app"
	"github.com/poly-workshop/go-webmods/gorm_client"
	"github.com/poly-workshop/go-webmods/redis_client"
)

// Configuration keys constants
const (
	// Server configuration keys
	ServerPortKey     = "server.port"
	ServerHTTPPortKey = "server.http_port"

	// Auth configuration keys
	AuthInternalTokenKey               = "auth.internal_token"
	AuthJWTSecretKey                   = "auth.jwt_secret"
	AuthGithubClientIDKey              = "auth.github_client_id"
	AuthGithubClientSecretKey          = "auth.github_client_secret"
	AuthGithubRedirectURLKey           = "auth.github_redirect_url"
	AuthOAuthStateExpirationMinutesKey = "auth.oauth_state_expiration_minutes"

	// Session configuration keys
	SessionExpirationHoursKey = "session.expiration_hours"

	// Database configuration keys
	DatabaseDriverKey   = "gorm_client.database.driver"
	DatabaseHostKey     = "gorm_client.database.host"
	DatabasePortKey     = "gorm_client.database.port"
	DatabaseUsernameKey = "gorm_client.database.username"
	DatabasePasswordKey = "gorm_client.database.password"
	DatabaseNameKey     = "gorm_client.database.name"
	DatabaseSSLModeKey  = "gorm_client.database.sslmode"

	// Redis configuration keys
	RedisUrlsKey     = "redis.urls"
	RedisPasswordKey = "redis.password"
)

// Default values constants
const (
	DefaultJWTSecret                   = "default_jwt_secret_change_in_production"
	DefaultSessionExpirationHours      = 24
	DefaultOAuthStateExpirationMinutes = 10
)

type Config struct {
	Server   ServerConfig
	Auth     AuthConfig
	Session  SessionConfig
	Database gorm_client.Config
	Redis    redis_client.Config
}

type ServerConfig struct {
	Port     uint
	HTTPPort uint
}

type AuthConfig struct {
	InternalToken                string
	JWTSecret                    string
	GithubClientID               string
	GithubClientSecret           string
	GithubRedirectURL            string
	OAuthStateExpirationDuration time.Duration
}

type SessionConfig struct {
	ExpirationDuration time.Duration
}

func Load() Config {
	cfg := Config{
		Server: ServerConfig{
			Port:     app.Config().GetUint(ServerPortKey),
			HTTPPort: app.Config().GetUint(ServerHTTPPortKey),
		},
		Auth: AuthConfig{
			InternalToken:      app.Config().GetString(AuthInternalTokenKey),
			JWTSecret:          app.Config().GetString(AuthJWTSecretKey),
			GithubClientID:     app.Config().GetString(AuthGithubClientIDKey),
			GithubClientSecret: app.Config().GetString(AuthGithubClientSecretKey),
			GithubRedirectURL:  app.Config().GetString(AuthGithubRedirectURLKey),
			OAuthStateExpirationDuration: time.Duration(
				getIntWithDefault(
					AuthOAuthStateExpirationMinutesKey,
					DefaultOAuthStateExpirationMinutes,
				),
			) * time.Minute,
		},
		Session: SessionConfig{
			ExpirationDuration: time.Duration(
				getIntWithDefault(SessionExpirationHoursKey, DefaultSessionExpirationHours),
			) * time.Hour,
		},
		Database: gorm_client.Config{
			Driver:   app.Config().GetString(DatabaseDriverKey),
			Host:     app.Config().GetString(DatabaseHostKey),
			Port:     app.Config().GetInt(DatabasePortKey),
			Username: app.Config().GetString(DatabaseUsernameKey),
			Password: app.Config().GetString(DatabasePasswordKey),
			Name:     app.Config().GetString(DatabaseNameKey),
			SSLMode:  app.Config().GetString(DatabaseSSLModeKey),
		},
		Redis: redis_client.Config{
			Urls:     app.Config().GetStringSlice(RedisUrlsKey),
			Password: app.Config().GetString(RedisPasswordKey),
		},
	}

	// Set default JWT Secret if not provided
	if cfg.Auth.JWTSecret == "" {
		cfg.Auth.JWTSecret = DefaultJWTSecret
	}

	return cfg
}

func getIntWithDefault(key string, defaultValue int) int {
	if value := app.Config().GetInt(key); value != 0 {
		return value
	}
	return defaultValue
}
