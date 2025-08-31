package handler

import (
	"context"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/poly-workshop/auth-portal/configs"
	"github.com/poly-workshop/auth-portal/internal/model"
	providerPkg "github.com/poly-workshop/auth-portal/internal/provider"
	"github.com/poly-workshop/auth-portal/internal/repository"
	"github.com/poly-workshop/auth-portal/internal/service"
	"github.com/poly-workshop/auth-portal/internal/utils"
	protopb "github.com/poly-workshop/auth-portal/pkg/proto"
	"github.com/redis/go-redis/v9"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gorm.io/gorm"
)

type AuthHandler struct {
	db             *gorm.DB
	userRepo       repository.UserRepository
	oauthService   service.OAuthService
	sessionService service.SessionService
	config         configs.Config
	oauthConfigs   map[string]*oauth2.Config
	protopb.UnimplementedAuthServiceServer
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func NewAuthHandler(
	db *gorm.DB,
	rdb redis.UniversalClient,
	sessionService service.SessionService,
	oauthService service.OAuthService,
) *AuthHandler {
	config := configs.Load()

	// Initialize OAuth configurations
	oauthConfigs := make(map[string]*oauth2.Config)
	oauthConfigs["github"] = &oauth2.Config{
		ClientID:     config.Auth.GithubClientID,
		ClientSecret: config.Auth.GithubClientSecret,
		Scopes:       []string{"user:email"},
		Endpoint:     github.Endpoint,
		RedirectURL:  config.Auth.GithubRedirectURL,
	}

	return &AuthHandler{
		db:             db,
		userRepo:       repository.NewUserRepository(db),
		oauthService:   oauthService,
		sessionService: sessionService,
		config:         config,
		oauthConfigs:   oauthConfigs,
	}
}

// GetOAuthCodeURL generates OAuth authorization URL with embedded CSRF protection
func (h *AuthHandler) GetOAuthCodeURL(
	ctx context.Context,
	req *protopb.GetOAuthCodeURLRequest,
) (*protopb.GetOAuthCodeURLResponse, error) {
	slog.InfoContext(ctx, "oauth code url request started",
		"provider", req.Provider,
		"ip_address", h.extractIPAddress(ctx),
		"user_agent", h.extractUserAgent(ctx))

	if req.Provider == "" {
		slog.WarnContext(ctx, "oauth code url request failed", "error", "provider is required")
		return nil, status.Errorf(codes.InvalidArgument, "provider is required")
	}
	oauthConfig, exists := h.oauthConfigs[req.Provider]
	if !exists {
		slog.WarnContext(
			ctx,
			"oauth code url request failed",
			"error",
			"unsupported provider",
			"provider",
			req.Provider,
		)
		return nil, status.Errorf(codes.InvalidArgument, "unsupported provider: %s", req.Provider)
	}

	// Extract client information for additional security
	userAgent := h.extractUserAgent(ctx)
	ipAddress := h.extractIPAddress(ctx)

	// Use custom redirect URL if provided, otherwise use default from config
	redirectURL := req.GetRedirectUrl()
	if redirectURL == "" {
		redirectURL = oauthConfig.RedirectURL
	}

	// Create a copy of the OAuth config with the custom redirect URL
	customOauthConfig := *oauthConfig
	customOauthConfig.RedirectURL = redirectURL

	// Generate state with embedded CSRF protection, including the redirect URL
	state, err := h.oauthService.GenerateState(ctx, req.Provider, redirectURL, userAgent, ipAddress)
	if err != nil {
		slog.ErrorContext(
			ctx,
			"oauth state generation failed",
			"error",
			err,
			"provider",
			req.Provider,
		)
		return nil, err
	}

	url := customOauthConfig.AuthCodeURL(state, oauth2.AccessTypeOffline)

	slog.InfoContext(ctx, "oauth code url generated successfully",
		"provider", req.Provider,
		"redirect_url", redirectURL,
		"state_id", state[:16], // Log partial state for debugging
		"ip_address", ipAddress)

	return &protopb.GetOAuthCodeURLResponse{
		Url:   url,
		State: state, // Return the state containing all security information
	}, nil
}

// LoginByOAuth handles OAuth login flow with CSRF protection
func (h *AuthHandler) LoginByOAuth(
	ctx context.Context,
	req *protopb.LoginByOAuthRequest,
) (*protopb.LoginSession, error) {
	ipAddress := h.extractIPAddress(ctx)
	userAgent := h.extractUserAgent(ctx)

	slog.InfoContext(ctx, "oauth login attempt started",
		"ip_address", ipAddress,
		"user_agent", userAgent)

	if req.Code == "" || req.State == "" {
		slog.WarnContext(
			ctx,
			"oauth login failed",
			"error",
			"code and state are required",
			"has_code",
			req.Code != "",
			"has_state",
			req.State != "",
		)
		return nil, status.Errorf(codes.InvalidArgument, "code and state are required")
	}

	stateData, err := h.oauthService.ValidateState(ctx, req.State, userAgent, ipAddress)
	if err != nil {
		slog.WarnContext(
			ctx,
			"oauth state validation failed",
			"error",
			err,
			"state_prefix",
			req.State[:min(16, len(req.State))],
			"ip_address",
			ipAddress,
		)
		return nil, err
	}

	slog.InfoContext(
		ctx,
		"oauth state validated successfully",
		"provider",
		stateData.Provider,
		"redirect_url",
		stateData.RedirectURL,
	)

	// Delete used state
	err = h.oauthService.DeleteState(ctx, req.State)
	if err != nil {
		slog.ErrorContext(
			ctx,
			"failed to delete used oauth state",
			"error",
			err,
			"state_prefix",
			req.State[:min(16, len(req.State))],
		)
		return nil, status.Errorf(codes.Internal, "failed to delete used state: %v", err)
	}

	oauthConfig, exists := h.oauthConfigs[stateData.Provider]
	if !exists {
		slog.ErrorContext(ctx, "unsupported oauth provider", "provider", stateData.Provider)
		return nil, status.Errorf(
			codes.InvalidArgument,
			"unsupported provider: %s",
			stateData.Provider,
		)
	}

	// Use the redirect URL from state if available, otherwise use default from config
	redirectURL := stateData.RedirectURL
	if redirectURL == "" {
		redirectURL = oauthConfig.RedirectURL
	}

	// Create a copy of the OAuth config with the redirect URL from state
	customOauthConfig := *oauthConfig
	customOauthConfig.RedirectURL = redirectURL

	// Exchange code for token
	token, err := customOauthConfig.Exchange(ctx, req.Code)
	if err != nil {
		slog.ErrorContext(
			ctx,
			"oauth token exchange failed",
			"error",
			err,
			"provider",
			stateData.Provider,
		)
		return nil, status.Errorf(codes.Internal, "failed to exchange code for token: %v", err)
	}

	slog.DebugContext(ctx, "oauth token exchange successful", "provider", stateData.Provider)

	// Get user info from provider
	userProvider, err := providerPkg.GetUserProvider(stateData.Provider)
	if err != nil {
		slog.ErrorContext(
			ctx,
			"failed to get user provider",
			"error",
			err,
			"provider",
			stateData.Provider,
		)
		return nil, status.Errorf(codes.Internal, "failed to get user provider: %v", err)
	}

	userInfo, err := userProvider.GetUserInfo(ctx, token.AccessToken)
	if err != nil {
		slog.ErrorContext(
			ctx,
			"failed to get user info from provider",
			"error",
			err,
			"provider",
			stateData.Provider,
		)
		return nil, status.Errorf(codes.Internal, "failed to get user info: %v", err)
	}

	slog.InfoContext(
		ctx,
		"user info retrieved from provider",
		"provider",
		stateData.Provider,
		"user_id",
		userInfo.ID,
		"email",
		userInfo.Email,
	)

	// Find or create user
	var user *model.UserModel
	var isNewUser bool
	if stateData.Provider == "github" {
		user, err = h.userRepo.GetByGithubID(ctx, userInfo.ID)
		if err != nil && err != gorm.ErrRecordNotFound {
			slog.ErrorContext(
				ctx,
				"failed to query user by github id",
				"error",
				err,
				"github_id",
				userInfo.ID,
			)
			return nil, status.Errorf(codes.Internal, "failed to query user: %v", err)
		}

		if user == nil {
			isNewUser = true
			// Create new user
			now := time.Now()
			user = &model.UserModel{
				Name:        userInfo.Name,
				Email:       userInfo.Email,
				GithubID:    &userInfo.ID,
				LastLoginAt: &now,
				Role:        model.UserRoleUser,
			}

			if err := h.userRepo.Create(ctx, user); err != nil {
				slog.ErrorContext(
					ctx,
					"failed to create new user",
					"error",
					err,
					"email",
					userInfo.Email,
					"github_id",
					userInfo.ID,
				)
				return nil, status.Errorf(codes.Internal, "failed to create user: %v", err)
			}
			slog.InfoContext(
				ctx,
				"new user created successfully",
				"user_id",
				user.ID,
				"email",
				user.Email,
				"provider",
				stateData.Provider,
			)
		} else {
			// Update last login
			now := time.Now()
			user.LastLoginAt = &now
			if err := h.userRepo.Update(ctx, user); err != nil {
				slog.ErrorContext(ctx, "failed to update user last login", "error", err, "user_id", user.ID)
				return nil, status.Errorf(codes.Internal, "failed to update user: %v", err)
			}
			slog.InfoContext(ctx, "existing user login successful", "user_id", user.ID, "email", user.Email, "provider", stateData.Provider)
		}
	}

	// Create login session
	sessionID, err := h.sessionService.CreateSession(ctx, user.ID)
	if err != nil {
		slog.ErrorContext(ctx, "failed to create login session", "error", err, "user_id", user.ID)
		return nil, status.Errorf(codes.Internal, "failed to create session: %v", err)
	}

	slog.InfoContext(ctx, "oauth login completed successfully",
		"user_id", user.ID,
		"session_id", sessionID[:16],
		"provider", stateData.Provider,
		"is_new_user", isNewUser,
		"ip_address", ipAddress)

	// Get session expiration time
	expiresAt, err := h.sessionService.GetSessionExpirationTime(ctx, sessionID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get session expiration: %v", err)
	}
	return &protopb.LoginSession{
		Id:        sessionID,
		ExpiresAt: timestamppb.New(expiresAt),
	}, nil
}

// LoginByPassword handles password-based login
func (h *AuthHandler) LoginByPassword(
	ctx context.Context,
	req *protopb.LoginByPasswordRequest,
) (*protopb.LoginSession, error) {
	ipAddress := h.extractIPAddress(ctx)
	userAgent := h.extractUserAgent(ctx)

	slog.InfoContext(ctx, "password login attempt started",
		"email", req.Email,
		"ip_address", ipAddress,
		"user_agent", userAgent)

	if req.Email == "" || req.Password == "" {
		slog.WarnContext(
			ctx,
			"password login failed",
			"error",
			"email and password are required",
			"has_email",
			req.Email != "",
			"has_password",
			req.Password != "",
		)
		return nil, status.Errorf(codes.InvalidArgument, "email and password are required")
	}

	// Get user by email
	user, err := h.userRepo.GetByEmail(ctx, req.Email)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			slog.WarnContext(
				ctx,
				"password login failed",
				"error",
				"user not found",
				"email",
				req.Email,
				"ip_address",
				ipAddress,
			)
			return nil, status.Errorf(codes.NotFound, "invalid credentials")
		}
		slog.ErrorContext(
			ctx,
			"failed to query user for password login",
			"error",
			err,
			"email",
			req.Email,
		)
		return nil, status.Errorf(codes.Internal, "failed to query user: %v", err)
	}

	// Check if user has a password set
	if user.HashedPassword == nil {
		slog.WarnContext(
			ctx,
			"password login attempt for oauth-only account",
			"user_id",
			user.ID,
			"email",
			req.Email,
			"ip_address",
			ipAddress,
		)
		return nil, status.Errorf(
			codes.FailedPrecondition,
			"password login not available for this account",
		)
	}

	// Verify password
	valid, err := utils.VerifyPassword(req.Password, *user.HashedPassword)
	if err != nil {
		slog.ErrorContext(
			ctx,
			"password verification error",
			"error",
			err,
			"user_id",
			user.ID,
			"email",
			req.Email,
		)
		return nil, status.Errorf(codes.Internal, "failed to verify password: %v", err)
	}
	if !valid {
		slog.WarnContext(
			ctx,
			"password login failed",
			"error",
			"invalid password",
			"user_id",
			user.ID,
			"email",
			req.Email,
			"ip_address",
			ipAddress,
		)
		return nil, status.Errorf(codes.Unauthenticated, "invalid credentials")
	}

	// Update last login
	now := time.Now()
	user.LastLoginAt = &now
	if err := h.userRepo.Update(ctx, user); err != nil {
		slog.ErrorContext(ctx, "failed to update user last login", "error", err, "user_id", user.ID)
		return nil, status.Errorf(codes.Internal, "failed to update user: %v", err)
	}

	// Create login session
	sessionID, err := h.sessionService.CreateSession(ctx, user.ID)
	if err != nil {
		slog.ErrorContext(ctx, "failed to create login session", "error", err, "user_id", user.ID)
		return nil, status.Errorf(codes.Internal, "failed to create session: %v", err)
	}

	slog.InfoContext(ctx, "password login completed successfully",
		"user_id", user.ID,
		"email", req.Email,
		"session_id", sessionID[:16],
		"ip_address", ipAddress)

	expiresAt, err := h.sessionService.GetSessionExpirationTime(ctx, sessionID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get session expiration: %v", err)
	}
	return &protopb.LoginSession{
		Id:        sessionID,
		ExpiresAt: timestamppb.New(expiresAt),
	}, nil
}

// GetUserToken generates JWT token for authenticated users
func (h *AuthHandler) GetUserToken(
	ctx context.Context,
	req *protopb.GetUserTokenRequest,
) (*protopb.UserToken, error) {
	slog.InfoContext(
		ctx,
		"user token request started",
		"session_id",
		req.SessionId[:min(16, len(req.SessionId))],
	)

	if req.SessionId == "" {
		slog.WarnContext(ctx, "user token request failed", "error", "session_id is required")
		return nil, status.Errorf(codes.InvalidArgument, "session_id is required")
	}

	// Get user ID from session (this automatically refreshes the session)
	userID, err := h.sessionService.GetUserIDFromSession(ctx, req.SessionId)
	if err != nil {
		slog.WarnContext(
			ctx,
			"user token request failed",
			"error",
			"invalid or expired session",
			"session_id",
			req.SessionId[:min(16, len(req.SessionId))],
		)
		return nil, err
	}

	// Get session expiration time after refresh
	sessionExpiresAt, err := h.sessionService.GetSessionExpirationTime(ctx, req.SessionId)
	if err != nil {
		slog.ErrorContext(
			ctx,
			"failed to get session expiration time",
			"error",
			err,
			"user_id",
			userID,
			"session_id",
			req.SessionId[:min(16, len(req.SessionId))],
		)
		return nil, status.Errorf(codes.Internal, "failed to get session expiration: %v", err)
	}

	// Get user details
	user, err := h.userRepo.GetByID(ctx, *userID)
	if err != nil {
		slog.ErrorContext(
			ctx,
			"failed to get user details for token generation",
			"error",
			err,
			"user_id",
			userID,
		)
		return nil, status.Errorf(codes.Internal, "failed to get user: %v", err)
	}

	// Generate JWT token with session expiration time
	// This ensures the token expires when the session expires
	userToken, err := utils.NewUserTokenWithExpiration(
		user.ID,
		user.Role,
		h.config.Auth.JWTSecret,
		sessionExpiresAt,
	)
	if err != nil {
		slog.ErrorContext(ctx, "failed to generate JWT token", "error", err, "user_id", user.ID)
		return nil, status.Errorf(codes.Internal, "failed to generate token: %v", err)
	}

	slog.InfoContext(ctx, "user token generated successfully",
		"user_id", user.ID,
		"role", user.Role,
		"session_id", req.SessionId[:16],
		"token_expires_at", sessionExpiresAt)

	return userToken, nil
}

// extractUserAgent extracts user agent from gRPC metadata
func (h *AuthHandler) extractUserAgent(ctx context.Context) string {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		userAgents := md.Get("user-agent")
		if len(userAgents) > 0 {
			return userAgents[0]
		}
	}
	return ""
}

// extractIPAddress extracts IP address from gRPC peer info
func (h *AuthHandler) extractIPAddress(ctx context.Context) string {
	if p, ok := peer.FromContext(ctx); ok {
		if addr := p.Addr; addr != nil {
			// Handle different address types
			switch addr := addr.(type) {
			case *net.TCPAddr:
				return addr.IP.String()
			case *net.UDPAddr:
				return addr.IP.String()
			default:
				// Try to parse the string representation
				addrStr := addr.String()
				if host, _, err := net.SplitHostPort(addrStr); err == nil {
					return host
				}
				// Check for X-Forwarded-For header in metadata
				if md, ok := metadata.FromIncomingContext(ctx); ok {
					xForwardedFor := md.Get("x-forwarded-for")
					if len(xForwardedFor) > 0 {
						// Get the first IP from the comma-separated list
						ips := strings.Split(xForwardedFor[0], ",")
						if len(ips) > 0 {
							return strings.TrimSpace(ips[0])
						}
					}

					xRealIP := md.Get("x-real-ip")
					if len(xRealIP) > 0 {
						return xRealIP[0]
					}
				}
				return addrStr
			}
		}
	}
	return ""
}
