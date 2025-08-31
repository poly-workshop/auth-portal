package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/poly-workshop/auth-portal/configs"
	auth_v1_pb "github.com/poly-workshop/auth-portal/gen/auth/v1"
	"github.com/poly-workshop/auth-portal/internal/model"
	providerPkg "github.com/poly-workshop/auth-portal/internal/provider"
	"github.com/poly-workshop/auth-portal/internal/repository"
	"github.com/poly-workshop/auth-portal/internal/utils"
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

// OAuthStateData represents OAuth state information
type OAuthStateData struct {
	Provider    string    `json:"provider"`
	RedirectURL string    `json:"redirect_url,omitempty"`
	UserAgent   string    `json:"user_agent,omitempty"`
	IPAddress   string    `json:"ip_address,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
}

type AuthService interface {
	// gRPC service methods
	GetOAuthCodeURL(ctx context.Context, req *auth_v1_pb.GetOAuthCodeURLRequest) (*auth_v1_pb.GetOAuthCodeURLResponse, error)
	LoginByOAuth(ctx context.Context, req *auth_v1_pb.LoginByOAuthRequest) (*auth_v1_pb.LoginByPasswordResponse, error)
	LoginByPassword(ctx context.Context, req *auth_v1_pb.LoginByPasswordRequest) (*auth_v1_pb.LoginByPasswordResponse, error)
	GetUserToken(ctx context.Context, req *auth_v1_pb.GetUserTokenRequest) (*auth_v1_pb.GetUserTokenResponse, error)
}

type authService struct {
	db           *gorm.DB
	rdb          redis.UniversalClient
	userRepo     repository.UserRepository
	config       configs.Config
	oauthConfigs map[string]*oauth2.Config
	auth_v1_pb.UnimplementedAuthServiceServer
}

func NewAuthService(
	db *gorm.DB,
	rdb redis.UniversalClient,
) auth_v1_pb.AuthServiceServer {
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

	return &authService{
		db:           db,
		rdb:          rdb,
		userRepo:     repository.NewUserRepository(db),
		config:       config,
		oauthConfigs: oauthConfigs,
	}
}

// OAuth state management methods
func (s *authService) generateState(
	ctx context.Context,
	provider, redirectURL, userAgent, ipAddress string,
) (string, error) {
	// Generate random state
	stateBytes := make([]byte, 32)
	if _, err := rand.Read(stateBytes); err != nil {
		return "", status.Errorf(codes.Internal, "failed to generate state: %v", err)
	}
	state := hex.EncodeToString(stateBytes)

	// Create state data
	now := time.Now()
	stateData := OAuthStateData{
		Provider:    provider,
		RedirectURL: redirectURL,
		UserAgent:   userAgent,
		IPAddress:   ipAddress,
		CreatedAt:   now,
		ExpiresAt:   now.Add(s.config.Auth.OAuthStateExpirationDuration),
	}

	// Store state data in Redis
	dataBytes, err := json.Marshal(stateData)
	if err != nil {
		return "", status.Errorf(codes.Internal, "failed to marshal state data: %v", err)
	}

	stateKey := fmt.Sprintf("oauth_state:%s", state)
	err = s.rdb.Set(ctx, stateKey, string(dataBytes), s.config.Auth.OAuthStateExpirationDuration).Err()
	if err != nil {
		return "", status.Errorf(codes.Internal, "failed to store state: %v", err)
	}

	return state, nil
}

func (s *authService) validateState(
	ctx context.Context,
	state, userAgent, ipAddress string,
) (*OAuthStateData, error) {
	stateKey := fmt.Sprintf("oauth_state:%s", state)
	dataStr, err := s.rdb.Get(ctx, stateKey).Result()
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid or expired state")
	}

	var stateData OAuthStateData
	if err := json.Unmarshal([]byte(dataStr), &stateData); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to unmarshal state data: %v", err)
	}

	// Validate expiration
	if time.Now().After(stateData.ExpiresAt) {
		// Clean up expired state
		err = s.deleteState(ctx, state)
		if err != nil {
			slog.ErrorContext(ctx, "failed to delete expired oauth state",
				"error", err,
				"state_prefix", state[:min(16, len(state))],
			)
		}
		return nil, status.Errorf(codes.InvalidArgument, "state has expired")
	}

	// Validate user agent if provided during creation (optional but recommended)
	if stateData.UserAgent != "" && userAgent != "" && stateData.UserAgent != userAgent {
		return nil, status.Errorf(
			codes.InvalidArgument,
			"user agent mismatch - possible session hijacking",
		)
	}

	// Validate IP address if provided during creation (optional but recommended)
	if stateData.IPAddress != "" && ipAddress != "" && stateData.IPAddress != ipAddress {
		return nil, status.Errorf(
			codes.InvalidArgument,
			"IP address mismatch - possible session hijacking",
		)
	}

	return &stateData, nil
}

func (s *authService) deleteState(ctx context.Context, state string) error {
	stateKey := fmt.Sprintf("oauth_state:%s", state)
	return s.rdb.Del(ctx, stateKey).Err()
}

// Session management methods
func (s *authService) createSession(ctx context.Context, userID string) (string, error) {
	// Generate session ID
	sessionBytes := make([]byte, 32)
	if _, err := rand.Read(sessionBytes); err != nil {
		slog.ErrorContext(ctx, "failed to generate session ID", "error", err, "user_id", userID)
		return "", status.Errorf(codes.Internal, "failed to generate session ID: %v", err)
	}
	sessionID := hex.EncodeToString(sessionBytes)

	// Store session in Redis with configured expiration
	sessionKey := fmt.Sprintf("session:%s", sessionID)
	err := s.rdb.Set(ctx, sessionKey, userID, s.config.Session.ExpirationDuration).Err()
	if err != nil {
		slog.ErrorContext(
			ctx,
			"failed to store session in redis",
			"error",
			err,
			"user_id",
			userID,
			"session_id",
			sessionID[:16],
		)
		return "", status.Errorf(codes.Internal, "failed to store session: %v", err)
	}

	slog.InfoContext(
		ctx,
		"session created successfully",
		"user_id",
		userID,
		"session_id",
		sessionID[:16],
		"expires_in_hours",
		24,
	)
	return sessionID, nil
}

func (s *authService) getUserIDFromSession(ctx context.Context, sessionID string) (*string, error) {
	sessionKey := fmt.Sprintf("session:%s", sessionID)
	userIDStr, err := s.rdb.Get(ctx, sessionKey).Result()
	if err != nil {
		slog.WarnContext(
			ctx,
			"session lookup failed",
			"error",
			"invalid or expired session",
			"session_id",
			sessionID[:min(16, len(sessionID))],
		)
		return nil, status.Errorf(codes.Unauthenticated, "invalid or expired session")
	}

	var userID string
	if _, err := fmt.Sscanf(userIDStr, "%s", &userID); err != nil {
		slog.ErrorContext(
			ctx,
			"invalid session data format",
			"error",
			err,
			"session_id",
			sessionID[:min(16, len(sessionID))],
		)
		return nil, status.Errorf(codes.Internal, "invalid session data")
	}

	// Automatically refresh session TTL when accessed
	if err := s.refreshSession(ctx, sessionID); err != nil {
		// Log the error but don't fail the request - session is still valid
		slog.WarnContext(
			ctx,
			"session refresh failed but continuing",
			"error",
			err,
			"user_id",
			userID,
			"session_id",
			sessionID[:16],
		)
	} else {
		slog.DebugContext(ctx, "session refreshed successfully", "user_id", userID, "session_id", sessionID[:16])
	}

	return &userID, nil
}

func (s *authService) refreshSession(ctx context.Context, sessionID string) error {
	sessionKey := fmt.Sprintf("session:%s", sessionID)
	return s.rdb.Expire(ctx, sessionKey, s.config.Session.ExpirationDuration).Err()
}

func (s *authService) getSessionExpirationTime(
	ctx context.Context,
	sessionID string,
) (time.Time, error) {
	sessionKey := fmt.Sprintf("session:%s", sessionID)
	ttl, err := s.rdb.TTL(ctx, sessionKey).Result()
	if err != nil {
		return time.Time{}, status.Errorf(codes.Internal, "failed to get session TTL: %v", err)
	}
	if ttl == -2 { // Key does not exist
		return time.Time{}, status.Errorf(codes.Unauthenticated, "session not found")
	}
	if ttl == -1 { // Key exists but has no expiration
		return time.Time{}, status.Errorf(codes.Internal, "session has no expiration")
	}
	return time.Now().Add(ttl), nil
}

// GetOAuthCodeURL generates OAuth authorization URL with embedded CSRF protection
func (s *authService) GetOAuthCodeURL(
	ctx context.Context,
	req *auth_v1_pb.GetOAuthCodeURLRequest,
) (*auth_v1_pb.GetOAuthCodeURLResponse, error) {
	slog.InfoContext(ctx, "oauth code url request started",
		"provider", req.Provider,
		"ip_address", s.extractIPAddress(ctx),
		"user_agent", s.extractUserAgent(ctx))

	if req.Provider == "" {
		slog.WarnContext(ctx, "oauth code url request failed", "error", "provider is required")
		return nil, status.Errorf(codes.InvalidArgument, "provider is required")
	}
	oauthConfig, exists := s.oauthConfigs[req.Provider]
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
	userAgent := s.extractUserAgent(ctx)
	ipAddress := s.extractIPAddress(ctx)

	// Use custom redirect URL if provided, otherwise use default from config
	redirectURL := req.GetRedirectUrl()
	if redirectURL == "" {
		redirectURL = oauthConfig.RedirectURL
	}

	// Create a copy of the OAuth config with the custom redirect URL
	customOauthConfig := *oauthConfig
	customOauthConfig.RedirectURL = redirectURL

	// Generate state with embedded CSRF protection, including the redirect URL
	state, err := s.generateState(ctx, req.Provider, redirectURL, userAgent, ipAddress)
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

	return &auth_v1_pb.GetOAuthCodeURLResponse{
		Url:   url,
		State: state, // Return the state containing all security information
	}, nil
}

// LoginByOAuth handles OAuth login flow with CSRF protection
func (s *authService) LoginByOAuth(
	ctx context.Context,
	req *auth_v1_pb.LoginByOAuthRequest,
) (*auth_v1_pb.LoginByOAuthResponse, error) {
	ipAddress := s.extractIPAddress(ctx)
	userAgent := s.extractUserAgent(ctx)

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

	stateData, err := s.validateState(ctx, req.State, userAgent, ipAddress)
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
	err = s.deleteState(ctx, req.State)
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

	oauthConfig, exists := s.oauthConfigs[stateData.Provider]
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
		user, err = s.userRepo.GetByGithubID(ctx, userInfo.ID)
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

			if err := s.userRepo.Create(ctx, user); err != nil {
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
			if err := s.userRepo.Update(ctx, user); err != nil {
				slog.ErrorContext(ctx, "failed to update user last login", "error", err, "user_id", user.ID)
				return nil, status.Errorf(codes.Internal, "failed to update user: %v", err)
			}
			slog.InfoContext(ctx, "existing user login successful", "user_id", user.ID, "email", user.Email, "provider", stateData.Provider)
		}
	}

	// Create login session
	sessionID, err := s.createSession(ctx, user.ID)
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
	expiresAt, err := s.getSessionExpirationTime(ctx, sessionID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get session expiration: %v", err)
	}
	return &auth_v1_pb.LoginByOAuthResponse{
		Session: &auth_v1_pb.LoginSession{
			Id:        sessionID,
			ExpiresAt: timestamppb.New(expiresAt),
		},
	}, nil
}

// LoginByPassword handles password-based login
func (s *authService) LoginByPassword(
	ctx context.Context,
	req *auth_v1_pb.LoginByPasswordRequest,
) (*auth_v1_pb.LoginByPasswordResponse, error) {
	ipAddress := s.extractIPAddress(ctx)
	userAgent := s.extractUserAgent(ctx)

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
	user, err := s.userRepo.GetByEmail(ctx, req.Email)
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
	if err := s.userRepo.Update(ctx, user); err != nil {
		slog.ErrorContext(ctx, "failed to update user last login", "error", err, "user_id", user.ID)
		return nil, status.Errorf(codes.Internal, "failed to update user: %v", err)
	}

	// Create login session
	sessionID, err := s.createSession(ctx, user.ID)
	if err != nil {
		slog.ErrorContext(ctx, "failed to create login session", "error", err, "user_id", user.ID)
		return nil, status.Errorf(codes.Internal, "failed to create session: %v", err)
	}

	slog.InfoContext(ctx, "password login completed successfully",
		"user_id", user.ID,
		"email", req.Email,
		"session_id", sessionID[:16],
		"ip_address", ipAddress)

	expiresAt, err := s.getSessionExpirationTime(ctx, sessionID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get session expiration: %v", err)
	}
	return &auth_v1_pb.LoginByPasswordResponse{
		Session: &auth_v1_pb.LoginSession{
			Id:        sessionID,
			ExpiresAt: timestamppb.New(expiresAt),
		},
	}, nil
}

// GetUserToken generates JWT token for authenticated users
func (s *authService) GetUserToken(
	ctx context.Context,
	req *auth_v1_pb.GetUserTokenRequest,
) (*auth_v1_pb.GetUserTokenResponse, error) {
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
	userID, err := s.getUserIDFromSession(ctx, req.SessionId)
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
	sessionExpiresAt, err := s.getSessionExpirationTime(ctx, req.SessionId)
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
	user, err := s.userRepo.GetByID(ctx, *userID)
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
		s.config.Auth.JWTSecret,
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

	return &auth_v1_pb.GetUserTokenResponse{
		Token: userToken,
	}, nil
}

// extractUserAgent extracts user agent from gRPC metadata
func (s *authService) extractUserAgent(ctx context.Context) string {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		userAgents := md.Get("user-agent")
		if len(userAgents) > 0 {
			return userAgents[0]
		}
	}
	return ""
}

// extractIPAddress extracts IP address from gRPC peer info
func (s *authService) extractIPAddress(ctx context.Context) string {
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
