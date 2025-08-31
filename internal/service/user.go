package service

import (
	"context"
	"fmt"

	"github.com/poly-workshop/auth-portal/internal/model"
	"github.com/poly-workshop/auth-portal/internal/repository"
	"github.com/poly-workshop/auth-portal/pkg/auth"
	protopb "github.com/poly-workshop/auth-portal/pkg/proto"
)

type UserService interface {
	CreateUser(ctx context.Context, req *protopb.CreateUserRequest) error
	GetUser(ctx context.Context, id string) (*protopb.User, error)
	GetCurrentUser(ctx context.Context) (*protopb.User, error)
	GetUserByEmail(ctx context.Context, email string) (*protopb.User, error)
	UpdateUser(ctx context.Context, req *protopb.UpdateUserRequest) error
	DeleteUser(ctx context.Context, id string) error
	ListUsers(ctx context.Context, req *protopb.ListUsersRequest) (*protopb.ListUsersResponse, error)
}

type userService struct {
	userRepo repository.UserRepository
}

func NewUserService(userRepo repository.UserRepository) UserService {
	return &userService{
		userRepo: userRepo,
	}
}

func (s *userService) CreateUser(ctx context.Context, req *protopb.CreateUserRequest) error {
	user := &model.UserModel{
		Name:     req.Name,
		Email:    req.Email,
		GithubID: req.GithubId,
	}
	user.Role.FromPb(req.Role)

	return s.userRepo.Create(ctx, user)
}

func (s *userService) GetUser(ctx context.Context, id string) (*protopb.User, error) {
	user, err := s.userRepo.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	return user.ToPb(), nil
}

func (s *userService) GetCurrentUser(ctx context.Context) (*protopb.User, error) {
	// Get user info from context (set by auth interceptor)
	userInfo, ok := ctx.Value(auth.ContextKeyUserInfo).(*auth.UserInfo)
	if !ok {
		return nil, fmt.Errorf("user info not found in context")
	}

	return s.GetUser(ctx, userInfo.UserID)
}

func (s *userService) GetUserByEmail(ctx context.Context, email string) (*protopb.User, error) {
	user, err := s.userRepo.GetByEmail(ctx, email)
	if err != nil {
		return nil, fmt.Errorf("failed to get user by email: %w", err)
	}
	return user.ToPb(), nil
}

func (s *userService) UpdateUser(ctx context.Context, req *protopb.UpdateUserRequest) error {
	user, err := s.userRepo.GetByID(ctx, req.Id)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}

	user.UpdateFromPb(req)
	return s.userRepo.Update(ctx, user)
}

func (s *userService) DeleteUser(ctx context.Context, id string) error {
	return s.userRepo.Delete(ctx, id)
}

func (s *userService) ListUsers(
	ctx context.Context,
	req *protopb.ListUsersRequest,
) (*protopb.ListUsersResponse, error) {
	if req.Page < 1 {
		req.Page = 1
	}
	if req.PageSize < 1 {
		req.PageSize = 10 // Default page size
	}
	offset := int((req.Page - 1) * req.PageSize)
	limit := int(req.PageSize)

	result := &protopb.ListUsersResponse{}
	count, err := s.userRepo.Count(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to count users: %w", err)
	}
	if count > 0 {
		result.Total = uint64(count)
		users, err := s.userRepo.List(ctx, offset, limit)
		if err != nil {
			return nil, fmt.Errorf("failed to list users: %w", err)
		}
		result.Users = make([]*protopb.User, len(users))
		for i, user := range users {
			result.Users[i] = user.ToPb()
		}
	}
	return result, nil
}
