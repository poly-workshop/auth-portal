package service

import (
	"context"
	"fmt"

	user_v1_pb "github.com/poly-workshop/auth-portal/gen/user/v1"
	"github.com/poly-workshop/auth-portal/internal/model"
	"github.com/poly-workshop/auth-portal/internal/repository"
	"github.com/poly-workshop/auth-portal/pkg/auth"
)

type UserService interface {
	CreateUser(ctx context.Context, req *user_v1_pb.CreateUserRequest) (*user_v1_pb.CreateUserResponse, error)
	GetUser(ctx context.Context, req *user_v1_pb.GetUserRequest) (*user_v1_pb.GetCurrentUserResponse, error)
	UpdateUser(ctx context.Context, req *user_v1_pb.UpdateUserRequest) (*user_v1_pb.UpdateUserResponse, error)
	DeleteUser(ctx context.Context, req *user_v1_pb.DeleteUserRequest) (*user_v1_pb.DeleteUserResponse, error)
	ListUsers(ctx context.Context, req *user_v1_pb.ListUsersRequest) (*user_v1_pb.ListUsersResponse, error)
	GetCurrentUser(ctx context.Context, req *user_v1_pb.GetCurrentUserRequest) (*user_v1_pb.GetCurrentUserResponse, error)
}

type userService struct {
	userRepo repository.UserRepository
	user_v1_pb.UnimplementedUserServiceServer
}

func NewUserService(userRepo repository.UserRepository) user_v1_pb.UserServiceServer {
	return &userService{
		userRepo: userRepo,
	}
}

func (s *userService) CreateUser(
	ctx context.Context,
	req *user_v1_pb.CreateUserRequest,
) (*user_v1_pb.CreateUserResponse, error) {
	user := &model.UserModel{
		Name:     req.Name,
		Email:    req.Email,
		GithubID: req.GithubId,
	}
	user.Role.FromPb(req.Role)

	err := s.userRepo.Create(ctx, user)
	if err != nil {
		return nil, err
	}
	return &user_v1_pb.CreateUserResponse{}, nil
}

func (s *userService) GetUser(
	ctx context.Context,
	req *user_v1_pb.GetUserRequest,
) (*user_v1_pb.GetUserResponse, error) {
	user, err := s.userRepo.GetByID(ctx, req.Id)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	return &user_v1_pb.GetUserResponse{
		User: user.ToPb(),
	}, nil
}

func (s *userService) GetCurrentUser(
	ctx context.Context,
	req *user_v1_pb.GetCurrentUserRequest,
) (*user_v1_pb.GetCurrentUserResponse, error) {
	// Get user info from context (set by auth interceptor)
	userInfo, ok := ctx.Value(auth.ContextKeyUserInfo).(*auth.UserInfo)
	if !ok {
		return nil, fmt.Errorf("user info not found in context")
	}

	user, err := s.userRepo.GetByID(ctx, userInfo.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	return &user_v1_pb.GetCurrentUserResponse{
		User: user.ToPb(),
	}, nil
}

func (s *userService) UpdateUser(
	ctx context.Context,
	req *user_v1_pb.UpdateUserRequest,
) (*user_v1_pb.UpdateUserResponse, error) {
	user, err := s.userRepo.GetByID(ctx, req.Id)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	user.UpdateFromPb(req)
	err = s.userRepo.Update(ctx, user)
	if err != nil {
		return nil, err
	}
	return &user_v1_pb.UpdateUserResponse{}, nil
}

func (s *userService) DeleteUser(
	ctx context.Context,
	req *user_v1_pb.DeleteUserRequest,
) (*user_v1_pb.DeleteUserResponse, error) {
	err := s.userRepo.Delete(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return &user_v1_pb.DeleteUserResponse{}, nil
}

func (s *userService) ListUsers(
	ctx context.Context,
	req *user_v1_pb.ListUsersRequest,
) (*user_v1_pb.ListUsersResponse, error) {
	if req.Page < 1 {
		req.Page = 1
	}
	if req.PageSize < 1 {
		req.PageSize = 10 // Default page size
	}
	offset := int((req.Page - 1) * req.PageSize)
	limit := int(req.PageSize)

	result := &user_v1_pb.ListUsersResponse{}
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
		result.Users = make([]*user_v1_pb.User, len(users))
		for i, user := range users {
			result.Users[i] = user.ToPb()
		}
	}
	return result, nil
}
