package service

import (
	"context"
	"fmt"

	"github.com/poly-workshop/auth-portal/internal/model"
	"github.com/poly-workshop/auth-portal/internal/repository"
	"github.com/poly-workshop/auth-portal/pkg/auth"
	"github.com/poly-workshop/auth-portal/pkg/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

type UserService interface {
	CreateUser(ctx context.Context, req *proto.CreateUserRequest) (*emptypb.Empty, error)
	GetUser(ctx context.Context, req *proto.GetUserRequest) (*proto.User, error)
	UpdateUser(ctx context.Context, req *proto.UpdateUserRequest) (*emptypb.Empty, error)
	DeleteUser(ctx context.Context, req *proto.DeleteUserRequest) (*emptypb.Empty, error)
	ListUsers(ctx context.Context, req *proto.ListUsersRequest) (*proto.ListUsersResponse, error)
	GetCurrentUser(ctx context.Context, req *emptypb.Empty) (*proto.User, error)
}

type userService struct {
	userRepo repository.UserRepository
	proto.UnimplementedUserServiceServer
}

func NewUserService(userRepo repository.UserRepository) proto.UserServiceServer {
	return &userService{
		userRepo: userRepo,
	}
}

func (s *userService) CreateUser(
	ctx context.Context,
	req *proto.CreateUserRequest,
) (*emptypb.Empty, error) {
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
	return &emptypb.Empty{}, nil
}

func (s *userService) GetUser(
	ctx context.Context,
	req *proto.GetUserRequest,
) (*proto.User, error) {
	user, err := s.userRepo.GetByID(ctx, req.Id)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	return user.ToPb(), nil
}

func (s *userService) GetCurrentUser(
	ctx context.Context,
	req *emptypb.Empty,
) (*proto.User, error) {
	// Get user info from context (set by auth interceptor)
	userInfo, ok := ctx.Value(auth.ContextKeyUserInfo).(*auth.UserInfo)
	if !ok {
		return nil, fmt.Errorf("user info not found in context")
	}

	user, err := s.userRepo.GetByID(ctx, userInfo.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	return user.ToPb(), nil
}

func (s *userService) UpdateUser(
	ctx context.Context,
	req *proto.UpdateUserRequest,
) (*emptypb.Empty, error) {
	user, err := s.userRepo.GetByID(ctx, req.Id)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	user.UpdateFromPb(req)
	err = s.userRepo.Update(ctx, user)
	if err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (s *userService) DeleteUser(
	ctx context.Context,
	req *proto.DeleteUserRequest,
) (*emptypb.Empty, error) {
	err := s.userRepo.Delete(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (s *userService) ListUsers(
	ctx context.Context,
	req *proto.ListUsersRequest,
) (*proto.ListUsersResponse, error) {
	if req.Page < 1 {
		req.Page = 1
	}
	if req.PageSize < 1 {
		req.PageSize = 10 // Default page size
	}
	offset := int((req.Page - 1) * req.PageSize)
	limit := int(req.PageSize)

	result := &proto.ListUsersResponse{}
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
		result.Users = make([]*proto.User, len(users))
		for i, user := range users {
			result.Users[i] = user.ToPb()
		}
	}
	return result, nil
}
