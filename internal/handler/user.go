package handler

import (
	"context"

	"github.com/poly-workshop/auth-portal/internal/service"
	protopb "github.com/poly-workshop/auth-portal/pkg/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

type UserHandler struct {
	userService service.UserService
	protopb.UnimplementedUserServiceServer
}

func NewUserHandler(userService service.UserService) *UserHandler {
	return &UserHandler{
		userService: userService,
	}
}

func (h *UserHandler) CreateUser(
	ctx context.Context,
	req *protopb.CreateUserRequest,
) (*emptypb.Empty, error) {
	err := h.userService.CreateUser(ctx, req)
	if err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (h *UserHandler) GetUser(
	ctx context.Context,
	req *protopb.GetUserRequest,
) (*protopb.User, error) {
	return h.userService.GetUser(ctx, req.Id)
}

func (h *UserHandler) UpdateUser(
	ctx context.Context,
	req *protopb.UpdateUserRequest,
) (*emptypb.Empty, error) {
	err := h.userService.UpdateUser(ctx, req)
	if err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (h *UserHandler) DeleteUser(
	ctx context.Context,
	req *protopb.DeleteUserRequest,
) (*emptypb.Empty, error) {
	err := h.userService.DeleteUser(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (h *UserHandler) ListUsers(
	ctx context.Context,
	req *protopb.ListUsersRequest,
) (*protopb.ListUsersResponse, error) {
	resp, err := h.userService.ListUsers(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (h *UserHandler) GetCurrentUser(
	ctx context.Context,
	req *emptypb.Empty,
) (*protopb.User, error) {
	return h.userService.GetCurrentUser(ctx)
}
