package model

import (
	"time"

	"github.com/google/uuid"
	protopb "github.com/poly-workshop/auth-portal/pkg/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gorm.io/gorm"
)

type UserRole string

const (
	UserRoleUser  UserRole = "user"
	UserRoleAdmin UserRole = "admin"
)

func (role UserRole) ToPb() protopb.UserRole {
	switch role {
	case UserRoleUser:
		return protopb.UserRole_USER
	case UserRoleAdmin:
		return protopb.UserRole_ADMIN
	default:
		return protopb.UserRole_USER // Default to user if unknown
	}
}

func (role *UserRole) FromPb(pbRole protopb.UserRole) {
	switch pbRole {
	case protopb.UserRole_USER:
		*role = UserRoleUser
	case protopb.UserRole_ADMIN:
		*role = UserRoleAdmin
	default:
		*role = UserRoleUser // Default to user if unknown
	}
}

type UserModel struct {
	ID             string         `gorm:"type:varchar(36);primaryKey" json:"id"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`
	DeletedAt      gorm.DeletedAt `gorm:"index" json:"-"`
	Name           string         `gorm:"type:varchar(100);not null"             json:"name"`
	Email          string         `gorm:"type:varchar(255);uniqueIndex;not null" json:"email"`
	HashedPassword *string        `gorm:"column:hashed_password"                 json:"-"`
	GithubID       *string        `gorm:"column:github_id;unique"                json:"github_id"`
	LastLoginAt    *time.Time     `                                              json:"last_login_at"`
	Role           UserRole       `gorm:"type:varchar(20);default:'user'"        json:"role"`
}

func (UserModel) TableName() string {
	return "users"
}

// BeforeCreate generates a UUID for the user before creating
func (u *UserModel) BeforeCreate(tx *gorm.DB) error {
	if u.ID == "" {
		u.ID = uuid.New().String()
	}
	return nil
}

func (u *UserModel) ToPb() *protopb.User {
	return &protopb.User{
		Id:        u.ID,
		Name:      u.Name,
		Email:     u.Email,
		GithubId:  u.GithubID,
		Role:      u.Role.ToPb(),
		CreatedAt: timestamppb.New(u.CreatedAt),
		UpdatedAt: timestamppb.New(u.UpdatedAt),
	}
}

func (u *UserModel) UpdateFromPb(req *protopb.UpdateUserRequest) {
	if req.Name != nil {
		u.Name = *req.Name
	}
	if req.Email != nil {
		u.Email = *req.Email
	}
	if req.GithubId != nil {
		u.GithubID = req.GithubId
	}
	if req.Role != nil {
		u.Role.FromPb(*req.Role)
	}
}
