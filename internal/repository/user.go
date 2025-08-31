package repository

import (
	"context"
	"log/slog"

	"github.com/poly-workshop/auth-portal/internal/model"
	"gorm.io/gorm"
)

type UserRepository interface {
	Create(ctx context.Context, user *model.UserModel) error
	GetByID(ctx context.Context, id string) (*model.UserModel, error)
	GetByEmail(ctx context.Context, email string) (*model.UserModel, error)
	GetByGithubID(ctx context.Context, githubID string) (*model.UserModel, error)
	Update(ctx context.Context, user *model.UserModel) error
	Delete(ctx context.Context, id string) error
	List(ctx context.Context, offset, limit int) ([]*model.UserModel, error)
	Count(ctx context.Context) (int64, error)
}

type userRepository struct {
	db *gorm.DB
}

func NewUserRepository(db *gorm.DB) UserRepository {
	return &userRepository{db: db}
}

func (r *userRepository) Create(ctx context.Context, user *model.UserModel) error {
	err := r.db.WithContext(ctx).Create(user).Error
	if err != nil {
		slog.ErrorContext(ctx, "failed to create user", "error", err, "email", user.Email)
		return err
	}
	slog.InfoContext(
		ctx,
		"user created successfully",
		"user_id",
		user.ID,
		"email",
		user.Email,
		"role",
		user.Role,
	)
	return nil
}

func (r *userRepository) GetByID(ctx context.Context, id string) (*model.UserModel, error) {
	var user model.UserModel
	err := r.db.WithContext(ctx).Where("id = ?", id).First(&user).Error
	if err != nil {
		slog.ErrorContext(ctx, "failed to get user by ID", "error", err, "user_id", id)
		return nil, err
	}
	slog.DebugContext(ctx, "user retrieved successfully", "user_id", user.ID, "email", user.Email)
	return &user, nil
}

func (r *userRepository) GetByEmail(ctx context.Context, email string) (*model.UserModel, error) {
	var user model.UserModel
	err := r.db.WithContext(ctx).Where("email = ?", email).First(&user).Error
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *userRepository) GetByGithubID(
	ctx context.Context,
	githubID string,
) (*model.UserModel, error) {
	var user model.UserModel
	err := r.db.WithContext(ctx).Where("github_id = ?", githubID).First(&user).Error
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *userRepository) Update(ctx context.Context, user *model.UserModel) error {
	err := r.db.WithContext(ctx).Save(user).Error
	if err != nil {
		slog.ErrorContext(ctx, "failed to update user", "error", err, "user_id", user.ID)
		return err
	}
	slog.DebugContext(ctx, "user updated successfully", "user_id", user.ID, "email", user.Email)
	return nil
}

func (r *userRepository) Delete(ctx context.Context, id string) error {
	return r.db.WithContext(ctx).Where("id = ?", id).Delete(&model.UserModel{}).Error
}

func (r *userRepository) List(ctx context.Context, offset, limit int) ([]*model.UserModel, error) {
	var users []*model.UserModel
	err := r.db.WithContext(ctx).Offset(offset).Limit(limit).Find(&users).Error
	if err != nil {
		slog.ErrorContext(
			ctx,
			"failed to list users",
			"error",
			err,
			"offset",
			offset,
			"limit",
			limit,
		)
		return nil, err
	}
	slog.DebugContext(
		ctx,
		"users listed successfully",
		"count",
		len(users),
		"offset",
		offset,
		"limit",
		limit,
	)
	return users, nil
}

func (r *userRepository) Count(ctx context.Context) (int64, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(&model.UserModel{}).Count(&count).Error
	if err != nil {
		return 0, err
	}
	return count, nil
}
