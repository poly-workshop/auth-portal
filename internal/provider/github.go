package provider

import (
	"context"
	"fmt"

	"github.com/google/go-github/v73/github"
)

type GitHubProvider struct{}

func (g *GitHubProvider) GetUserInfo(ctx context.Context, token string) (UserInfo, error) {
	client := github.NewClient(nil).WithAuthToken(token)
	user, _, err := client.Users.Get(ctx, "")
	if err != nil {
		return UserInfo{}, err
	}
	return UserInfo{
		ID:        fmt.Sprintf("%d", user.GetID()),
		Name:      user.GetName(),
		Email:     user.GetEmail(),
		AvatarURL: user.GetAvatarURL(),
	}, nil
}
