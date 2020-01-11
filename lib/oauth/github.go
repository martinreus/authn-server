package oauth

import (
	"context"
	"encoding/json"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"io/ioutil"
)

// NewGitHubProvider returns a AuthN integration for GitHub OAuth
func NewGitHubProvider(credentials *Credentials) *Provider {
	config := &oauth2.Config{
		ClientID:     credentials.ID,
		ClientSecret: credentials.Secret,
		Scopes:       []string{"user:email"},
		Endpoint:     github.Endpoint,
	}

	return &Provider{
		config: config,
		UserInfo: func(t *oauth2.Token) (*UserInfo, error) {
			client := config.Client(context.TODO(), t)
			resp, err := client.Get("https://api.github.com/user")
			if err != nil {
				return nil, err
			}
			defer resp.Body.Close()

			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				return nil, err
			}

			var user struct {
				ID     string `json:"id"`
				Name   string `json:"name"`
				Email  string `json:"email"`
				Avatar string `json:"avatar_url"`
			}

			err = json.Unmarshal(body, &user)
			if err != nil {
				return nil, err
			}

			return &UserInfo{
				ID:      user.ID,
				Email:   user.Email,
				Name:    user.Name,
				Picture: user.Avatar,
			}, nil
		},
	}
}
