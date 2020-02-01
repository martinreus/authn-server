package oauth

import (
	"context"
	"encoding/json"
	"io/ioutil"

	"golang.org/x/oauth2"
)

// NewDiscordProvider returns a AuthN integration for Discord OAuth
func NewDiscordProvider(credentials *Credentials) *Provider {
	config := &oauth2.Config{
		ClientID:     credentials.ID,
		ClientSecret: credentials.Secret,
		Scopes:       []string{"identify", "email"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://discordapp.com/api/oauth2/authorize",
			TokenURL: "https://discordapp.com/api/oauth2/token",
		},
	}

	return &Provider{
		config: config,
		UserInfo: func(t *oauth2.Token) (*UserInfo, error) {
			client := config.Client(context.TODO(), t)
			resp, err := client.Get("https://discordapp.com/api/users/@me")
			if err != nil {
				return nil, err
			}
			defer resp.Body.Close()

			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				return nil, err
			}

			var dUser struct{
				ID string `json:"id"`
				Username string `json:"username"`
				Email string `json:"email"`
				AvatarHash string `json:"avatar"`
			}

			err = json.Unmarshal(body, &dUser)

			user := UserInfo{
				ID:      dUser.ID,
				Email: dUser.Email,
				Name: dUser.Username,
				// avatar hash, need to check how to retrieve the proper link!?!
				// Discord documentation:
				// https://discordapp.com/developers/docs/resources/user#user-object
				//
				// PictureURL: "https://cdn.discordapp.com/avatars/" + dUser.ID + "/" + dUser.AvatarHash + ".png",
			}
			return &user, err
		},
	}
}
