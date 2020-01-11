package oauth

import (
	"context"
	"encoding/json"
	"io/ioutil"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/facebook"
)

// NewFacebookProvider returns a AuthN integration for Facebook OAuth
func NewFacebookProvider(credentials *Credentials) *Provider {
	config := &oauth2.Config{
		ClientID:     credentials.ID,
		ClientSecret: credentials.Secret,
		Scopes:       []string{"email"},
		Endpoint:     facebook.Endpoint,
	}

	return &Provider{
		config: config,
		UserInfo: func(t *oauth2.Token) (*UserInfo, error) {
			client := config.Client(context.TODO(), t)
			resp, err := client.Get("https://graph.facebook.com/me?fields=id,name,email,picture.width(200).height(200)")
			if err != nil {
				return nil, err
			}
			defer resp.Body.Close()

			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				return nil, err
			}

			var fbUser struct {
				ID      string `json:"id"`
				Name    string `json:"name"`
				Email   string `json:"email"`
				Picture struct {
					Data struct {
						IsSilhouette bool   `json:"is_silhouette"`
						Url          string `json:"url"`
					} `json:"data"`
				} `json:"picture"`
			}
			err = json.Unmarshal(body, &fbUser)

			user := UserInfo{
				ID:      fbUser.ID,
				Email:   fbUser.Email,
				Name:    fbUser.Name,
				Picture: fbUser.Picture.Data.Url,
			}
			return &user, err
		},
	}
}
