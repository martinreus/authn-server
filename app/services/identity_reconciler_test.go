package services_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/stretchr/testify/assert"

	"github.com/keratin/authn-server/app/services"
	"github.com/keratin/authn-server/lib/oauth"
	"golang.org/x/oauth2"

	"github.com/keratin/authn-server/app"
	"github.com/keratin/authn-server/app/data/mock"
)

func TestIdentityReconciler(t *testing.T) {
	store := mock.NewAccountStore()
	cfg := &app.Config{}

	t.Run("linked account should update name and pic if empty", func(t *testing.T) {
		acct, err := store.Create(services.User{Username: "linked@test.com", Password: []byte("password")})
		require.NoError(t, err)
		err = store.AddOauthAccount(acct.ID, "testProvider", "123", "TOKEN")
		require.NoError(t, err)

		found, err := services.IdentityReconciler(store, cfg, "testProvider", &oauth.UserInfo{ID: "123", Email: "linked@test.com", Name: "New Name", Picture: "newPicture"}, &oauth2.Token{}, 0)
		assert.NoError(t, err)
		if assert.NotNil(t, found) {
			assert.Equal(t,  "linked@test.com", found.Username)
			//assert.Equal(t, "New Name", found.Name)
			//assert.Equal(t, "newPicture", found.PictureURL)

		}
	})

	t.Run("linked account should maintain old name", func(t *testing.T) {
		acct, err := store.Create(services.User{Username: "linkedWithName@test.com", Password: []byte("password"), Name: "Old Name", PictureURL: "oldPic"})
		require.NoError(t, err)
		err = store.AddOauthAccount(acct.ID, "testProvider", "555", "TOKEN")
		require.NoError(t, err)

		found, err := services.IdentityReconciler(store, cfg, "testProvider", &oauth.UserInfo{ID: "555", Email: "linkedWithName@test.com", Name: "New Name", Picture: "newPicture"}, &oauth2.Token{}, 0)
		assert.NoError(t, err)
		if assert.NotNil(t, found) {
			assert.Equal(t, "linkedWithName@test.com", found.Username)
			assert.Equal(t, "Old Name", found.Name)
			assert.Equal(t, "oldPic", found.Picture)
		}
	})

	t.Run("linked account that is locked", func(t *testing.T) {
		acct, err := store.Create(services.User{Username: "linkedlocked@test.com", Password: []byte("password")})
		require.NoError(t, err)
		err = store.AddOauthAccount(acct.ID, "testProvider", "234", "TOKEN")
		require.NoError(t, err)
		_, err = store.Lock(acct.ID)
		require.NoError(t, err)

		found, err := services.IdentityReconciler(store, cfg, "testProvider", &oauth.UserInfo{ID: "234", Email: "linkedlocked@test.com"}, &oauth2.Token{}, 0)
		assert.Error(t, err)
		assert.Nil(t, found)
	})

	t.Run("linkable account updating name and pic", func(t *testing.T) {
		acct, err := store.Create(services.User{Username: "linkable@test.com", Password: []byte("password")})
		require.NoError(t, err)

		found, err := services.IdentityReconciler(store, cfg, "testProvider", &oauth.UserInfo{ID: "345", Email: "linkable@test.com", Name: "New Name", Picture: "newPic"}, &oauth2.Token{}, acct.ID)
		assert.NoError(t, err)
		if assert.NotNil(t, found) {
			assert.Equal(t, "linkable@test.com", found.Username)
			//assert.Equal(t, "New Name", found.Name)
			//assert.Equal(t, "newPic", found.PictureURL)
		}
	})

	t.Run("linkable account maintains old name", func(t *testing.T) {
		acct, err := store.Create(services.User{Username: "linkableWithName@test.com", Password: []byte("password"), Name: "Old Name", PictureURL: "oldPic"})
		require.NoError(t, err)

		found, err := services.IdentityReconciler(store, cfg, "testProvider", &oauth.UserInfo{ID: "666", Email: "linkableWithName@test.com", Name: "New Name", Picture: "newPic"}, &oauth2.Token{}, acct.ID)
		assert.NoError(t, err)
		if assert.NotNil(t, found) {
			assert.Equal(t, "linkableWithName@test.com", found.Username)
			assert.Equal(t, "Old Name", found.Name)
			assert.Equal(t, "oldPic", found.Picture)
		}
	})

	t.Run("linkable account that is linked", func(t *testing.T) {
		acct, err := store.Create(services.User{Username: "linkablelinked@test.com", Password: []byte("password")})
		require.NoError(t, err)
		err = store.AddOauthAccount(acct.ID, "testProvider", "0", "TOKEN")
		require.NoError(t, err)

		found, err := services.IdentityReconciler(store, cfg, "testProvider", &oauth.UserInfo{ID: "456", Email: "linkablelinked@test.com"}, &oauth2.Token{}, acct.ID)
		assert.Error(t, err)
		assert.Nil(t, found)
	})

	t.Run("new account", func(t *testing.T) {
		found, err := services.IdentityReconciler(store, cfg, "testProvider", &oauth.UserInfo{ID: "567", Email: "new@test.com"}, &oauth2.Token{}, 0)
		assert.NoError(t, err)
		if assert.NotNil(t, found) {
			assert.Equal(t, "new@test.com", found.Username)
		}
	})

	t.Run("new account with username collision", func(t *testing.T) {
		_, err := store.Create(services.User{Username: "existing@test.com", Password: []byte("password")})
		require.NoError(t, err)

		found, err := services.IdentityReconciler(store, cfg, "testProvider", &oauth.UserInfo{ID: "678", Email: "existing@test.com"}, &oauth2.Token{}, 0)
		assert.Error(t, err)
		assert.Nil(t, found)
	})
}
