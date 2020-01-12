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
		acct, err := store.Create("linked@test.com", []byte("password"), "", "")
		require.NoError(t, err)
		err = store.AddOauthAccount(acct.ID, "testProvider", "123", "TOKEN")
		require.NoError(t, err)

		found, err := services.IdentityReconciler(store, cfg, "testProvider", &oauth.UserInfo{ID: "123", Email: "linked@test.com", Name: "New Name", Picture: "newPicture"}, &oauth2.Token{}, 0)
		assert.NoError(t, err)
		if assert.NotNil(t, found) {
			assert.Equal(t, found.Username, "linked@test.com")
			assert.Equal(t, found.Name, "New Name")
			assert.Equal(t, found.Picture, "newPicture")

		}
	})

	t.Run("linked account should maintain old name", func(t *testing.T) {
		acct, err := store.Create("linked@test.com", []byte("password"), "Old Name", "oldPic")
		require.NoError(t, err)
		err = store.AddOauthAccount(acct.ID, "testProvider", "123", "TOKEN")
		require.NoError(t, err)

		found, err := services.IdentityReconciler(store, cfg, "testProvider", &oauth.UserInfo{ID: "123", Email: "linked@test.com", Name: "New Name", Picture: "newPicture"}, &oauth2.Token{}, 0)
		assert.NoError(t, err)
		if assert.NotNil(t, found) {
			assert.Equal(t, found.Username, "linked@test.com")
			assert.Equal(t, found.Name, "Old Name")
			assert.Equal(t, found.Picture, "oldPic")
		}
	})

	t.Run("linked account that is locked", func(t *testing.T) {
		acct, err := store.Create("linkedlocked@test.com", []byte("password"), "", "")
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
		acct, err := store.Create("linkable@test.com", []byte("password"), "", "")
		require.NoError(t, err)

		found, err := services.IdentityReconciler(store, cfg, "testProvider", &oauth.UserInfo{ID: "345", Email: "linkable@test.com", Name: "New Name", Picture: "newPic"}, &oauth2.Token{}, acct.ID)
		assert.NoError(t, err)
		if assert.NotNil(t, found) {
			assert.Equal(t, found.Username, "linkable@test.com")
			assert.Equal(t, found.Name, "New Name")
			assert.Equal(t, found.Picture, "newPic")
		}
	})

	t.Run("linkable account maintains old name", func(t *testing.T) {
		acct, err := store.Create("linkable@test.com", []byte("password"), "Old Name", "oldPic")
		require.NoError(t, err)

		found, err := services.IdentityReconciler(store, cfg, "testProvider", &oauth.UserInfo{ID: "345", Email: "linkable@test.com", Name: "New Name", Picture: "newPic"}, &oauth2.Token{}, acct.ID)
		assert.NoError(t, err)
		if assert.NotNil(t, found) {
			assert.Equal(t, found.Username, "linkable@test.com")
			assert.Equal(t, found.Name, "Old Name")
			assert.Equal(t, found.Picture, "oldPic")
		}
	})

	t.Run("linkable account that is linked", func(t *testing.T) {
		acct, err := store.Create("linkablelinked@test.com", []byte("password"), "", "")
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
			assert.Equal(t, found.Username, "new@test.com")
		}
	})

	t.Run("new account with username collision", func(t *testing.T) {
		_, err := store.Create("existing@test.com", []byte("password"), "", "")
		require.NoError(t, err)

		found, err := services.IdentityReconciler(store, cfg, "testProvider", &oauth.UserInfo{ID: "678", Email: "existing@test.com"}, &oauth2.Token{}, 0)
		assert.Error(t, err)
		assert.Nil(t, found)
	})
}
