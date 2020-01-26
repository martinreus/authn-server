package services_test

import (
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/keratin/authn-server/app"
	"github.com/keratin/authn-server/app/data/mock"
	"github.com/keratin/authn-server/app/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// it's a "secret"
var bcrypted = []byte("$2a$10$W5AiL6r4XBrZHc3NEcMUC.xj52oYl6YQw6YpTP1OkjFLmWfOk7oqC")

func TestAccountImporter(t *testing.T) {
	accountStore := mock.NewAccountStore()
	cfg := &app.Config{
		BcryptCost: 4,
	}

	_, err := accountStore.Create(services.User{Username: "existing", Password: []byte("secret"), Name: "A Name", PictureURL: "aPicURL"})
	require.NoError(t, err)

	testCases := []struct {
		username string
		password []byte
		name     string
		pic      string
		locked   bool
		errors   *services.FieldErrors
	}{
		{"unlocked", bcrypted, "", "", false, nil},
		{"with_name", bcrypted, "Someone van Surname", "http://not.valid/asdasd.png", false, nil},
		{"locked", bcrypted, "", "", true, nil},
		{"plaintext", []byte("secret"), "", "", false, nil},
		{"", bcrypted, "", "", false, &services.FieldErrors{{"username", services.ErrMissing}}},
		{"invalid", []byte(""), "", "", false, &services.FieldErrors{{"password", services.ErrMissing}}},
		{"existing", bcrypted, "", "", false, &services.FieldErrors{{"username", services.ErrTaken}}},
	}

	for _, tc := range testCases {
		account, errors := services.AccountImporter(accountStore, cfg, services.User{Username: tc.username, Password: tc.password, Name: tc.name, PictureURL: tc.pic}, tc.locked)
		if tc.errors == nil {
			assert.Empty(t, errors)
			assert.NotEmpty(t, account)
			assert.Equal(t, tc.locked, account.Locked)
			assert.Equal(t, tc.username, account.Username)
			assert.Equal(t, tc.name, account.Name)
			assert.Equal(t, tc.pic, account.Picture)
			assert.NoError(t, bcrypt.CompareHashAndPassword(account.Password, []byte("secret")))
		} else {
			assert.Equal(t, *tc.errors, errors)
			assert.Empty(t, account)
		}
	}
}
