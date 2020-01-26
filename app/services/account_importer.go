package services

import (
	"regexp"

	"golang.org/x/crypto/bcrypt"

	"github.com/keratin/authn-server/app"
	"github.com/keratin/authn-server/app/data"
	"github.com/keratin/authn-server/app/models"
	"github.com/pkg/errors"
)

var bcryptPattern = regexp.MustCompile(`\A\$2[ayb]\$[0-9]{2}\$[A-Za-z0-9\.\/]{53}\z`)

func AccountImporter(store data.AccountStore, cfg *app.Config, user User, locked bool) (*models.Account, error) {
	if user.Username == "" {
		return nil, FieldErrors{{"username", ErrMissing}}
	}
	if string(user.Password) == "" {
		return nil, FieldErrors{{"password", ErrMissing}}
	}

	var hash []byte
	var err error
	if bcryptPattern.Match(user.Password) {
		hash = user.Password
	} else {
		hash, err = bcrypt.GenerateFromPassword(user.Password, cfg.BcryptCost)
		if err != nil {
			return nil, errors.Wrap(err, "bcrypt")
		}
	}

	newUser := user
	newUser.Password = hash
	acc, err := store.Create(newUser)
	if err != nil {
		if data.IsUniquenessError(err) {
			return nil, FieldErrors{{"username", ErrTaken}}
		}

		return nil, errors.Wrap(err, "Create")
	}

	if locked {
		acc.Locked = true
		_, err := store.Lock(acc.ID)
		if err != nil {
			return nil, errors.Wrap(err, "Lock")
		}
	}

	return acc, nil
}
