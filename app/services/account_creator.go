package services

import (
	"strings"

	"github.com/keratin/authn-server/app"
	"github.com/keratin/authn-server/app/data"
	"github.com/keratin/authn-server/app/models"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

func AccountCreator(store data.AccountStore, cfg *app.Config, user User) (*models.Account, error) {
	username := strings.TrimSpace(user.Username)

	errs := FieldErrors{}

	fieldError := UsernameValidator(cfg, username)
	if fieldError != nil {
		errs = append(errs, *fieldError)
	}

	fieldError = PasswordValidator(cfg, string(user.Password))
	if fieldError != nil {
		errs = append(errs, *fieldError)
	}

	if len(errs) > 0 {
		return nil, errs
	}

	hash, err := bcrypt.GenerateFromPassword(user.Password, cfg.BcryptCost)
	if err != nil {
		return nil, errors.Wrap(err, "bcrypt")
	}

	acc, err := store.Create(User{Username: username, Password: hash, Name: user.Name, PictureURL: user.PictureURL})

	if err != nil {
		if data.IsUniquenessError(err) {
			return nil, FieldErrors{{"username", ErrTaken}}
		}

		return nil, errors.Wrap(err, "Create")
	}

	return acc, nil
}
