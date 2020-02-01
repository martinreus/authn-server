package handlers

import (
	"github.com/keratin/authn-server/lib/parse"
	"net/http"
	"regexp"

	"github.com/keratin/authn-server/app"
	"github.com/keratin/authn-server/app/services"
)

func PostAccountsImport(app *app.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var user struct {
			Username   string
			Password   string
			Name       string
			PictureURL string
			Locked     string
		}
		if err := parse.Payload(r, &user); err != nil {
			WriteErrors(w, err)
			return
		}
		locked, err := regexp.MatchString("^(?i:t|true|yes)$", user.Locked)
		if err != nil {
			panic(err)
		}

		account, err := services.AccountImporter(
			app.AccountStore,
			app.Config,
			services.User{
				Username:   user.Username,
				Password:   []byte(user.Password),
				Name:       user.Name,
				PictureURL: user.PictureURL,
			},
			locked,
		)
		if err != nil {
			if fe, ok := err.(services.FieldErrors); ok {
				WriteErrors(w, fe)
				return
			}

			panic(err)
		}

		WriteData(w, http.StatusCreated, map[string]interface{}{
			"id":      account.ID,
			"name":    account.Name,
			"picture": account.Picture,
		})
	}
}
