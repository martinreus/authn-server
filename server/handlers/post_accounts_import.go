package handlers

import (
	"net/http"
	"regexp"

	"github.com/keratin/authn-server/app"
	"github.com/keratin/authn-server/app/services"
)

func PostAccountsImport(app *app.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		locked, err := regexp.MatchString("^(?i:t|true|yes)$", r.FormValue("locked"))
		if err != nil {
			panic(err)
		}

		account, err := services.AccountImporter(
			app.AccountStore,
			app.Config,
			services.User{
				Username:   r.FormValue("username"),
				Password:   []byte(r.FormValue("password")),
				Name:       r.FormValue("name"),
				PictureURL: r.FormValue("picture")},
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
