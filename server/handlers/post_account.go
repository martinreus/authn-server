package handlers

import (
	"net/http"

	"github.com/keratin/authn-server/app"
	"github.com/keratin/authn-server/app/services"
	"github.com/keratin/authn-server/lib/route"
	"github.com/keratin/authn-server/server/sessions"
)

func PostAccount(app *app.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Create the account
		account, err := services.AccountCreator(
			app.AccountStore,
			app.Config, services.User{
				Username:   r.FormValue("username"),
				Password:   []byte(r.FormValue("password")),
				Name:       r.FormValue("name"),
				PictureURL: r.FormValue("pictureURL"),
			})
		if err != nil {
			if fe, ok := err.(services.FieldErrors); ok {
				WriteErrors(w, fe)
				return
			}

			panic(err)
		}

		sessionToken, identityToken, err := services.SessionCreator(
			app.AccountStore, app.RefreshTokenStore, app.KeyStore, app.Actives, app.Config, app.Reporter,
			account.ID, route.MatchedDomain(r), sessions.GetRefreshToken(r),
		)
		if err != nil {
			panic(err)
		}

		// Return the signed session in a cookie
		sessions.Set(app.Config, w, sessionToken)

		// Return the signed identity token in the body
		WriteData(w, http.StatusCreated, map[string]string{
			"id_token": identityToken,
		})
	}
}
