package data

import (
	"fmt"

	"github.com/keratin/authn-server/app/data/postgres"

	"github.com/jmoiron/sqlx"
	"github.com/keratin/authn-server/app/data/mysql"
	"github.com/keratin/authn-server/app/data/sqlite3"
	"github.com/keratin/authn-server/app/models"
)

type AccountStore interface {
	Create(user struct {
		Username   string
		Password   []byte
		Name       string
		PictureURL string
	}) (*models.Account, error)
	Find(id int) (*models.Account, error)
	FindByUsername(u string) (*models.Account, error)
	FindByOauthAccount(p string, pid string) (*models.Account, error)
	AddOauthAccount(id int, p string, pid string, tok string) error
	GetOauthAccounts(id int) ([]*models.OauthAccount, error)
	Archive(id int) (bool, error)
	Lock(id int) (bool, error)
	Unlock(id int) (bool, error)
	RequireNewPassword(id int) (bool, error)
	SetPassword(id int, p []byte) (bool, error)
	UpdateUsername(id int, u string) (bool, error)
	SetLastLogin(id int) (bool, error)
}

func NewAccountStore(db sqlx.Ext) (AccountStore, error) {
	switch db.DriverName() {
	case "sqlite3":
		store := sqlite3.New(db)
		return &store, nil
	case "mysql":
		store := mysql.New(db)
		return &store, nil
	case "postgres":
		store := postgres.New(db)
		return &store, nil
	default:
		return nil, fmt.Errorf("unsupported driver: %v", db.DriverName())
	}
}
