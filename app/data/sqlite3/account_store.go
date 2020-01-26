package sqlite3

import (
	"database/sql"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/keratin/authn-server/app/models"
)

func New(db sqlx.Ext) accountStore {
	return accountStore{
		db,
	}
}

type accountStore struct {
	sqlx.Ext
}

func (db *accountStore) Find(id int) (*models.Account, error) {
	account := models.Account{}
	err := sqlx.Get(db, &account, "SELECT * FROM accounts WHERE id = ?", id)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	if account.DeletedAt != nil {
		account.Username = ""
		account.Picture = ""
		account.Name = ""
	}
	return &account, nil
}

func (db *accountStore) FindByUsername(u string) (*models.Account, error) {
	account := models.Account{}
	err := sqlx.Get(db, &account, "SELECT * FROM accounts WHERE username = ? AND deleted_at IS NULL", u)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return &account, nil
}

func (db *accountStore) FindByOauthAccount(provider string, providerID string) (*models.Account, error) {
	account := models.Account{}
	err := sqlx.Get(db, &account, "SELECT a.* FROM accounts a INNER JOIN oauth_accounts oa ON a.id = oa.account_id WHERE oa.provider = ? AND oa.provider_id = ?", provider, providerID)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return &account, nil
}

func (db *accountStore) Create(user struct {
	Username   string // must be set
	Password   []byte
	Name       string
	PictureURL string
}) (*models.Account, error) {
	now := time.Now()

	account := &models.Account{
		Username:          user.Username,
		Password:          user.Password,
		Name:              user.Name,
		Picture:           user.PictureURL,
		PasswordChangedAt: now,
		CreatedAt:         now,
		UpdatedAt:         now,
	}

	result, err := sqlx.NamedExec(db,
		"INSERT INTO accounts (username, password, name, picture, locked, require_new_password, password_changed_at, created_at, updated_at, last_login_at) VALUES (:username, :password, :name, :picture, :locked, :require_new_password, :password_changed_at, :created_at, :updated_at, :last_login_at)",
		account,
	)
	if err != nil {
		return nil, err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, err
	}
	account.ID = int(id)

	return account, nil
}

func (db *accountStore) AddOauthAccount(accountID int, provider string, providerID string, accessToken string) error {
	now := time.Now()

	_, err := sqlx.NamedExec(db, `
        INSERT INTO oauth_accounts (account_id, provider, provider_id, access_token, created_at, updated_at)
        VALUES (:account_id, :provider, :provider_id, :access_token, :created_at, :updated_at)
    `, map[string]interface{}{
		"account_id":   accountID,
		"provider":     provider,
		"provider_id":  providerID,
		"access_token": accessToken,
		"created_at":   now,
		"updated_at":   now,
	})
	return err
}

func (db *accountStore) GetOauthAccounts(accountID int) ([]*models.OauthAccount, error) {
	accounts := []*models.OauthAccount{}
	err := sqlx.Select(db, &accounts, `SELECT * FROM oauth_accounts WHERE account_id = ?`, accountID)
	return accounts, err
}

func (db *accountStore) Archive(id int) (bool, error) {
	_, err := db.Exec("DELETE FROM oauth_accounts WHERE account_id = ?", id)
	if err != nil {
		return false, err
	}
	result, err := db.Exec("UPDATE accounts SET username = '@'||HEX(RANDOMBLOB(16)), password = ?, deleted_at = ? WHERE id = ?", "", time.Now(), id)
	return ok(result, err)
}

func (db *accountStore) Lock(id int) (bool, error) {
	result, err := db.Exec("UPDATE accounts SET locked = ?, updated_at = ? WHERE id = ?", true, time.Now(), id)
	return ok(result, err)
}

func (db *accountStore) Unlock(id int) (bool, error) {
	result, err := db.Exec("UPDATE accounts SET locked = ?, updated_at = ? WHERE id = ?", false, time.Now(), id)
	return ok(result, err)
}

func (db *accountStore) RequireNewPassword(id int) (bool, error) {
	result, err := db.Exec("UPDATE accounts SET require_new_password = ?, updated_at = ? WHERE id = ?", true, time.Now(), id)
	return ok(result, err)
}

func (db *accountStore) SetPassword(id int, p []byte) (bool, error) {
	result, err := db.Exec("UPDATE accounts SET password = ?, require_new_password = ?, password_changed_at = ?, updated_at = ? WHERE id = ?", p, false, time.Now(), time.Now(), id)
	return ok(result, err)
}

func (db *accountStore) UpdateUsername(id int, u string) (bool, error) {
	result, err := db.Exec("UPDATE accounts SET username = ?, updated_at = ? WHERE id = ?", u, time.Now(), id)
	return ok(result, err)
}

func (db *accountStore) SetLastLogin(id int) (bool, error) {
	result, err := db.Exec("UPDATE accounts SET last_login_at = ? WHERE id = ?", time.Now(), id)
	return ok(result, err)
}

func ok(result sql.Result, err error) (bool, error) {
	if err != nil {
		return false, err
	}
	count, err := result.RowsAffected()
	return count > 0, err
}
