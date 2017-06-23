package identities

import (
	"crypto/rsa"
	"strconv"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/keratin/authn/config"
	"github.com/keratin/authn/data"
	"github.com/keratin/authn/models"
	"github.com/keratin/authn/tokens/sessions"
)

type Claims struct {
	AuthTime int64 `json:"auth_time"`
	jwt.StandardClaims
}

func (c *Claims) Sign(rsa_key *rsa.PrivateKey) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodRS256, c).SignedString(rsa_key)
}

func New(store data.RefreshTokenStore, cfg *config.Config, session *sessions.Claims) (*Claims, error) {
	account_id, err := store.Find(models.RefreshToken(session.Subject))
	if err != nil {
		return nil, err
	}

	return &Claims{
		AuthTime: session.IssuedAt,
		StandardClaims: jwt.StandardClaims{
			Issuer:    session.Issuer,
			Subject:   strconv.Itoa(account_id),
			Audience:  session.Azp,
			ExpiresAt: time.Now().Add(cfg.AccessTokenTTL).Unix(),
			IssuedAt:  time.Now().Unix(),
		},
	}, nil
}
