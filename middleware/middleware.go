package middleware

import (
	"context"
	"fmt"
	"net/http"

	"github.com/FerberJ/goauth/config"
	"github.com/FerberJ/goauth/mail"
	"github.com/FerberJ/goauth/service"
	"github.com/FerberJ/goauth/store"
	"github.com/FerberJ/goauth/token"

	"github.com/go-webauthn/webauthn/webauthn"
)

const (
	claimCtxKey = "claimCtxKey"
)

type Middleware struct {
	db     store.DB
	config config.Config
	smtp   mail.MailClient
	auth   *webauthn.WebAuthn
}

func NewMiddleware(db store.DB, conf config.Config, mailClient mail.MailClient, webauth *webauthn.WebAuthn) Middleware {
	return Middleware{
		db:     db,
		config: conf,
		smtp:   mailClient,
		auth:   webauth,
	}
}

func (mw Middleware) Admin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claim, err := GetClaim(r.Context())
		if err != nil {
			http.Error(w, "cant get claim", http.StatusUnauthorized)
			return
		}

		userService := service.NewUser(mw.db, mw.config)

		user, err := userService.Get(r.Context(), claim.UserID)
		if err != nil {
			http.Error(w, "cant get user", http.StatusBadRequest)
			return
		}

		if !user.Admin {
			http.Error(w, "user is not admin", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(r.Context()))
	})
}

func (mw Middleware) Authorization(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("authorization")
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		c, err := token.VerifyToken(cookie.Value, mw.config.Secret)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), claimCtxKey, c)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func GetClaim(ctx context.Context) (*token.Claims, error) {
	claim, ok := ctx.Value(claimCtxKey).(*token.Claims)
	if !ok {
		return nil, fmt.Errorf("could not recieve claim")
	}

	return claim, nil
}
