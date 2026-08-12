package middleware

import (
	"context"
	"errors"
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
	dbCtxKey     = "dbCtxKey"
	configCtxKey = "configCtxKey"
	smtpCtxKey   = "smtpCtxKey"
	claimCtxKey  = "claimCtxKey"
	authCtxKey   = "authCtxKey"
	appCtxKey    = "appCtxKey"
)

type AppContext struct {
	DB     store.DB
	Config config.Config
	SMTP   mail.MailClient
	Auth   *webauthn.WebAuthn
}

/*
func WithDB(db store.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), dbCtxKey, db)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
func GetDB(ctx context.Context) (store.DB, error) {
	store, ok := ctx.Value(dbCtxKey).(store.DB)
	if !ok {
		//
	}

	return store, nil
}
func WithConfig(conf config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), configCtxKey, conf)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
func GetConfig(ctx context.Context) (config.Config, error) {
	conf, ok := ctx.Value(configCtxKey).(config.Config)
	if !ok {
		//
	}

	return conf, nil
}
func WithSMTP(mailClient smtp.MailClient) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), smtpCtxKey, mailClient)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
func GetSMTP(ctx context.Context) (smtp.MailClient, error) {
	mailclient, ok := ctx.Value(smtpCtxKey).(smtp.MailClient)
	if !ok {
		//
	}

	return mailclient, nil
}
*/

func WithAppContext(db store.DB, conf config.Config, mailClient mail.MailClient, webauth *webauthn.WebAuthn) func(http.Handler) http.Handler {
	app := AppContext{
		DB:     db,
		Config: conf,
		SMTP:   mailClient,
		Auth:   webauth,
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), appCtxKey, app)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func GetAppContext(ctx context.Context) (AppContext, error) {
	app, ok := ctx.Value(appCtxKey).(AppContext)
	if !ok {
		return AppContext{}, errors.New("app context not found")
	}
	return app, nil
}

func Admin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		appContext, err := GetAppContext(r.Context())
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		claim, err := GetClaim(r.Context())
		if err != nil {
			http.Error(w, "cant get claim", http.StatusUnauthorized)
			return
		}

		userService := service.NewUser(appContext.DB, appContext.Config)

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

func Authorization(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		appContext, err := GetAppContext(r.Context())
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		cookie, err := r.Cookie("authorization")
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		c, err := token.VerifyToken(cookie.Value, appContext.Config.Secret)
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
