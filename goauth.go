package goauth

import (
	"database/sql"
	"net/http"

	"github.com/FerberJ/goauth/api"
	"github.com/FerberJ/goauth/auth"
	"github.com/FerberJ/goauth/config"
	"github.com/FerberJ/goauth/mail"
	"github.com/FerberJ/goauth/middleware"
	"github.com/FerberJ/goauth/store"

	"github.com/go-chi/chi/v5"
)

type Goauth struct {
	r   chi.Router
	cfg config.Config
	err error
	mw  middleware.Middleware
}

func New(db *sql.DB) *Goauth {
	a := new(Goauth)

	cfg, err := config.GetConf(db)

	//
	cfg.SMTP.ResetPasswordMail = mail.ResetPasswordMail
	cfg.SMTP.VerifyUserMail = mail.VerifyUserMail

	a.cfg = cfg
	a.err = err

	return a
}

func (a *Goauth) Err() error {
	return a.err
}
func (a *Goauth) Router() chi.Router {
	return a.r
}

func (a *Goauth) WithCustomResetPasswordMail(m func(cfgEndpoint string, token string) (message string, sunject string, err error)) *Goauth {
	a.cfg.SMTP.ResetPasswordMail = m
	return a
}

func (a *Goauth) WithCustomVerifyUserMail(m func(cfgEndpoint string, token string) (message string, sunject string, err error)) *Goauth {
	a.cfg.SMTP.VerifyUserMail = m
	return a
}

// func(next http.Handler) http.Handler
func (a *Goauth) Admin(next http.Handler) http.Handler {
	return a.mw.Admin(next)
}

func (a *Goauth) Authorization(next http.Handler) http.Handler {
	return a.mw.Authorization(next)
}

func (a *Goauth) SetupRoutes() *Goauth {
	st, err := store.Init(a.cfg.DB)
	if err != nil {
		a.err = err
		return a
	}
	mailClient, err := mail.Init(a.cfg.SMTP)
	if err != nil {
		a.err = err
		return a
	}
	wa, err := auth.Init()
	if err != nil {
		a.err = err
		return a
	}
	a.mw = middleware.NewMiddleware(st, a.cfg, mailClient, wa)

	routes := api.GetRoutes(a.cfg, st, mailClient, wa)

	a.r = routes

	return a
}
