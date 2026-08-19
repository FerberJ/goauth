package goauth

import (
	"database/sql"
	"net/http"

	"github.com/FerberJ/goauth/api"
	"github.com/FerberJ/goauth/auth"
	"github.com/FerberJ/goauth/config"
	"github.com/FerberJ/goauth/frontend/components/loginform"
	signupform "github.com/FerberJ/goauth/frontend/components/signup"
	"github.com/FerberJ/goauth/mail"
	"github.com/FerberJ/goauth/middleware"
	"github.com/FerberJ/goauth/store"
	"github.com/a-h/templ"

	"github.com/go-chi/chi/v5"
)

type Goauth struct {
	cfg     config.Config
	err     error
	mw      middleware.Middleware
	pattern string
}

func New(db *sql.DB) *Goauth {
	a := new(Goauth)
	a.pattern = "/auth"

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

func (a *Goauth) WithPattern(pattern string) *Goauth {
	a.pattern = pattern
	return a
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

func (a *Goauth) GetLoginForm() templ.Component {
	return loginform.LoginForm()
}

func (a *Goauth) GetSignupForm() templ.Component {
	return signupform.SignupForm()
}

func (a *Goauth) GetRoutes(r *chi.Mux) error {
	st, err := store.Init(a.cfg.DB)
	if err != nil {
		return err
	}
	mailClient, err := mail.Init(a.cfg.SMTP)
	if err != nil {
		return err
	}
	wa, err := auth.Init()
	if err != nil {
		return err
	}
	a.mw = middleware.NewMiddleware(st, a.cfg, mailClient, wa)

	routes := api.GetRoutes(a.cfg, st, mailClient, wa, a.pattern)

	r.Mount(a.pattern, routes)

	return nil
}
