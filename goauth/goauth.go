package goauth

import (
	"database/sql"

	"github.com/FerberJ/goauth/api"
	"github.com/FerberJ/goauth/auth"
	"github.com/FerberJ/goauth/config"
	"github.com/FerberJ/goauth/mail"
	"github.com/FerberJ/goauth/store"

	"github.com/go-chi/chi/v5"
)

type Goauth struct {
	router chi.Router
	conf   config.Config
	err    error
}

func New(db *sql.DB) *Goauth {
	goauth := new(Goauth)

	conf, err := config.GetConf(db)

	//
	conf.SMTP.ResetPasswordMail = mail.ResetPasswordMail
	conf.SMTP.VerifyUserMail = mail.VerifyUserMail

	goauth.conf = conf
	goauth.err = err

	return goauth
}

func (a *Goauth) Err() error {
	return a.err
}
func (a *Goauth) Router() chi.Router {
	return a.router
}

func (a *Goauth) WithCustomResetPasswordMail(m func(cfgEndpoint string, token string) (message string, sunject string, err error)) *Goauth {
	a.conf.SMTP.ResetPasswordMail = m
	return a
}

func (a *Goauth) WithCustomVerifyUserMail(m func(cfgEndpoint string, token string) (message string, sunject string, err error)) *Goauth {
	a.conf.SMTP.VerifyUserMail = m
	return a
}

func (a *Goauth) SetupRoutes() *Goauth {
	st, err := store.Init(a.conf.DB)
	if err != nil {
		a.err = err
		return a
	}
	mailClient, err := mail.Init(a.conf.SMTP)
	if err != nil {
		a.err = err
		return a
	}
	wa, err := auth.Init()
	if err != nil {
		a.err = err
		return a
	}

	routes := api.GetRoutes(a.conf, st, mailClient, wa)

	a.router = routes

	return a
}
