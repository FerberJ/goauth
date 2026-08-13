package handler

import (
	"github.com/FerberJ/goauth/config"
	"github.com/FerberJ/goauth/mail"
	"github.com/FerberJ/goauth/store"
	"github.com/go-webauthn/webauthn/webauthn"
)

type Handler struct {
	db     store.DB
	config config.Config
	smtp   mail.MailClient
	auth   *webauthn.WebAuthn
}

func NewHandler(db store.DB, conf config.Config, mailClient mail.MailClient, webauth *webauthn.WebAuthn) Handler {
	return Handler{
		db:     db,
		config: conf,
		smtp:   mailClient,
		auth:   webauth,
	}
}
