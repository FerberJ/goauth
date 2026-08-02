package api

import (
	"go/playground/config"
	"go/playground/handler"
	"go/playground/mail"
	"go/playground/middleware"
	"go/playground/store"

	"github.com/go-chi/chi/v5"
	"github.com/go-webauthn/webauthn/webauthn"
)

func GetRoutes(config config.Config, db store.DB, mc mail.MailClient, wa *webauthn.WebAuthn) chi.Router {
	r := chi.NewRouter()

	r.Use(middleware.WithAppContext(db, config, mc, wa))

	r.Post("/signup", handler.HandleSignup)
	r.Post("/signup/fido/begin", handler.HandleBeginSignup)
	r.Post("/signup/fido/finish", handler.HandleFinishSignup)

	r.Get("/verify/{token}", handler.HandleVerifyToken)

	r.Post("/login", handler.HandleLogin)
	r.Get("/login/fido/begin", handler.HandleBeginLogin)
	r.Post("/login/fido/finish", handler.HandleFinishLogin)

	r.Post("/logout", handler.HandleLogout)

	r.Post("/refresh", handler.HandleRefresh)

	r.Post("/password/forgot", handler.HandleForgotPassword)
	r.Post("/password/reset", handler.HandleResetPassword) // Need the token from /password/forgot

	m := r.With(middleware.Authorization)

	m.Post("/password/change", handler.HandleChangePassword)

	m.Put("/profile/fido/begin", handler.HandleBeginRegister)
	m.Put("/profile/fido/finish", handler.HandleFinishRegister)
	m.Get("/profile", handler.HandleProfile)
	m.Patch("/profile/name", handler.HandleChangeName)

	return r
}
