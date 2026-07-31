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
	r.Get("/verify/{token}", handler.HandleVerifyToken)
	r.Post("/login", handler.HandleLogin)
	r.Post("/logout", handler.HandleLogout)
	r.Post("/refresh", handler.HandleRefresh)
	r.Post("/forgot-password", handler.HandleForgotPassword)
	r.Post("/change-password", handler.HandleResetPassword)

	r.Get("/fido/register/begin", handler.HandleBeginRegister)
	r.Post("/fido/register/finish", handler.HandleFinishRegister)
	r.Get("/fido/login/begin", handler.HandleBeginLogin)
	r.Post("/fido/login/finish", handler.HandleFinishLogin)

	m := r.With(middleware.Authorization)

	m.Get("/profile", handler.HandleProfile)
	m.Patch("/profile/name", handler.HandleChangeName)

	return r
}
