package api

import (
	"github.com/FerberJ/goauth/config"
	"github.com/FerberJ/goauth/handler"
	"github.com/FerberJ/goauth/mail"
	"github.com/FerberJ/goauth/middleware"
	"github.com/FerberJ/goauth/store"

	"github.com/go-chi/chi/v5"
	"github.com/go-webauthn/webauthn/webauthn"
)

func GetRoutes(config config.Config, db store.DB, mc mail.MailClient, wa *webauthn.WebAuthn) chi.Router {
	r := chi.NewRouter()

	mw := middleware.NewMiddleware(db, config, mc, wa)
	h := handler.NewHandler(db, config, mc, wa)

	r.Post("/signup", h.HandleSignup)
	r.Post("/signup/fido/begin", h.HandleBeginSignup)
	r.Post("/signup/fido/finish", h.HandleFinishSignup)

	r.Get("/verify/{token}", h.HandleVerifyToken)

	r.Post("/login", h.HandleLogin)
	r.Get("/login/fido/begin", h.HandleBeginLogin)
	r.Post("/login/fido/finish", h.HandleFinishLogin)

	r.Post("/logout", h.HandleLogout)

	r.Post("/refresh", h.HandleRefresh)

	r.Post("/password/forgot", h.HandleForgotPassword)
	r.Post("/password/reset", h.HandleResetPassword) // Need the token from /password/forgot

	m := r.With(mw.Authorization)

	m.Post("/profile/password/change", h.HandleChangePassword)

	m.Get("/profile/fido/begin", h.HandleBeginRegister)
	m.Post("/profile/fido/finish", h.HandleFinishRegister)
	m.Get("/profile", h.HandleProfile)
	m.Put("/profile", h.HandleProfileUpdate)
	m.Delete("/profile", h.HandleProfileDelete)
	m.Put("/profile/image", h.HandleSetProfileImage)
	m.Get("/profile/image", h.HandleGetProfileImage)

	a := m.With(mw.Admin)

	a.Post("/admin/users", h.HandleCreateUser)
	a.Get("/admin/users", h.HandleListUsers)
	a.Get("/admin/users/{id}", h.HandleGetUsers)
	a.Post("/admin/users/{id}/verify", h.HandleUserVerify)
	a.Put("/admin/users/{id}", h.HandleUserUpdate)
	a.Delete("/admin/users/{id}", h.HandleUserDelete)
	a.Put("/admin/users/{id}/image", h.HandleSetUserImage)
	a.Get("/admin/users/{id}/image", h.HandleGetUserImage)

	return r
}
