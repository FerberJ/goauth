package api

import (
	"go/playground/config"
	"go/playground/handler"
	"go/playground/middleware"
	"go/playground/smtp"
	"go/playground/store"

	"github.com/go-chi/chi"
)

func GetRoutes(config config.Config, db store.DB, mailClient smtp.MailClient) chi.Router {
	r := chi.NewRouter().
		With(middleware.WithAppContext(db, config, mailClient))

	r.Post("/signup", handler.HandleSignup)
	r.Post("/verify/{token}", auth.handleVerifyToken)
	r.Post("/login", auth.handleLogin)

	m := r.With(middleware.Authorization)

	m.Get("/profile", handler.HandleProfile)
	m.Patch("/profile/name", handler.HandleChangeName)

	return r
}
