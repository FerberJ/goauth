package loginfidopage

import (
	"github.com/FerberJ/goauth/middleware"
	"github.com/go-chi/chi/v5"
)

type Handler struct {
	r  chi.Router
	mw middleware.Middleware
}

func NewHandler(r chi.Router, mw middleware.Middleware) (h *Handler) {
	h = &Handler{
		r:  r,
		mw: mw,
	}

	h.addRoutes()

	return
}
