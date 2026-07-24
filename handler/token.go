package handler

import (
	"go/playground/middleware"
	"go/playground/service"
	"net/http"

	"github.com/go-chi/chi/v5"
)

func HandleVerifyToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	app, err := middleware.GetAppContext(r.Context())
	if err != nil {
		//
	}

	db := app.DB
	cfg := app.Config

	verifyToken := chi.URLParam(r, "token")
	v := service.NewVerification(db, cfg)
	err = v.VerifyEmail(ctx, verifyToken)
	if err != nil {
		http.Error(w, "could not verify user", http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
