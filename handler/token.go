package handler

import (
	errormsg "go/playground/error_msg"
	"go/playground/middleware"
	"go/playground/service"
	"net/http"

	"github.com/go-chi/chi/v5"
)

func HandleVerifyToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	app, err := middleware.GetAppContext(r.Context())
	if err != nil {
		errormsg.AppContextErr(w, err)
		return
	}

	db := app.DB
	cfg := app.Config

	verifyToken := chi.URLParam(r, "token")
	v := service.NewVerification(db, cfg)
	err = v.VerifyEmail(ctx, verifyToken)
	if err != nil {
		errormsg.VerifyErr(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
