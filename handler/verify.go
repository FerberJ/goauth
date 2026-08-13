package handler

import (
	"net/http"

	errormsg "github.com/FerberJ/goauth/error_msg"
	"github.com/FerberJ/goauth/service"

	"github.com/go-chi/chi/v5"
)

func (h Handler) HandleVerifyToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	db := h.db
	cfg := h.config

	verifyToken := chi.URLParam(r, "token")
	v := service.NewVerification(db, cfg)
	err := v.Verify(ctx, verifyToken)
	if err != nil {
		errormsg.VerifyErr(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
