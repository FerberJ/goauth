package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/FerberJ/goauth/encryption"
	errormsg "github.com/FerberJ/goauth/error_msg"
	"github.com/FerberJ/goauth/models"
	"github.com/FerberJ/goauth/service"
)

func (h Handler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	loginRequest, err := getValidBody[models.LoginRequest](r)
	if err != nil {
		errormsg.DecodeErr(w, err)
		return
	}

	db := h.db
	cfg := h.config

	u := service.NewUser(db, cfg)
	user, err := u.GetFromMail(ctx, loginRequest.Email)
	if err != nil {
		errormsg.GetEntryErr(w, err)
		return
	}

	valid, err := encryption.CompareHash(user.Password, loginRequest.Password)
	if err != nil {
		errormsg.ValidatePasswordErr(w, err)
		return
	}
	if !valid {
		errormsg.ValidatePasswordErr(w, fmt.Errorf("password is not valid"))
		return
	}

	t, err := getTokens(ctx, user.ID, h)
	if err != nil {
		errormsg.GetTokenErr(w, err)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "authorization",
		Value:    t.JWT,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int((24 * time.Hour).Seconds()),
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh",
		Value:    t.Refresh,
		Path:     "/auth/refresh",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(h.config.Refresh.TokenTTL),
	})

	w.WriteHeader(http.StatusNoContent)
}

func (h Handler) HandleBeginLogin(w http.ResponseWriter, r *http.Request) {
	var user models.User
	ctx := r.Context()
	email := r.URL.Query().Get("email")

	db := h.db
	wa := h.auth
	cfg := h.config

	u := service.NewUser(db, cfg)

	user, err := u.GetFromMail(ctx, email)
	if err != nil {
		errormsg.GetEntryErr(w, err)
		return
	}

	credentials, err := user.BeginLogin(db, wa)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(credentials)
}

func (h Handler) HandleFinishLogin(w http.ResponseWriter, r *http.Request) {
	var user models.User
	ctx := r.Context()
	email := r.URL.Query().Get("email")

	db := h.db
	wa := h.auth
	cfg := h.config

	u := service.NewUser(db, cfg)
	user, err := u.GetFromMail(ctx, email)
	if err != nil {
		errormsg.GetEntryErr(w, err)
		return
	}

	err = user.FinishLogin(db, wa, r)
	if err != nil {
		errormsg.RequestErr(w, err)
		return
	}

	t, err := getTokens(ctx, user.ID, h)
	if err != nil {
		errormsg.GetTokenErr(w, err)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "authorization",
		Value:    t.JWT,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int((24 * time.Hour).Seconds()),
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh",
		Value:    t.Refresh,
		Path:     "/auth/refresh",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(h.config.Refresh.TokenTTL.Seconds()),
	})

	w.WriteHeader(http.StatusNoContent)
}
