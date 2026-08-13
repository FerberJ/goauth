package handler

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/FerberJ/goauth/encryption"
	errormsg "github.com/FerberJ/goauth/error_msg"
	"github.com/FerberJ/goauth/models"
	"github.com/FerberJ/goauth/store"
)

func (h Handler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	loginRequest, err := getValidBody[models.LoginRequest](r)
	if err != nil {
		errormsg.DecodeErr(w, err)
		return
	}

	db := h.db

	u, err := db.Queries.GetFromMail(ctx, loginRequest.Email)
	if err != nil {
		errormsg.GetEntryErr(w, err)
		return
	}

	if !u.PasswordHash.Valid {
		errormsg.ValidatePasswordErr(w, fmt.Errorf("password is not valid"))
	}
	valid, err := encryption.CompareHash(store.NullStringToString(u.PasswordHash), loginRequest.Password)
	if err != nil {
		errormsg.ValidatePasswordErr(w, err)
		return
	}
	if !valid {
		errormsg.ValidatePasswordErr(w, fmt.Errorf("password is not valid"))
		return
	}

	t, err := getTokens(ctx, u.ID, h)
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
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh",
		Value:    t.Refresh,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})

	w.WriteHeader(http.StatusNoContent)
}

func (h Handler) HandleBeginLogin(w http.ResponseWriter, r *http.Request) {
	var user models.User
	ctx := r.Context()
	email := r.URL.Query().Get("email")

	db := h.db
	wa := h.auth

	u, err := db.Queries.GetFromMail(ctx, email)
	if err != nil {
		errormsg.GetEntryErr(w, err)
		return
	}
	user, err = models.GetUser(u)
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

	u, err := db.Queries.GetFromMail(ctx, email)
	if err != nil {
		errormsg.GetEntryErr(w, err)
		return
	}
	user, err = models.GetUser(u)
	if err != nil {
		errormsg.GetEntryErr(w, err)
		return
	}

	err = user.FinishLogin(db, wa, r)
	if err != nil {
		errormsg.RequestErr(w, err)
		return
	}

	t, err := getTokens(ctx, u.ID, h)
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
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh",
		Value:    t.Refresh,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})

	w.WriteHeader(http.StatusNoContent)
}
