package handler

import (
	"net/http"

	"github.com/FerberJ/goauth/encryption"
	errormsg "github.com/FerberJ/goauth/error_msg"
)

func (h Handler) HandleLogout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	c, err := r.Cookie("refresh")
	if err != nil {
		errormsg.GetCookieErr(w, err)
		return
	}

	db := h.db

	hashRefresh := encryption.HashToken(c.Value)
	refresh, err := db.Queries.GetRefresh(ctx, hashRefresh)
	if err != nil {
		errormsg.GetEntryErr(w, err)
		return
	}

	err = db.Queries.DeleteRefresh(ctx, refresh.ID)
	if err != nil {
		errormsg.DeleteErr(w, err)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "authorization",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}
