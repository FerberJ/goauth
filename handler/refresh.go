package handler

import (
	"fmt"
	"net/http"
	"time"

	"github.com/FerberJ/goauth/encryption"
	errormsg "github.com/FerberJ/goauth/error_msg"
	"github.com/FerberJ/goauth/service"
)

func (h Handler) HandleRefresh(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	c, err := r.Cookie("refresh")
	if err != nil {
		errormsg.GetCookieErr(w, err)
		return
	}

	db := h.db
	cfg := h.config

	re := service.NewRefresh(db, cfg)

	hashRefresh := encryption.HashToken(c.Value)
	refresh, err := re.Get(ctx, hashRefresh)

	if refresh.ExpiresAt < time.Now().Unix() {
		errormsg.ExpireErr(w, fmt.Errorf("refresh token has expired"))
		return
	}

	if refresh.Revoked {
		errormsg.RevokeErr(w, fmt.Errorf("refresh token has been revoked"))
		return
	}

	err = re.Revoke(ctx, refresh.ID)
	if err != nil {
		errormsg.UpdateErr(w, err)
		return
	}

	t, err := getTokens(ctx, refresh.UserID, h)
	if err != nil {
		errormsg.GetEntryErr(w, err)
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

	w.WriteHeader(http.StatusOK)
}
