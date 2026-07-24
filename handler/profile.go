package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"go/playground/encryption"
	errormsg "go/playground/error_msg"
	"go/playground/mail"
	"go/playground/middleware"
	"go/playground/models"
	"go/playground/service"
	"go/playground/store"
	"go/playground/store/gen"
	"go/playground/token"
	"net/http"
	"net/url"
)

func HandleProfile(w http.ResponseWriter, r *http.Request) {
	app, err := middleware.GetAppContext(r.Context())
	if err != nil {
		errormsg.AppContextErr(w, err)
		return
	}

	db := app.DB

	c, err := middleware.GetClaim(r.Context())
	if err != nil {
		errormsg.ClaimErr(w, err)
		return
	}

	user, err := db.Queries.GetUser(r.Context(), c.UserID)
	if err != nil {
		errormsg.GetEntryErr(w, err)
		return
	}

	u := models.User{
		ID:   user.ID,
		Name: user.Name,
		Mail: user.Mail,
	}

	payload, err := json.Marshal(u)

	w.Header().Set("Content-Type", "application/json")
	w.Write(payload)
	w.WriteHeader(http.StatusCreated)
}

func HandleChangeName(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	app, err := middleware.GetAppContext(r.Context())
	if err != nil {
		errormsg.AppContextErr(w, err)
		return
	}
	db := app.DB
	cfg := app.Config

	u := service.NewUser(db, cfg)

	c, err := middleware.GetClaim(r.Context())
	if err != nil {
		errormsg.ClaimErr(w, err)
		return
	}

	var renameRequest models.RenameRequest

	err = json.NewDecoder(r.Body).Decode(&renameRequest)
	if err != nil {
		errormsg.DecodeErr(w, err)
		return
	}
	err = u.UpdateName(ctx, renameRequest, c.ID)
	if err != nil {
		errormsg.UpdateErr(w, err)
		return
	}
}

func HandleSignup(w http.ResponseWriter, r *http.Request) {
	var signupRequest models.SignupRequest
	ctx := r.Context()

	err := json.NewDecoder(r.Body).Decode(&signupRequest)
	if err != nil {
		errormsg.DecodeErr(w, err)
		return
	}

	app, err := middleware.GetAppContext(r.Context())
	if err != nil {
		errormsg.AppContextErr(w, err)
		return
	}

	db := app.DB
	cfg := app.Config
	smtp := app.SMTP

	u := service.NewUser(db, cfg)
	token, err := u.Create(ctx, signupRequest)
	if err != nil {
		errormsg.CreateErr(w, err)
		return
	}

	verifyURL, err := url.JoinPath(cfg.Verification.Endpoint, "verify", token)
	if err != nil {
		errormsg.JoinPathErr(w, err)
		return
	}
	err = smtp.SendMail(cfg.SMTP.Username, signupRequest.Email, verifyURL, "verify", mail.HTML)
	if err != nil {
		errormsg.SendMailErr(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
}

func HandleLogin(w http.ResponseWriter, r *http.Request) {
	var loginRequest models.LoginRequest
	ctx := r.Context()

	err := json.NewDecoder(r.Body).Decode(&loginRequest)
	if err != nil {
		errormsg.DecodeErr(w, err)
		return
	}

	app, err := middleware.GetAppContext(r.Context())
	if err != nil {
		errormsg.AppContextErr(w, err)
		return
	}

	db := app.DB

	u, err := db.Queries.GetFromMail(ctx, loginRequest.Email)
	if err != nil {
		errormsg.GetEntryErr(w, err)
		return
	}

	valid, err := encryption.CompareHash(u.PasswordHash, loginRequest.Password)
	if err != nil {
		errormsg.ValidatePasswordErr(w, err)
		return
	}
	if !valid {
		errormsg.ValidatePasswordErr(w, fmt.Errorf("password is not valid"))
		return
	}

	t, err := GetTokens(ctx, u.ID, app)
	if err != nil {
		errormsg.GetTokenErr(w, err)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "authorization",
		Value:    t.JWT,
		Path:     "/",
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteStrictMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh",
		Value:    t.Refresh,
		Path:     "/",
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteStrictMode,
	})

	w.WriteHeader(http.StatusOK)
}

func HandleLogout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	c, err := r.Cookie("refresh")
	if err != nil {
		errormsg.GetCookieErr(w, err)
		return
	}

	app, err := middleware.GetAppContext(r.Context())
	if err != nil {
		errormsg.AppContextErr(w, err)
		return
	}

	db := app.DB

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
		Secure:   false,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}

func HandleRefresh(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	c, err := r.Cookie("refresh")
	if err != nil {
		errormsg.GetCookieErr(w, err)
		return
	}

	app, err := middleware.GetAppContext(r.Context())
	if err != nil {
		errormsg.AppContextErr(w, err)
		return
	}

	db := app.DB

	hashRefresh := encryption.HashToken(c.Value)
	refresh, err := db.Queries.GetRefresh(ctx, hashRefresh)
	if err != nil {
		errormsg.GetEntryErr(w, err)
		return
	}

	if refresh.ExpiresAt < time.Now().Unix() {
		errormsg.ExpireErr(w, fmt.Errorf("refresh token has expired"))
		return
	}

	if refresh.Revoked {
		errormsg.RevokeErr(w, fmt.Errorf("refresh token has been revoked"))
		return
	}

	err = db.Queries.RefreshRevoke(ctx, refresh.ID)
	if err != nil {
		errormsg.UpdateErr(w, err)
		return
	}

	t, err := GetTokens(ctx, refresh.UserID, app)
	if err != nil {
		errormsg.GetEntryErr(w, err)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "authorization",
		Value:    t.JWT,
		Path:     "/",
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteStrictMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh",
		Value:    t.Refresh,
		Path:     "/",
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteStrictMode,
	})

	w.WriteHeader(http.StatusOK)
}

func HandleForgotPassword(w http.ResponseWriter, r *http.Request) {
	/*
		var resetRequest models.Reset
		ctx := r.Context()

		err := json.NewDecoder(r.Body).Decode(&resetRequest)
		if err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
	*/
}

func GetTokens(ctx context.Context, userID string, app middleware.AppContext) (token.Tokens, error) {
	cfg := app.Config
	db := app.DB

	t, err := token.CreateTokens(userID, cfg.Secret)
	if err != nil {
		return t, err
	}

	newID, err := db.CreateID(ctx, store.Refresh)
	if err != nil {
		return t, err
	}

	hashRefresh := encryption.HashToken(t.Refresh)
	_, err = db.Queries.CreateRefresh(ctx, gen.CreateRefreshParams{
		ID:        newID,
		TokenID:   hashRefresh,
		UserID:    userID,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(cfg.Refresh.TokenTTL).Unix(),
	})
	if err != nil {
		return t, err
	}

	return t, nil
}
