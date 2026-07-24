package handler

import (
	"context"
	"encoding/json"
	"time"

	"go/playground/encryption"
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
		//
	}

	db := app.DB

	c, err := middleware.GetClaim(r.Context())
	if err != nil {
		//
	}

	user, err := db.Queries.GetUser(r.Context(), c.UserID)
	if err != nil {
		//
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
		//
	}
	db := app.DB
	cfg := app.Config

	u := service.NewUser(db, cfg)

	c, err := middleware.GetClaim(r.Context())
	if err != nil {
		//
	}

	var renameRequest models.RenameRequest

	err = json.NewDecoder(r.Body).Decode(&renameRequest)
	if err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	err = u.UpdateName(ctx, renameRequest, c.ID)
	if err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
}

func HandleSignup(w http.ResponseWriter, r *http.Request) {
	var signupRequest models.SignupRequest
	ctx := r.Context()

	err := json.NewDecoder(r.Body).Decode(&signupRequest)
	if err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	app, err := middleware.GetAppContext(r.Context())
	if err != nil {
		//
	}

	db := app.DB
	cfg := app.Config
	smtp := app.SMTP

	u := service.NewUser(db, cfg)
	token, err := u.Create(ctx, signupRequest)
	if err != nil {
		//
	}

	verifyURL, err := url.JoinPath(cfg.Verification.Endpoint, "verify", token)
	smtp.SendMail(cfg.SMTP.Username, signupRequest.Email, verifyURL, "verify", mail.HTML)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
}

func HandleLogin(w http.ResponseWriter, r *http.Request) {
	var loginRequest models.LoginRequest
	ctx := r.Context()

	err := json.NewDecoder(r.Body).Decode(&loginRequest)
	if err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	app, err := middleware.GetAppContext(r.Context())
	if err != nil {
		//
	}

	db := app.DB

	u, err := db.Queries.GetFromMail(ctx, loginRequest.Email)
	if err != nil {
		//
	}

	valid, err := encryption.CompareHash(u.PasswordHash, loginRequest.Password)
	if err != nil {
		//
	}
	if !valid {
		//
	}

	t, err := GetTokens(ctx, u.ID, app)
	if err != nil {
		//
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
		//
	}

	app, err := middleware.GetAppContext(r.Context())
	if err != nil {
		//
	}

	db := app.DB

	hashRefresh := encryption.HashToken(c.Value)
	refresh, err := db.Queries.GetRefresh(ctx, hashRefresh)
	if err != nil {
		//
	}

	err = db.Queries.DeleteRefresh(ctx, refresh.ID)
	if err != nil {
		//
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
		//
	}

	app, err := middleware.GetAppContext(r.Context())
	if err != nil {
		//
	}

	db := app.DB

	hashRefresh := encryption.HashToken(c.Value)
	refresh, err := db.Queries.GetRefresh(ctx, hashRefresh)
	if err != nil {
		//
	}

	if refresh.ExpiresAt < time.Now().Unix() {
		//
	}

	if refresh.Revoked {
		//
	}

	err = db.Queries.RefreshRevoke(ctx, refresh.ID)
	if err != nil {
		//
	}

	t, err := GetTokens(ctx, refresh.UserID, app)
	if err != nil {
		//
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
		//
	}

	newID, err := db.CreateID(ctx, store.Refresh)

	hashRefresh := encryption.HashToken(t.Refresh)
	_, err = db.Queries.CreateRefresh(ctx, gen.CreateRefreshParams{
		ID:        newID,
		TokenID:   hashRefresh,
		UserID:    userID,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(cfg.Refresh.TokenTTL).Unix(),
	})
	if err != nil {
		//
	}

	return t, nil
}
