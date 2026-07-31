package handler

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
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

	"github.com/google/uuid"
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
		Name: store.NullStringToString(user.Name),
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

	renameRequest, err := decodeBody[models.RenameRequest](r)
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
	ctx := r.Context()
	signupRequest, err := decodeBody[models.SignupRequest](r)
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
	token, _, err := u.Create(ctx, signupRequest, false)
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
	ctx := r.Context()
	loginRequest, err := decodeBody[models.LoginRequest](r)
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

	t, err := getTokens(ctx, u.ID, app)
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

	w.WriteHeader(http.StatusNoContent)
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

	t, err := getTokens(ctx, refresh.UserID, app)
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
	ctx := r.Context()
	resetRequest, err := decodeBody[models.ResetRequest](r)
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

	u, err := db.Queries.GetFromMail(ctx, resetRequest.Email)

	t, err := getPasswordToken(ctx, u.ID, app)

	verifyURL, err := url.JoinPath(cfg.Password.Endpoint, "reset-password", t)
	if err != nil {
		errormsg.JoinPathErr(w, err)
		return
	}
	err = smtp.SendMail(cfg.SMTP.Username, resetRequest.Email, verifyURL, "reset password", mail.HTML)
	if err != nil {
		errormsg.SendMailErr(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func HandleBeginLogin(w http.ResponseWriter, r *http.Request) {
	var user models.User
	ctx := r.Context()
	email := r.URL.Query().Get("email")

	app, err := middleware.GetAppContext(r.Context())
	if err != nil {
		errormsg.AppContextErr(w, err)
		return
	}

	db := app.DB
	wa := app.Auth

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

func HandleFinishLogin(w http.ResponseWriter, r *http.Request) {
	var user models.User
	ctx := r.Context()
	email := r.URL.Query().Get("email")

	app, err := middleware.GetAppContext(r.Context())
	if err != nil {
		errormsg.AppContextErr(w, err)
		return
	}

	db := app.DB
	wa := app.Auth

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

	t, err := getTokens(ctx, u.ID, app)
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

	w.WriteHeader(http.StatusNoContent)
}

func HandleBeginSignup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	email := r.URL.Query().Get("email")

	app, err := middleware.GetAppContext(r.Context())
	if err != nil {
		errormsg.AppContextErr(w, err)
		return
	}

	db := app.DB
	wa := app.Auth
	cfg := app.Config

	userService := service.NewUser(db, cfg)
	_, err = userService.GetFromMail(ctx, email)
	if !errors.Is(err, sql.ErrNoRows) {
		errormsg.UserAlreadyExists(w, fmt.Errorf("user already exists"))
		return
	}
	_, userID, err := userService.Create(ctx, models.SignupRequest{
		Name:     "",
		Email:    uuid.NewString(),
		Password: "",
	}, true)
	if err != nil {
		errormsg.CreateErr(w, err)
		return
	}

	user := models.User{
		ID:   userID,
		Mail: email,
	}

	credentials, err := user.BeginRegistration(db, wa)
	if err != nil {
		errormsg.BeginRegistrationErr(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(credentials)
}

func HandleFinishSignup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	email := r.URL.Query().Get("email")

	app, err := middleware.GetAppContext(r.Context())
	if err != nil {
		errormsg.AppContextErr(w, err)
		return
	}

	db := app.DB
	wa := app.Auth

	user := models.User{Mail: email}
	err = user.FinishRegistration(db, wa, r)

	data, err := json.Marshal(user.Credentials)
	//db.Queries.up
	err = db.Queries.UserUpdateSignupCredentials(ctx, gen.UserUpdateSignupCredentialsParams{
		Credentials: json.RawMessage(data),
		ID:          user.ID,
		Mail:        email,
	})

	err = db.Queries.VerifyUser(ctx, gen.VerifyUserParams{
		Verified: true,
		ID:       user.ID,
	})

	w.WriteHeader(http.StatusNoContent)
}

func HandleResetPassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	resetPassword, err := decodeBody[models.ResetPassword](r)
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

	userID := ""
	skipOldPassword := false

	if resetPassword.Token != "" {
		tokenHash := encryption.HashToken(resetPassword.Token)
		pw, err := db.Queries.GetPasswordForgot(ctx, tokenHash)
		if err != nil {
			errormsg.GetEntryErr(w, err)
			return
		}

		if pw.ExpiresAt < time.Now().Unix() {
			errormsg.ExpireErr(w, fmt.Errorf("refresh token has expired"))
			return
		}

		if pw.Revoked {
			errormsg.RevokeErr(w, fmt.Errorf("refresh token has been revoked"))
			return
		}

		userID = pw.UserID
		skipOldPassword = true
	} else if resetPassword.OldPassword != "" && resetPassword.Email != "" {
		user, err := db.Queries.GetFromMail(ctx, resetPassword.Email)
		if err != nil {
			errormsg.GetEntryErr(w, err)
			return
		}

		userID = user.ID
		skipOldPassword = false
	} else {
		errormsg.RevokeErr(w, fmt.Errorf("either a reset password token has to be provided or the old password with email"))
	}

	u := service.NewUser(db, cfg)
	err = u.UpdatePassword(ctx, models.UpdatePasswordRequest{
		NewPassword: resetPassword.Password,
		OldPassword: resetPassword.OldPassword,
	}, userID, skipOldPassword)
	if err != nil {
		errormsg.UpdatePasswordErr(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func getPasswordToken(ctx context.Context, userID string, app middleware.AppContext) (string, error) {
	cfg := app.Config
	db := app.DB

	p := service.NewPassword(db, cfg)

	return p.Create(ctx, userID)
}

func getVerification(ctx context.Context, userID string, app middleware.AppContext) (string, error) {
	cfg := app.Config
	db := app.DB

	v := service.NewVerification(db, cfg)

	return v.Create(ctx, userID)
}

func getTokens(ctx context.Context, userID string, app middleware.AppContext) (token.Tokens, error) {
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
