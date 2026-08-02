package handler

import (
	"context"
	"encoding/json"
	"time"

	"go/playground/encryption"
	errormsg "go/playground/error_msg"
	"go/playground/middleware"
	"go/playground/models"
	"go/playground/service"
	"go/playground/store"
	"go/playground/store/gen"
	"go/playground/token"
	"net/http"
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

	renameRequest, err := getValidBody[models.RenameRequest](r)
	if err != nil {
		errormsg.DecodeErr(w, err)
		return
	}
	err = u.UpdateName(ctx, renameRequest, c.UserID)
	if err != nil {
		errormsg.UpdateErr(w, err)
		return
	}
}

func HandleBeginRegister(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	token, err := middleware.GetClaim(ctx)
	if err != nil {
		errormsg.ClaimErr(w, err)
		return
	}

	app, err := middleware.GetAppContext(r.Context())
	if err != nil {
		errormsg.AppContextErr(w, err)
		return
	}

	db := app.DB
	wa := app.Auth
	cfg := app.Config

	userService := service.NewUser(db, cfg)

	u, err := userService.Get(ctx, token.UserID)
	if err != nil {
		errormsg.GetEntryErr(w, err)
		return
	}

	credentials, err := u.BeginRegistration(db, wa)
	if err != nil {
		errormsg.BeginRegistrationErr(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(credentials)
}

func HandleFinishRegister(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	token, err := middleware.GetClaim(ctx)
	if err != nil {
		errormsg.ClaimErr(w, err)
		return
	}

	app, err := middleware.GetAppContext(r.Context())
	if err != nil {
		errormsg.AppContextErr(w, err)
		return
	}

	db := app.DB
	wa := app.Auth
	cfg := app.Config

	userService := service.NewUser(db, cfg)

	u, err := userService.Get(ctx, token.UserID)
	if err != nil {
		errormsg.GetEntryErr(w, err)
		return
	}

	err = u.FinishRegistration(db, wa, r)

	data, err := json.Marshal(u.Credentials)
	//db.Queries.up
	err = db.Queries.UserUpdateSignupCredentials(ctx, gen.UserUpdateSignupCredentialsParams{
		Credentials: json.RawMessage(data),
		ID:          u.ID,
		Mail:        u.Mail,
	})

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
