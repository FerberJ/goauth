package handler

import (
	"fmt"
	"net/http"
	"time"

	"github.com/FerberJ/goauth/encryption"
	errormsg "github.com/FerberJ/goauth/error_msg"
	"github.com/FerberJ/goauth/mail"
	"github.com/FerberJ/goauth/middleware"
	"github.com/FerberJ/goauth/models"
	"github.com/FerberJ/goauth/service"
)

func HandleForgotPassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	resetRequest, err := getValidBody[models.ResetRequest](r)
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

	// verifyURL, err := url.JoinPath(cfg.Password.Endpoint, "password", "reset", t)
	message, subject, err := cfg.SMTP.ResetPasswordMail(cfg.Password.Endpoint, t)
	if err != nil {
		errormsg.JoinPathErr(w, err)
		return
	}
	err = smtp.SendMail(cfg.SMTP.Username, resetRequest.Email, message, subject, mail.HTML)
	if err != nil {
		errormsg.SendMailErr(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func HandleResetPassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	resetPassword, err := getValidBody[models.ResetPassword](r)
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

	p := service.NewPassword(db, cfg)
	u := service.NewUser(db, cfg)

	tokenHash := encryption.HashToken(resetPassword.Token)
	pw, err := p.Get(ctx, tokenHash)
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

	err = u.ResetPassword(ctx, resetPassword.Password, pw.UserID)
	if err != nil {
		errormsg.ResetPasswordErr(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func HandleChangePassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	resetPassword, err := getValidBody[models.UpdatePassword](r)
	if err != nil {
		errormsg.DecodeErr(w, err)
		return
	}

	app, err := middleware.GetAppContext(r.Context())
	if err != nil {
		errormsg.AppContextErr(w, err)
		return
	}

	token, err := middleware.GetClaim(ctx)
	if err != nil {
		errormsg.ClaimErr(w, err)
		return
	}

	db := app.DB
	cfg := app.Config

	u := service.NewUser(db, cfg)
	err = u.ChangePassword(ctx, models.UpdatePasswordRequest{
		NewPassword: resetPassword.Password,
		OldPassword: resetPassword.OldPassword,
	}, token.UserID)
	if err != nil {
		errormsg.UpdatePasswordErr(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
