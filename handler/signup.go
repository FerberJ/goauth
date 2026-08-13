package handler

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	errormsg "github.com/FerberJ/goauth/error_msg"
	"github.com/FerberJ/goauth/mail"
	"github.com/FerberJ/goauth/models"
	"github.com/FerberJ/goauth/service"

	"github.com/google/uuid"
)

func (h Handler) HandleSignup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	signupRequest, err := getValidBody[models.SignupRequest](r)
	if err != nil {
		errormsg.DecodeErr(w, err)
		return
	}

	db := h.db
	cfg := h.config
	smtp := h.smtp

	u := service.NewUser(db, cfg)
	token, _, err := u.Create(ctx, signupRequest, false)
	if err != nil {
		errormsg.CreateErr(w, err)
		return
	}

	message, subject, err := cfg.SMTP.VerifyUserMail(cfg.Password.Endpoint, token)
	if err != nil {
		errormsg.JoinPathErr(w, err)
		return
	}
	err = smtp.SendMail(cfg.SMTP.Username, signupRequest.Email, message, subject, mail.HTML)
	if err != nil {
		errormsg.SendMailErr(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
}

func (h Handler) HandleBeginSignup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	email := r.URL.Query().Get("email")

	db := h.db
	wa := h.auth
	cfg := h.config

	userService := service.NewUser(db, cfg)
	_, err := userService.GetFromMail(ctx, email)
	if !errors.Is(err, sql.ErrNoRows) {
		errormsg.UserAlreadyExistsErr(w, fmt.Errorf("user already exists"))
		return
	}
	_, userID, err := userService.Create(ctx, models.SignupRequest{
		Username: "",
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

func (h Handler) HandleFinishSignup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	email := r.URL.Query().Get("email")

	db := h.db
	wa := h.auth
	cfg := h.config
	smtp := h.smtp

	user := models.User{Mail: email}
	err := user.FinishRegistration(db, wa, r)

	u := service.NewUser(db, cfg)
	err = u.UpdateSignupCredentials(ctx, user.Credentials, user.ID, user.Mail)
	/*
		data, err := json.Marshal(user.Credentials)
			//db.Queries.up
			err = db.Queries.UserUpdateSignupCredentials(ctx, gen.UserUpdateSignupCredentialsParams{
				Credentials: json.RawMessage(data),
				ID:          user.ID,
				Mail:        email,
			})

	*/

	v := service.NewVerification(db, cfg)
	token, err := v.Create(ctx, user.ID)
	if err != nil {
		errormsg.GetTokenErr(w, err)
		return
	}

	message, subject, err := cfg.SMTP.VerifyUserMail(cfg.Password.Endpoint, token)
	if err != nil {
		errormsg.JoinPathErr(w, err)
		return
	}
	err = smtp.SendMail(cfg.SMTP.Username, email, message, subject, mail.HTML)
	if err != nil {
		errormsg.SendMailErr(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
