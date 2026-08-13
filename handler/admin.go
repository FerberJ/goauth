package handler

import (
	"encoding/json"
	"net/http"
	"strconv"

	errormsg "github.com/FerberJ/goauth/error_msg"
	"github.com/FerberJ/goauth/mail"
	"github.com/FerberJ/goauth/models"
	"github.com/FerberJ/goauth/service"
	"github.com/FerberJ/goauth/store"
	"github.com/FerberJ/goauth/store/gen"
	"github.com/go-chi/chi/v5"
)

func (h Handler) HandleListUsers(w http.ResponseWriter, r *http.Request) {
	var err error
	limitStr := r.URL.Query().Get("limit")
	limit := -1
	if limitStr != "" {
		limit, err = strconv.Atoi(limitStr)
		if err != nil {
			errormsg.ParseQueryErr(w, err)
		}
	}
	offsetStr := r.URL.Query().Get("offset")
	offset := -1
	if offsetStr != "" {
		offset, err = strconv.Atoi(offsetStr)
		if err != nil {
			errormsg.ParseQueryErr(w, err)
		}
	}

	db := h.db

	users, err := db.Queries.GetUsers(r.Context(), gen.GetUsersParams{
		Offset: int64(offset),
		Limit:  int64(limit),
	})
	if err != nil {
		errormsg.GetEntryErr(w, err)
		return
	}

	uList := make([]models.User, 0, len(users))
	for _, user := range users {
		u := models.User{
			ID:        user.ID,
			Username:  store.NullStringToString(user.Username),
			Firstname: store.NullStringToString(user.Firstname),
			Lastname:  store.NullStringToString(user.Lastname),
			Mail:      user.Mail,
			Admin:     user.Admin,
		}
		uList = append(uList, u)
	}

	payload, err := json.Marshal(uList)

	w.Header().Set("Content-Type", "application/json")
	w.Write(payload)
	w.WriteHeader(http.StatusOK)
}

func (h Handler) HandleGetUsers(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	db := h.db

	user, err := db.Queries.GetUser(r.Context(), id)
	if err != nil {
		errormsg.GetEntryErr(w, err)
		return
	}

	u := models.User{
		ID:        user.ID,
		Username:  store.NullStringToString(user.Username),
		Firstname: store.NullStringToString(user.Firstname),
		Lastname:  store.NullStringToString(user.Lastname),
		Mail:      user.Mail,
		Admin:     user.Admin,
	}

	payload, err := json.Marshal(u)

	w.Header().Set("Content-Type", "application/json")
	w.Write(payload)
	w.WriteHeader(http.StatusOK)
}

func (h Handler) HandleUserUpdate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	db := h.db
	cfg := h.config

	u := service.NewUser(db, cfg)

	id := chi.URLParam(r, "id")

	updateRequest, err := getValidBody[models.UpdateRequest](r)
	if err != nil {
		errormsg.DecodeErr(w, err)
		return
	}
	err = u.UpdateUser(ctx, updateRequest, id)
	if err != nil {
		errormsg.UpdateErr(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h Handler) HandleUserDelete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	db := h.db
	cfg := h.config

	u := service.NewUser(db, cfg)

	id := chi.URLParam(r, "id")

	err := u.Delete(ctx, id)
	if err != nil {
		errormsg.UpdateErr(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h Handler) HandleCreateUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	signupRequest, err := getValidBody[models.SignupRequest](r)
	if err != nil {
		errormsg.DecodeErr(w, err)
		return
	}

	db := h.db
	cfg := h.config
	u := service.NewUser(db, cfg)
	_, _, err = u.Create(ctx, signupRequest, false)
	if err != nil {
		errormsg.CreateErr(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
}

func (h Handler) HandleUserVerify(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	db := h.db
	cfg := h.config
	smtp := h.smtp

	u := service.NewUser(db, cfg)

	id := chi.URLParam(r, "id")

	user, err := u.Get(ctx, id)
	if err != nil {
		errormsg.GetEntryErr(w, err)
		return
	}

	token, err := u.CreateVerifyToken(ctx, id)
	if err != nil {
		errormsg.GetTokenErr(w, err)
		return
	}

	message, subject, err := cfg.SMTP.VerifyUserMail(cfg.Password.Endpoint, token)
	if err != nil {
		errormsg.JoinPathErr(w, err)
		return
	}
	err = smtp.SendMail(cfg.SMTP.Username, user.Mail, message, subject, mail.HTML)
	if err != nil {
		errormsg.SendMailErr(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
