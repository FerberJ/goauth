package handler

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"

	errormsg "github.com/FerberJ/goauth/error_msg"
	"github.com/FerberJ/goauth/mail"
	"github.com/FerberJ/goauth/models"
	"github.com/FerberJ/goauth/service"
	"github.com/go-chi/chi/v5"
)

func (h Handler) HandleListUsers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

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
	cfg := h.config

	u := service.NewUser(db, cfg)

	users, err := u.List(ctx, limit, offset)
	if err != nil {
		errormsg.GetEntryErr(w, err)
		return
	}

	payload, err := json.Marshal(users)

	w.Header().Set("Content-Type", "application/json")
	w.Write(payload)
	w.WriteHeader(http.StatusOK)
}

func (h Handler) HandleGetUsers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := chi.URLParam(r, "id")

	db := h.db
	cfg := h.config

	u := service.NewUser(db, cfg)

	user, err := u.Get(ctx, id)
	if err != nil {
		errormsg.GetEntryErr(w, err)
		return
	}

	payload, err := json.Marshal(user)

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

func (h Handler) HandleSetUserImage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	db := h.db
	cfg := h.config

	id := chi.URLParam(r, "id")

	// Limit total request size (e.g. 5MB) to prevent abuse
	r.Body = http.MaxBytesReader(w, r.Body, 5<<20) // 5MB

	// Parse the multipart form; the argument is the max memory used
	// before falling back to temp files on disk
	if err := r.ParseMultipartForm(5 << 20); err != nil {
		http.Error(w, "file too large or invalid form", http.StatusBadRequest)
		return
	}

	// "avatar" must match the form field name the client sends
	file, _, err := r.FormFile("avatar")
	if err != nil {
		http.Error(w, "missing avatar file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Read the file into memory
	imgData, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, "failed to read file", http.StatusInternalServerError)
		return
	}

	u := service.NewUser(db, cfg)
	err = u.SetProfileImage(ctx, id, imgData)
	if err != nil {
		http.Error(w, "failed to save file", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h Handler) HandleGetUserImage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	db := h.db
	cfg := h.config

	id := chi.URLParam(r, "id")

	u := service.NewUser(db, cfg)
	img, err := u.GetProfileImage(ctx, id)
	if err != nil {
		http.Error(w, "failed to get file", http.StatusBadRequest)
		return
	}

	mime := http.DetectContentType(img)

	w.Header().Set("Content-Type", mime)
	w.Write(img)
}
