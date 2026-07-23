package handler

import (
	"encoding/json"
	"go/playground/middleware"
	"go/playground/models"
	"go/playground/service"
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

	verifyURL, err := url.JoinPath(cfg.Verification.Endpoint, "verify", token)
	smtp.SendMail(cfg.SMTP.Username, signupRequest.Email, verifyURL, "verify", cfg)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
}
