package handler

import (
	"context"
	"encoding/json"
	"io"

	"net/http"

	errormsg "github.com/FerberJ/goauth/error_msg"
	"github.com/FerberJ/goauth/middleware"
	"github.com/FerberJ/goauth/models"
	"github.com/FerberJ/goauth/service"
	"github.com/FerberJ/goauth/token"
)

func (h Handler) HandleProfile(w http.ResponseWriter, r *http.Request) {
	db := h.db
	cfg := h.config

	c, err := middleware.GetClaim(r.Context())
	if err != nil {
		errormsg.ClaimErr(w, err)
		return
	}

	u := service.NewUser(db, cfg)
	user, err := u.Get(r.Context(), c.UserID)
	if err != nil {
		errormsg.GetEntryErr(w, err)
		return
	}

	payload, err := json.Marshal(user)

	w.Header().Set("Content-Type", "application/json")
	w.Write(payload)
	w.WriteHeader(http.StatusCreated)
}

func (h Handler) HandleProfileUpdate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	db := h.db
	cfg := h.config

	u := service.NewUser(db, cfg)

	c, err := middleware.GetClaim(r.Context())
	if err != nil {
		errormsg.ClaimErr(w, err)
		return
	}

	updateRequest, err := getValidBody[models.UpdateRequest](r)
	if err != nil {
		errormsg.DecodeErr(w, err)
		return
	}
	err = u.UpdateUser(ctx, updateRequest, c.UserID)
	if err != nil {
		errormsg.UpdateErr(w, err)
		return
	}
}

func (h Handler) HandleProfileDelete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	db := h.db
	cfg := h.config

	u := service.NewUser(db, cfg)

	c, err := middleware.GetClaim(r.Context())
	if err != nil {
		errormsg.ClaimErr(w, err)
		return
	}

	err = u.Delete(ctx, c.UserID)
	if err != nil {
		errormsg.UpdateErr(w, err)
		return
	}
}

func (h Handler) HandleBeginRegister(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	token, err := middleware.GetClaim(ctx)
	if err != nil {
		errormsg.ClaimErr(w, err)
		return
	}

	db := h.db
	wa := h.auth
	cfg := h.config

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

func (h Handler) HandleFinishRegister(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	token, err := middleware.GetClaim(ctx)
	if err != nil {
		errormsg.ClaimErr(w, err)
		return
	}

	db := h.db
	wa := h.auth
	cfg := h.config

	u := service.NewUser(db, cfg)

	user, err := u.Get(ctx, token.UserID)
	if err != nil {
		errormsg.GetEntryErr(w, err)
		return
	}

	err = user.FinishRegistration(db, wa, r)

	err = u.UpdateSignupCredentials(ctx, user.Credentials, user.ID, user.Mail)
	/*
		data, err := json.Marshal(u.Credentials)
		//db.Queries.up
		err = db.Queries.UserUpdateSignupCredentials(ctx, gen.UserUpdateSignupCredentialsParams{
			Credentials: json.RawMessage(data),
			ID:          u.ID,
			Mail:        u.Mail,
		})
	*/
	w.WriteHeader(http.StatusNoContent)
}

func getPasswordToken(ctx context.Context, userID string, h Handler) (string, error) {
	cfg := h.config
	db := h.db

	p := service.NewPassword(db, cfg)

	return p.Create(ctx, userID)
}

/*
func getVerification(ctx context.Context, userID string, h Handler) (string, error) {
	cfg := h.config
	db := h.db

	v := service.NewVerification(db, cfg)

	return v.Create(ctx, userID)
}
*/

func getTokens(ctx context.Context, userID string, h Handler) (token.Tokens, error) {
	cfg := h.config
	db := h.db

	re := service.NewRefresh(db, cfg)

	t, err := token.CreateTokens(userID, cfg.Secret)
	if err != nil {
		return t, err
	}

	t.Refresh, err = re.Create(ctx, userID)
	if err != nil {
		return t, err
	}

	return t, nil
}

func (h Handler) HandleSetProfileImage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	db := h.db
	cfg := h.config

	c, err := middleware.GetClaim(r.Context())
	if err != nil {
		errormsg.ClaimErr(w, err)
		return
	}

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
	err = u.SetProfileImage(ctx, c.UserID, imgData)
	if err != nil {
		http.Error(w, "failed to save file", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h Handler) HandleGetProfileImage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	db := h.db
	cfg := h.config

	c, err := middleware.GetClaim(r.Context())
	if err != nil {
		errormsg.ClaimErr(w, err)
		return
	}

	u := service.NewUser(db, cfg)
	img, err := u.GetProfileImage(ctx, c.UserID)
	if err != nil {
		http.Error(w, "failed to get file", http.StatusBadRequest)
		return
	}

	mime := http.DetectContentType(img)

	w.Header().Set("Content-Type", mime)
	w.Write(img)
}
