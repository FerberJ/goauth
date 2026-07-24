package auth

/*

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"go/playground/config"
	"go/playground/encryption"
	"go/playground/handler"
	"go/playground/mail"
	"go/playground/middleware"
	"go/playground/models"

	"go/playground/store"
	"go/playground/store/gen"
	"go/playground/token"

	"github.com/go-chi/chi/v5"
)

type Auth struct {
	config config.Config
	store  store.DB
	smtp   mail.MailClient
}

// Entry point for users of this Library.
// Needs the secret for creating the JWT-Token
// and Postgres connection
func Init(conf config.Config) (Auth, error) {
	var auth Auth
	s, err := store.Init(conf.DB)
	if err != nil {
		return auth, fmt.Errorf("error when initalising DB: %w", err)
	}
	mailClient, err := mail.Init(conf.SMTP)
	if err != nil {
		return auth, fmt.Errorf("error when initalising mail client: %w", err)
	}

	auth = Auth{
		config: conf,
		store:  s,
		smtp:   mailClient,
	}
	return auth, err
}

func (auth Auth) Signup(ctx context.Context, req models.SignupRequest) (string, error) {
	if req.Email == "" || req.Name == "" || req.Password == "" {
		return "", fmt.Errorf("invalid request")
	}
	passwordHash, err := encryption.HashPassword(req.Password)
	if err != nil {
		return "", fmt.Errorf("could not hash password: %w", err)
	}
	newID, err := auth.store.CreateID(ctx, store.User)
	if err != nil {
		return "", fmt.Errorf("could not create a new ID for User: %w", err)
	}
	u := gen.CreateUserParams{
		ID:           newID,
		Name:         req.Name,
		Mail:         req.Email,
		PasswordHash: passwordHash,
	}
	user, err := auth.store.Queries.CreateUser(ctx, u)
	if err != nil {
		return "", fmt.Errorf("could not create user: %w", err)
	}

	token, err := auth.createVerifivationToken(ctx, user.ID)
	if err != nil {
		return "", fmt.Errorf("verification token could not be created: %w", err)
	}

	return token, nil
}

func (auth Auth) createVerifivationToken(ctx context.Context, userID string) (string, error) {
	var err error
	token := ""
	for {
		token, err = encryption.GenerateRandomToken(auth.config.Verification.TokenBytes)
		if err != nil {
			return "", fmt.Errorf("could not generate verification token: %w", err)
		}
		exist, err := auth.store.Queries.VerificationExists(ctx, token)
		if err != nil {
			return "", fmt.Errorf("could not check if verification token already exists: %w", err)
		}
		if !exist {
			break
		}
	}

	tokenHash := encryption.HashToken(token)
	newID, err := auth.store.CreateID(ctx, store.Verification)
	if err != nil {
		return "", fmt.Errorf("could not create new ID for verification")
	}

	v := gen.CreateVerificationParams{
		ID:        newID,
		TokenID:   tokenHash,
		UserID:    userID,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(auth.config.Verification.TokenTTL).Unix(),
	}
	_, err = auth.store.Queries.CreateVerification(ctx, v)
	if err != nil {
		return "", fmt.Errorf("verification token could not be saved to DB: %w", err)
	}

	return token, nil
}

func (auth Auth) SendVerificationToken(ctx context.Context, token string, userMail string) error {
	path, err := url.JoinPath(auth.config.Verification.Endpoint, token)
	if err != nil {
		return err
	}
	return auth.smtp.SendMail(auth.config.SMTP.Client, userMail, path, "verification token", mail.Text)
}

func (auth Auth) VerifyEmail(ctx context.Context, token string) error {
	hashToken := encryption.HashToken(token)
	ver, err := auth.store.Queries.GetVerification(ctx, hashToken)
	if err != nil {
		return fmt.Errorf("could not find entry with verification token: %w", err)
	}

	// ExpiresAt
	if ver.ExpiresAt < time.Now().Unix() {
		return fmt.Errorf("token has expired")
	}
	if ver.Revoked {
		return fmt.Errorf("token has already been revoked")
	}

	err = auth.store.Queries.VerificationRevoke(ctx, ver.ID)
	if err != nil {
		return fmt.Errorf("could not update revoke by the verification")
	}

	u := gen.VerifyUserParams{
		Verified: true,
		ID:       ver.UserID,
	}
	err = auth.store.Queries.VerifyUser(ctx, u)
	if err != nil {
		return fmt.Errorf("could not update verification by the user")
	}

	return nil
}

func (auth Auth) Login(ctx context.Context, mail, password string) (token.Tokens, error) {
	var t token.Tokens

	u, err := auth.store.Queries.GetFromMail(ctx, mail)
	if err != nil {
		return t, fmt.Errorf("could not find user: %w", err)
	}

	valid, err := encryption.CompareHash(u.PasswordHash, password)
	if err != nil {
		return t, fmt.Errorf("could not compare to password hash: %w", err)
	}
	if !valid {
		return t, fmt.Errorf("incorect password")
	}

	return auth.getTokens(ctx, u.ID)
}

func (auth Auth) getTokens(ctx context.Context, userID string) (token.Tokens, error) {
	t, err := token.CreateTokens(userID, auth.config.Secret)
	if err != nil {
		return t, fmt.Errorf("could not create tokens: %w", err)
	}

	hashRefresh := encryption.HashToken(t.Refresh)
	newID, err := auth.store.CreateID(ctx, store.Refresh)
	_, err = auth.store.Queries.CreateRefresh(ctx, gen.CreateRefreshParams{
		ID:        newID,
		TokenID:   hashRefresh,
		UserID:    userID,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(auth.config.Refresh.TokenTTL).Unix(),
	})

	return t, nil
}

func (auth Auth) Refresh(ctx context.Context, refreshToken string) (token.Tokens, error) {
	var t token.Tokens
	hashToken := encryption.HashToken(refreshToken)
	ref, err := auth.store.Queries.GetRefresh(ctx, hashToken)
	if err != nil {
		return t, fmt.Errorf("could not find entry with refresh token: %w", err)
	}

	// ExpiresAt
	if ref.ExpiresAt < time.Now().Unix() {
		return t, fmt.Errorf("token has expired")
	}
	if ref.Revoked {
		return t, fmt.Errorf("token has already been revoked")
	}

	err = auth.store.Queries.RefreshRevoke(ctx, ref.ID)
	if err != nil {
		return t, fmt.Errorf("could not update revoke by the refresh")
	}

	return auth.getTokens(ctx, ref.UserID)
}

func (auth Auth) Logout(ctx context.Context, refreshToken string) error {
	hashToken := encryption.HashToken(refreshToken)
	ref, err := auth.store.Queries.GetRefresh(ctx, hashToken)
	if err != nil {
		return fmt.Errorf("could not find entry with refresh token: %w", err)
	}

	err = auth.store.Queries.RefreshRevoke(ctx, ref.ID)
	if err != nil {
		return fmt.Errorf("could not update revoke by the refresh")
	}

	return nil
}

func (auth Auth) ForgotPassword(ctx context.Context, mail string) (string, error) {
	u, err := auth.store.Queries.GetFromMail(ctx, mail)
	if err != nil {
		return "", fmt.Errorf("user could not be found: %w", err)
	}

	refreshToken, err := token.GetRefreshToken()
	if err != nil {
		return "", fmt.Errorf("can not create refresh token: %w", err)
	}
	hashRefresh := encryption.HashToken(refreshToken)
	newID, err := auth.store.CreateID(ctx, store.Refresh)
	if err != nil {
		return "", fmt.Errorf("could not create a new ID for refresh token: %w", err)
	}

	_, err = auth.store.Queries.CreateRefresh(ctx, gen.CreateRefreshParams{
		ID:        newID,
		TokenID:   hashRefresh,
		UserID:    u.ID,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(time.Minute * 15).Unix(),
	})
	if err != nil {
		return "", fmt.Errorf("could not save refresh token: %w", err)
	}

	return refreshToken, nil
}

func (auth Auth) ResetPassword(ctx context.Context, refreshToken, password string) error {
	hashToken := encryption.HashToken(refreshToken)
	ref, err := auth.store.Queries.GetRefresh(ctx, hashToken)
	if err != nil {
		return fmt.Errorf("could not find entry with refresh token: %w", err)
	}

	if ref.ExpiresAt < time.Now().Unix() {
		return fmt.Errorf("token has expired")
	}
	if ref.Revoked {
		return fmt.Errorf("token has already been revoked")
	}

	passwordHash, err := encryption.HashPassword(password)
	if err != nil {
		return fmt.Errorf("could not hash Password: %w", err)
	}

	err = auth.store.Queries.UserUpdatePassword(ctx, gen.UserUpdatePasswordParams{
		PasswordHash: passwordHash,
		ID:           ref.UserID,
	})
	if err != nil {
		return fmt.Errorf("user password could not be updated: %w", err)
	}

	err = auth.store.Queries.RefreshRevoke(ctx, ref.ID)
	if err != nil {
		return fmt.Errorf("refresh token could not be revoked: %w", err)
	}

	return nil
}

func (auth Auth) ChangePassword(ctx context.Context, bearerToken, oldPassword, newPassword string) error {
	claims, err := token.VerifyToken(bearerToken, auth.config.Secret)
	if err != nil {
		return fmt.Errorf("jwt token could not be verified: %w", err)
	}

	u, err := auth.store.Queries.GetUser(ctx, claims.UserID)
	if err != nil {
		return fmt.Errorf("user could not be found: %w", err)
	}

	ok, err := encryption.CompareHash(u.PasswordHash, oldPassword)
	if err != nil {
		return fmt.Errorf("password could not be verified: %w", err)
	}
	if !ok {
		return fmt.Errorf("incorrect password: %w", err)
	}

	passwordHash, err := encryption.HashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("new password could not be hashed: %w", err)
	}

	err = auth.store.Queries.UserUpdatePassword(ctx, gen.UserUpdatePasswordParams{
		PasswordHash: passwordHash,
		ID:           claims.UserID,
	})
	if err != nil {
		return fmt.Errorf("new password could not be saved: %w", err)
	}

	return nil
}

func (auth Auth) ChangeUserName(ctx context.Context, bearerToken, newName string) error {
	claims, err := token.VerifyToken(bearerToken, auth.config.Secret)
	if err != nil {
		return fmt.Errorf("jwt token could not be verified: %w", err)
	}

	err = auth.store.Queries.UpdateUserName(ctx, gen.UpdateUserNameParams{
		Name: newName,
		ID:   claims.UserID,
	})
	if err != nil {
		return fmt.Errorf("new password could not be saved: %w", err)
	}

	return nil
}

func (auth Auth) GetUser(ctx context.Context, bearerToken string) (models.User, error) {
	var user models.User
	claims, err := token.VerifyToken(bearerToken, auth.config.Secret)
	if err != nil {
		return user, fmt.Errorf("jwt token could not be verified: %w", err)
	}

	u, err := auth.store.Queries.GetUser(ctx, claims.UserID)
	if err != nil {
		return user, fmt.Errorf("user could not be found: %w", err)
	}

	user = models.User{
		ID:   u.ID,
		Name: u.Name,
		Mail: u.Mail,
	}

	return user, nil
}

func (auth Auth) DeleteUser(ctx context.Context, bearerToken string) error {
	claims, err := token.VerifyToken(bearerToken, auth.config.Secret)
	if err != nil {
		return fmt.Errorf("jwt token could not be verified: %w", err)
	}

	err = auth.store.Queries.DeleteUser(ctx, claims.UserID)
	if err != nil {
		return fmt.Errorf("could not delete user: %w", err)
	}

	return nil
}

func (auth Auth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("authorization") // .Get("authorization")
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		c, err := auth.verify(cookie.Value)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), "claimsContextKey", c)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (auth Auth) verify(jwtToken string) (*token.Claims, error) {
	return token.VerifyToken(jwtToken, auth.config.Secret)
}

func (auth Auth) GetRoutes() chi.Router {
	r := chi.NewRouter().
		With(middleware.WithAppContext(auth.store, auth.config, auth.smtp))

	r.Post("/signup", auth.handleSignup)
	r.Post("/verify/{token}", auth.HandleVerifyToken)
	r.Post("/login", auth.handleLogin)

	m := r.With(middleware.Authorization)

	m.Get("/profile", handler.HandleProfile)
	m.Patch("/profile/name", handler.HandleProfile)

	return r
}

func (auth Auth) handleProfile(w http.ResponseWriter, r *http.Request) {
	c, ok := r.Context().Value("claimsContextKey").(*token.Claims)
	if !ok {
		//
	}
	user, err := auth.store.Queries.GetUser(r.Context(), c.UserID)
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

func (auth Auth) handleLogin(w http.ResponseWriter, r *http.Request) {
	var loginRequest models.LoginRequest

	err := json.NewDecoder(r.Body).Decode(&loginRequest)
	if err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	tokens, err := auth.Login(r.Context(), loginRequest.Email, loginRequest.Password)
	if err != nil {
		http.Error(w, "invalid login credentials", http.StatusBadRequest)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "authorization",
		Value:    tokens.JWT,
		Path:     "/",
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteStrictMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh",
		Value:    tokens.Refresh,
		Path:     "/",
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteStrictMode,
	})

	w.WriteHeader(http.StatusOK)
}

func (auth Auth) HandleVerifyToken(w http.ResponseWriter, r *http.Request) {
	verifyToken := chi.URLParam(r, "token")
	ctx := context.Background()
	err := auth.VerifyEmail(ctx, verifyToken)
	if err != nil {
		http.Error(w, "could not verify user", http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (auth Auth) handleSignup(w http.ResponseWriter, r *http.Request) {
	var signupRequest models.SignupRequest

	err := json.NewDecoder(r.Body).Decode(&signupRequest)
	if err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	verifyToken, err := auth.Signup(r.Context(), signupRequest)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	verifyURL, err := url.JoinPath(auth.config.Verification.Endpoint, "verify", verifyToken)
	auth.smtp.SendMail(auth.config.SMTP.Username, signupRequest.Email, verifyURL, "verify", mail.Text)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
}


func CreateUser(password, user string) (string, error) {
	encrypt, err := encryption.HashPassword(password)
	if err != nil {
		return "", fmt.Errorf("can not encrypt password: %w", err)
	}

	u, err := db.Queries.CreateUser(context.Background(), gen.CreateUserParams{
		Name:         user,
		PasswordHash: encrypt,
	})

	return u.ID, err
}

func getPasswordHash(user string) (string, error) {
	u, err := db.Queries.GetFromMail(context.Background(), user)
	return u.PasswordHash, err
}

func Login(password, user string) (string, error) {
	hashedPw, err := getPasswordHash(user)
	if err != nil {
		return "", err
	}
	ok, err := encryption.ComparePassword(hashedPw, password)
	if !ok {
		return "", fmt.Errorf("wrong password")
	}
	if err != nil {
		return "", err
	}

	t, err := token.CreateToken(user, secret)
	if err != nil {
		return "", err
	}

	return t, nil
}



func Logout(password, user string) {}

func GetRoutes() chi.Router {
	r := chi.NewRouter()

	r.Post("/signup", handleCreateUser)
	r.Put("/password", handleChangePassword)
	r.Post("/login", handleLogin)

	return r
}

type credentials struct {
	User     string `json:"user"`
	Password string `json:"password"`
	Mail     string `json:"mail"`
}

func handleChangePassword(w http.ResponseWriter, r *http.Request) {

}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	var creds credentials
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if creds.User == "" || creds.Password == "" {
		http.Error(w, "user and password are required", http.StatusBadRequest)
		return
	}

	t, err := Login(creds.Password, creds.User)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    t,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})

	w.WriteHeader(http.StatusOK)
}

func handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var creds credentials
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if creds.User == "" || creds.Password == "" || creds.Mail == "" {
		http.Error(w, "username, email and password are required", http.StatusBadRequest)
		return
	}

	id, err := CreateUser(creds.Password, creds.User)
	if err != nil {
		http.Error(w, "could not create password", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)

	json.NewEncoder(w).Encode(map[string]any{
		"data": map[string]any{
			"id": id,
		},
	})
}
*/
