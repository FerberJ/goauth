package service

import (
	"context"
	"fmt"
	"time"

	"github.com/FerberJ/goauth/config"
	"github.com/FerberJ/goauth/encryption"
	"github.com/FerberJ/goauth/models"
	"github.com/FerberJ/goauth/store"
	"github.com/FerberJ/goauth/store/gen"
)

type Password struct {
	db     store.DB
	config config.Config
}

func NewPassword(db store.DB, conf config.Config) *Password {
	return &Password{
		db:     db,
		config: conf,
	}
}

func (p *Password) Create(ctx context.Context, userID string) (string, error) {
	var err error
	token := ""
	for {
		token, err = encryption.GenerateRandomToken(p.config.Password.TokenBytes)
		if err != nil {
			return "", fmt.Errorf("could not generate password token: %w", err)
		}
		exist, err := p.db.Queries.PasswordForgotExists(ctx, token)
		if err != nil {
			return "", fmt.Errorf("could not check if password token already exists: %w", err)
		}
		if !exist {
			break
		}
	}

	tokenHash := encryption.HashToken(token)
	newID, err := p.db.CreateID(ctx, store.Password)
	if err != nil {
		return "", fmt.Errorf("could not create new ID for password")
	}

	newV := gen.CreatePasswordForgotParams{
		ID:        newID,
		TokenID:   tokenHash,
		UserID:    userID,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(p.config.Password.TokenTTL).Unix(),
	}
	_, err = p.db.Queries.CreatePasswordForgot(ctx, newV)
	if err != nil {
		return "", fmt.Errorf("password token could not be saved to DB: %w", err)
	}

	return token, nil
}

func (p *Password) Get(ctx context.Context, tokenHash string) (models.Password, error) {
	var pw models.Password
	authV, err := p.db.Queries.GetPasswordForgot(ctx, tokenHash)
	if err != nil {
		return pw, fmt.Errorf("could not get password: %w", err)
	}

	pw = models.Password{
		ID:        authV.ID,
		TokenID:   authV.TokenID,
		UserID:    authV.UserID,
		IssuedAt:  authV.IssuedAt,
		ExpiresAt: authV.ExpiresAt,
		Revoked:   authV.Revoked,
	}

	return pw, nil
}

func (p *Password) Exists(ctx context.Context, id string) (bool, error) {
	exists, err := p.db.Queries.PasswordForgotExists(ctx, id)
	if err != nil {
		return false, fmt.Errorf("error when checking if user exists: %w", err)
	}

	return exists, nil
}

func (p *Password) PasswordIDExists(ctx context.Context, id string) (bool, error) {
	exists, err := p.db.Queries.PasswordForgotIDExists(ctx, id)
	if err != nil {
		return false, fmt.Errorf("error when checking if password token exists: %w", err)
	}

	return exists, nil
}

func (p *Password) Revoke(ctx context.Context, id string) error {
	err := p.db.Queries.PasswordForgotRevoke(ctx, id)
	if err != nil {
		return fmt.Errorf("could not revoke password token: %w", err)
	}

	return nil
}

func (p *Password) Verify(ctx context.Context, token string) error {
	hashToken := encryption.HashToken(token)
	ver, err := p.Get(ctx, hashToken)
	if err != nil {
		return fmt.Errorf("could not find token: %w", err)
	}

	if ver.ExpiresAt < time.Now().Unix() {
		return fmt.Errorf("token has expired")
	}
	if ver.Revoked {
		return fmt.Errorf("token has already been revoked")
	}

	err = p.Revoke(ctx, ver.ID)
	if err != nil {
		return fmt.Errorf("could not update revoke by the password")
	}

	u := gen.VerifyUserParams{
		Verified: true,
		ID:       ver.UserID,
	}
	err = p.db.Queries.VerifyUser(ctx, u)
	if err != nil {
		return fmt.Errorf("could not update password by the user")
	}

	return nil
}
