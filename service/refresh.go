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

type Refresh struct {
	db     store.DB
	config config.Config
}

func NewRefresh(db store.DB, conf config.Config) *Refresh {
	return &Refresh{
		db:     db,
		config: conf,
	}
}

func (v *Refresh) Create(ctx context.Context, userID string) (string, error) {
	var err error
	token := ""
	for {
		token, err = encryption.GenerateRandomToken(v.config.Verification.TokenBytes)
		if err != nil {
			return "", fmt.Errorf("could not generate verification token: %w", err)
		}
		exist, err := v.db.Queries.RefreshExists(ctx, token)
		if err != nil {
			return "", fmt.Errorf("could not check if verification token already exists: %w", err)
		}
		if !exist {
			break
		}
	}

	tokenHash := encryption.HashToken(token)
	newID, err := v.db.CreateID(ctx, store.Refresh)
	if err != nil {
		return "", fmt.Errorf("could not create new ID for verification")
	}

	newR := gen.CreateRefreshParams{
		ID:        newID,
		TokenID:   tokenHash,
		UserID:    userID,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(v.config.Verification.TokenTTL).Unix(),
	}
	_, err = v.db.Queries.CreateRefresh(ctx, newR)
	if err != nil {
		return "", fmt.Errorf("verification token could not be saved to DB: %w", err)
	}

	return token, nil
}

func (v *Refresh) Delete(ctx context.Context, id string) error {
	err := v.db.Queries.DeleteRefresh(ctx, id)
	if err != nil {
		return fmt.Errorf("could not delete refresh token: %w", err)
	}

	return nil
}

func (v *Refresh) Get(ctx context.Context, id string) (models.Refresh, error) {
	var refresh models.Refresh
	authV, err := v.db.Queries.GetRefresh(ctx, id)
	if err != nil {
		return refresh, fmt.Errorf("could not get verification: %w", err)
	}

	refresh = models.Refresh{
		ID:        authV.ID,
		TokenID:   authV.TokenID,
		UserID:    authV.UserID,
		IssuedAt:  authV.IssuedAt,
		ExpiresAt: authV.ExpiresAt,
		Revoked:   authV.Revoked,
	}

	return refresh, nil
}

func (v *Refresh) Exists(ctx context.Context, id string) (bool, error) {
	exists, err := v.db.Queries.RefreshExists(ctx, id)
	if err != nil {
		return false, fmt.Errorf("error when checking if user exists: %w", err)
	}

	return exists, nil
}

func (v *Refresh) RefreshIDExists(ctx context.Context, id string) (bool, error) {
	exists, err := v.db.Queries.RefreshIDExists(ctx, id)
	if err != nil {
		return false, fmt.Errorf("error when checking if user exists: %w", err)
	}

	return exists, nil
}

func (v *Refresh) Revoke(ctx context.Context, id string) error {
	err := v.db.Queries.RefreshRevoke(ctx, id)
	if err != nil {
		return fmt.Errorf("could not revoke verification token: %w", err)
	}

	return nil
}
