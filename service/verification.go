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

type Verification struct {
	db     store.DB
	config config.Config
}

func NewVerification(db store.DB, conf config.Config) *Verification {
	return &Verification{
		db:     db,
		config: conf,
	}
}

func (v *Verification) Create(ctx context.Context, userID string) (string, error) {
	var err error
	token := ""
	for {
		token, err = encryption.GenerateRandomToken(v.config.Verification.TokenBytes)
		if err != nil {
			return "", fmt.Errorf("could not generate verification token: %w", err)
		}
		exist, err := v.db.Queries.VerificationExists(ctx, token)
		if err != nil {
			return "", fmt.Errorf("could not check if verification token already exists: %w", err)
		}
		if !exist {
			break
		}
	}

	tokenHash := encryption.HashToken(token)
	newID, err := v.db.CreateID(ctx, store.Verification)
	if err != nil {
		return "", fmt.Errorf("could not create new ID for verification")
	}

	newV := gen.CreateVerificationParams{
		ID:        newID,
		TokenID:   tokenHash,
		UserID:    userID,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(v.config.Verification.TokenTTL).Unix(),
	}
	_, err = v.db.Queries.CreateVerification(ctx, newV)
	if err != nil {
		return "", fmt.Errorf("verification token could not be saved to DB: %w", err)
	}

	return token, nil
}

func (v *Verification) Get(ctx context.Context, tokenHash string) (models.Verification, error) {
	var verification models.Verification
	authV, err := v.db.Queries.GetVerification(ctx, tokenHash)
	if err != nil {
		return verification, fmt.Errorf("could not get verification: %w", err)
	}

	verification = models.Verification{
		ID:        authV.ID,
		TokenID:   authV.TokenID,
		UserID:    authV.UserID,
		IssuedAt:  authV.IssuedAt,
		ExpiresAt: authV.ExpiresAt,
		Revoked:   authV.Revoked,
	}

	return verification, nil
}

func (v *Verification) Exists(ctx context.Context, id string) (bool, error) {
	exists, err := v.db.Queries.VerificationExists(ctx, id)
	if err != nil {
		return false, fmt.Errorf("error when checking if user exists: %w", err)
	}

	return exists, nil
}

func (v *Verification) VerificationIDExists(ctx context.Context, id string) (bool, error) {
	exists, err := v.db.Queries.VerificationIDExists(ctx, id)
	if err != nil {
		return false, fmt.Errorf("error when checking if user exists: %w", err)
	}

	return exists, nil
}

func (v *Verification) Revoke(ctx context.Context, id string) error {
	err := v.db.Queries.VerificationRevoke(ctx, id)
	if err != nil {
		return fmt.Errorf("could not revoke verification token: %w", err)
	}

	return nil
}

func (v *Verification) Verify(ctx context.Context, token string) error {
	hashToken := encryption.HashToken(token)
	ver, err := v.Get(ctx, hashToken)
	if err != nil {
		return fmt.Errorf("could not find token: %w", err)
	}

	if ver.ExpiresAt < time.Now().Unix() {
		return fmt.Errorf("token has expired")
	}
	if ver.Revoked {
		return fmt.Errorf("token has already been revoked")
	}

	err = v.Revoke(ctx, ver.ID)
	if err != nil {
		return fmt.Errorf("could not update revoke by the verification")
	}

	u := gen.VerifyUserParams{
		Verified: true,
		ID:       ver.UserID,
	}
	err = v.db.Queries.VerifyUser(ctx, u)
	if err != nil {
		return fmt.Errorf("could not update verification by the user")
	}

	return nil
}
