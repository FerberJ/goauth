package service

import (
	"context"
	"encoding/json"
	"fmt"
	"go/playground/config"
	"go/playground/encryption"
	"go/playground/models"
	"go/playground/store"
	"go/playground/store/gen"
)

type User struct {
	db     store.DB
	config config.Config
}

func NewUser(db store.DB, conf config.Config) *User {
	return &User{
		db:     db,
		config: conf,
	}
}

func (u *User) Create(ctx context.Context, signup models.SignupRequest, isFido bool) (string, string, error) {
	var passwordHash = ""
	var err error

	if !isFido {
		if signup.Email == "" || signup.Name == "" || signup.Password == "" {
			return "", "", fmt.Errorf("invalid request")
		}
		passwordHash, err = encryption.HashPassword(signup.Password)
		if err != nil {
			return "", "", fmt.Errorf("could not hash password: %w", err)
		}
	}
	newID, err := u.db.CreateID(ctx, store.User)
	if err != nil {
		return "", "", fmt.Errorf("could not create a new ID for User: %w", err)
	}

	genUser := gen.CreateUserParams{
		ID:           newID,
		Name:         store.StringToNullString(signup.Name),
		Mail:         signup.Email,
		PasswordHash: store.StringToNullString(passwordHash),
		Credentials:  json.RawMessage([]byte("[]")),
	}
	user, err := u.db.Queries.CreateUser(ctx, genUser)
	if err != nil {
		return "", "", fmt.Errorf("could not create user: %w", err)
	}

	v := NewVerification(u.db, u.config)
	token, err := v.Create(ctx, user.ID)
	if err != nil {
		return "", "", fmt.Errorf("verification token could not be created: %w", err)
	}

	return token, user.ID, nil
}

func (u *User) Delete(ctx context.Context, id string) error {
	err := u.db.Queries.DeleteUser(ctx, id)
	if err != nil {
		return fmt.Errorf("could not delete user: %w", err)
	}

	return nil
}

func (u *User) GetFromMail(ctx context.Context, mail string) (models.User, error) {
	var user models.User
	authUser, err := u.db.Queries.GetFromMail(ctx, mail)
	if err != nil {
		return user, fmt.Errorf("could not find user from email %s: %w", mail, err)
	}

	user, err = models.GetUser(authUser)
	if err != nil {
		return user, fmt.Errorf("cannot format authUser to user")
	}

	return user, nil
}

func (u *User) Get(ctx context.Context, id string) (models.User, error) {
	var user models.User
	authUser, err := u.db.Queries.GetUser(ctx, id)
	if err != nil {
		return user, fmt.Errorf("could not find user from ID %s: %w", id, err)
	}

	user, err = models.GetUser(authUser)
	if err != nil {
		return user, fmt.Errorf("cannot format authUser to user")
	}

	return user, nil
}

func (u *User) UpdateName(ctx context.Context, rename models.RenameRequest, id string) error {
	err := u.db.Queries.UpdateUserName(ctx, gen.UpdateUserNameParams{
		Name: store.StringToNullString(rename.Name),
		ID:   id,
	})
	if err != nil {
		return fmt.Errorf("could not rename the user: %w", err)
	}
	return nil
}

func (u *User) Exists(ctx context.Context, id string) (bool, error) {
	exists, err := u.db.Queries.UserIDExists(ctx, id)
	if err != nil {
		return false, fmt.Errorf("error when checking if user exists: %w", err)
	}

	return exists, nil
}

func (u *User) ResetPassword(ctx context.Context, password string, id string) error {
	passwordHash, err := encryption.HashPassword(password)
	if err != nil {
		return fmt.Errorf("could not hash password: %w", err)
	}

	err = u.db.Queries.UserUpdatePassword(ctx, gen.UserUpdatePasswordParams{
		PasswordHash: store.StringToNullString(passwordHash),
		ID:           id,
	})
	if err != nil {
		return fmt.Errorf("could not update users new password: %w", err)
	}

	return nil
}

func (u *User) ChangePassword(ctx context.Context, passwords models.UpdatePasswordRequest, id string) error {
	user, err := u.Get(ctx, id)
	if err != nil {
		return fmt.Errorf("could not find user: %w", err)
	}

	ok, err := encryption.CompareHash(user.Password, passwords.OldPassword)
	if err != nil {
		return fmt.Errorf("could not compare passwords: %w", err)
	}
	if !ok {
		return fmt.Errorf("wrong password")
	}

	passwordHash, err := encryption.HashPassword(passwords.NewPassword)
	if err != nil {
		return fmt.Errorf("could not hash password: %w", err)
	}

	err = u.db.Queries.UserUpdatePassword(ctx, gen.UserUpdatePasswordParams{
		PasswordHash: store.StringToNullString(passwordHash),
		ID:           id,
	})
	if err != nil {
		return fmt.Errorf("could not update users new password: %w", err)
	}

	return nil
}

func (u *User) Verify(ctx context.Context, id string) error {
	err := u.db.Queries.VerifyUser(ctx, gen.VerifyUserParams{
		Verified: true,
		ID:       id,
	})
	if err != nil {
		return fmt.Errorf("could not verify user: %w", err)
	}

	return nil
}
