package models

type SignupRequest struct {
	Name     string `validate:"required"`
	Email    string `validate:"required,email"`
	Password string `validate:"required"`
}

func (t SignupRequest) Validate() error {
	return validate(t)
}

type RenameRequest struct {
	Name string `validate:"required"`
}

func (t RenameRequest) Validate() error {
	return validate(t)
}

type LoginRequest struct {
	Email    string `validate:"required,email"`
	Password string `validate:"required"`
}

func (t LoginRequest) Validate() error {
	return validate(t)
}

type UpdatePasswordRequest struct {
	OldPassword string
	NewPassword string
}

type UpdatePassword struct {
	Password    string `validate:"required"`
	OldPassword string `validate:"required"`
}

func (t UpdatePassword) Validate() error {
	return validate(t)
}
