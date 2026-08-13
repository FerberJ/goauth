package models

type SignupRequest struct {
	Firstname string
	Lastname  string
	Username  string `validate:"required"`
	Email     string `validate:"required,email"`
	Password  string `validate:"required"`
}

func (t SignupRequest) Validate() error {
	return validate(t)
}

type UpdateRequest struct {
	Username  string
	Firstname string
	Lastname  string
	Email     string `validate:"email"`
}

func (t UpdateRequest) Validate() error {
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
