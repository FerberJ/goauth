package models

type ResetRequest struct {
	Email string `validate:"required,email"`
}

func (t ResetRequest) Validate() error {
	return validate(t)
}

type ResetPassword struct {
	Password string `validate:"required"`
	Token    string `validate:"required"`
}

func (t ResetPassword) Validate() error {
	return validate(t)
}
