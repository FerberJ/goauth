package models

import "github.com/go-playground/validator/v10"

type Validate interface {
	Validate() error
}

func validate(t any) error {
	validate := validator.New(validator.WithRequiredStructEnabled())
	return validate.Struct(t)
}
