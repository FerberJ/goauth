package models

type ResetRequest struct {
	Email string
}

type ResetPassword struct {
	Email       string
	Password    string
	Token       string
	OldPassword string
}
