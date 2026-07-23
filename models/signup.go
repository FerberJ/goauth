package models

type SignupRequest struct {
	Name     string
	Email    string
	Password string
}
type RenameRequest struct {
	Name string
}

type LoginRequest struct {
	Email    string
	Password string
}

type UpdatePasswordRequest struct {
	OldPassword string
	NewPassword string
}
