package models

type Password struct {
	ID        string
	TokenID   string
	UserID    string
	IssuedAt  int64
	ExpiresAt int64
	Revoked   bool
}
