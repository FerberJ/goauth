package models

type User struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Mail     string `json:"mail"`
	Password string `json:"-"`
	Verified bool   `json:"-"`
}
