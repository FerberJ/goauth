package models

import (
	"encoding/json"
	"fmt"
	"go/playground/store"
	"go/playground/store/gen"
	"net/http"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

type User struct {
	ID          string                `json:"id"`
	Name        string                `json:"name"`
	Mail        string                `json:"mail"`
	Password    string                `json:"-"`
	Verified    bool                  `json:"-"`
	Credentials []webauthn.Credential `json:"-"`
}

func (u *User) WebAuthnID() []byte                         { return []byte(u.ID) }
func (u *User) WebAuthnName() string                       { return u.Mail }
func (u *User) WebAuthnDisplayName() string                { return u.Mail }
func (u *User) WebAuthnCredentials() []webauthn.Credential { return u.Credentials }
func (u *User) WebAuthnIcon() string                       { return "" }

func GetUser(u gen.AuthUser) (User, error) {
	var user User
	var creds []webauthn.Credential

	if err := json.Unmarshal(u.Credentials, &creds); err != nil {
		return user, err
	}

	user = User{
		ID:          u.ID,
		Name:        store.NullStringToString(u.Name),
		Mail:        u.Mail,
		Password:    store.NullStringToString(u.PasswordHash),
		Verified:    u.Verified,
		Credentials: creds,
	}

	return user, nil
}

func (u *User) BeginRegistration(db store.DB, webAuthn *webauthn.WebAuthn) (*protocol.CredentialCreation, error) {
	options, sessionData, err := webAuthn.BeginRegistration(u)
	if err != nil {
		return nil, err
	}

	err = db.Session.Set(u.Mail, sessionData)
	if err != nil {
		return nil, err
	}

	return options, nil
}

func (u *User) FinishRegistration(db store.DB, webAuthn *webauthn.WebAuthn, r *http.Request) error {
	sessionData, err := db.Session.Get(u.Mail)
	if err != nil {
		return err
	}
	if sessionData == nil {
		return fmt.Errorf("no registration session for user")
	}

	credential, err := webAuthn.FinishRegistration(u, *sessionData, r)
	if err != nil {
		return err
	}

	u.Credentials = append(u.Credentials, *credential)

	return nil
}

func (u *User) BeginLogin(db store.DB, webAuthn *webauthn.WebAuthn) (*protocol.CredentialAssertion, error) {
	options, sessionData, err := webAuthn.BeginLogin(u)
	if err != nil {
		return nil, err
	}

	err = db.Session.Set(u.ID, sessionData)
	if err != nil {
		return nil, err
	}

	return options, nil
}

func (u *User) FinishLogin(db store.DB, webAuthn *webauthn.WebAuthn, r *http.Request) error {
	sessionData, err := db.Session.Get(u.ID)
	if err != nil {
		return err
	}
	if sessionData == nil {
		return fmt.Errorf("no login session for user")
	}

	_, err = webAuthn.FinishLogin(u, *sessionData, r)
	if err != nil {
		return err
	}
	return nil
}
