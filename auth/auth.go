package auth

import "github.com/go-webauthn/webauthn/webauthn"

func Init() (*webauthn.WebAuthn, error) {
	webAuthn, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "My App",
		RPID:          "localhost", // domain, no scheme/port
		RPOrigins:     []string{"http://localhost:1122"},
	})
	return webAuthn, err
}
