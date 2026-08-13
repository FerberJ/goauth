package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"net/url"

	"github.com/FerberJ/goauth"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	_ "github.com/mattn/go-sqlite3"
)

func main() {
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	conn, err := sql.Open("sqlite3", "abcde.db")
	if err != nil {
		log.Fatal(err)
	}

	// authM.WithAppContext().GetClaim()
	a := goauth.New(conn).WithCustomVerifyUserMail(verifyUserMail).SetupRoutes()
	if a.Err() != nil {
		log.Fatal(a.Err())
	}

	if err := conn.Ping(); err != nil {
		log.Fatal(err)
	}

	r.Mount("/auth", a.Router())
	fs := http.FileServer(http.Dir("./static"))
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		fs.ServeHTTP(w, r)
	})
	r.Handle("/*", fs)

	l := r.With(a.Authorization)
	l.Get("/stuff", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	addr := ":1122"
	log.Printf("listening on %s", addr)
	if err := http.ListenAndServe(addr, r); err != nil {
		log.Fatal(err)
	}

}

func verifyUserMail(cfgEndpoint string, token string) (message string, sunject string, err error) {
	verifyURL, err := url.JoinPath(cfgEndpoint, "verify", token)
	if err != nil {
		return "", "", err
	}

	return buildVerifyLoginEmail(verifyURL), "Verify User", nil
}

const verifyLoginEmailHTML = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Verify Your Account</title>
</head>
<body style="margin:0;padding:0;background-color:#f4f4f7;font-family:Arial,Helvetica,sans-serif;">
  <table role="presentation" width="100%%" cellpadding="0" cellspacing="0" style="padding:40px 0;">
    <tr>
      <td align="center">
        <table role="presentation" width="480" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:8px;overflow:hidden;">
          <tr>
            <td style="padding:32px;text-align:center;">
              <h2 style="margin:0 0 16px;color:#1a1a1a;">Verify your Account</h2>
              <p style="color:#555555;font-size:14px;line-height:1.5;margin:0 0 24px;">
                We noticed a new Account with your email. Click the button below to verify it was you.
              </p>
              <a href="%s" style="display:inline-block;padding:12px 24px;background-color:#2563eb;color:#ffffff;text-decoration:none;border-radius:6px;font-size:14px;font-weight:bold;">
                Verify Account
              </a>
              <p style="color:#999999;font-size:12px;margin:24px 0 0;">
                If you didn't request this, you can safely ignore this email.
              </p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>`

func buildVerifyLoginEmail(verifyURL string) string {
	return fmt.Sprintf(verifyLoginEmailHTML, verifyURL)
}
