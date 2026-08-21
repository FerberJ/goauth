# goauth

A drop-in authentication module for [chi](https://github.com/go-chi/chi)-based Go applications. Mount it on a router and get signup/login, email verification, password reset, JWT + refresh-token sessions, WebAuthn/FIDO2 passwordless auth, admin user management, and a ready-made HTMX/Tailwind admin dashboard — backed by SQLite.

```go
module github.com/FerberJ/goauth
```

## Features

- **Email + password auth** — signup, login, logout, email verification
- **JWT sessions with rotating refresh tokens** — short-lived HS256 access token in a cookie, long-lived opaque refresh token (hashed at rest) with rotation on every `/refresh` call
- **Password management** — forgot/reset via emailed one-time token, change-password while authenticated
- **WebAuthn / FIDO2** — passwordless signup and login (`/signup/fido/*`, `/login/fido/*`) and adding a security key to an existing account (`/profile/fido/*`)
- **Admin API** — list/create/read/update/delete users, force-verify a user, manage profile images
- **Profile images** — upload/download an avatar, stored as a `BLOB` in SQLite
- **Built-in admin dashboard** — server-rendered [templ](https://templ.guide) + HTMX + Tailwind UI mounted alongside the API, gated behind auth + admin middleware
- **Pluggable email templates** — override the verification and reset-password email builders
- **Argon2id password hashing**, SHA-256 token hashing, constant-time comparisons
- **Schema-managed SQLite** — migrations run automatically via [goose](https://github.com/pressly/goose) on startup, queries generated with [sqlc](https://sqlc.dev)

## Installation

```bash
go get github.com/FerberJ/goauth
```

Requires Go 1.26+ and CGO (for `mattn/go-sqlite3`).

## Quick start

```go
package main

import (
	"database/sql"
	"log"
	"net/http"

	"github.com/FerberJ/goauth"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	_ "github.com/mattn/go-sqlite3"
)

func main() {
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	conn, err := sql.Open("sqlite3", "auth.db")
	if err != nil {
		log.Fatal(err)
	}

	auth := goauth.New(conn).WithPattern("/auth")
	if auth.Err() != nil {
		log.Fatal(auth.Err())
	}

	// Mounts the API under /auth and the dashboard under /auth/_/
	if err := auth.GetRoutes(r); err != nil {
		log.Fatal(err)
	}

	// Protect your own routes with the same middleware
	protected := r.With(auth.Authorization)
	protected.Get("/stuff", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	log.Fatal(http.ListenAndServe(":1122", r))
}
```

See [example/basic/main.go](example/basic/main.go) for a runnable example.

### Builder options

| Method | Purpose |
|---|---|
| `.WithPattern(pattern string)` | Base path the API + dashboard are mounted under (default `/auth`) |
| `.WithCustomVerifyUserMail(fn)` | Override the verification email's subject/body builder |
| `.WithCustomResetPasswordMail(fn)` | Override the password-reset email's subject/body builder |
| `.GetRoutes(r *chi.Mux) error` | Initializes the DB, mail client, WebAuthn, and mounts all routes |
| `.Authorization` | `func(http.Handler) http.Handler` — require a valid session cookie |
| `.Admin` | `func(http.Handler) http.Handler` — require `Authorization` **and** `admin = true` |
| `.GetLoginForm()` / `.GetSignupForm()` | `templ.Component` you can embed in your own pages |

## Configuration

Configuration is loaded from a `.env` file (via [godotenv](https://github.com/joho/godotenv)) / the process environment on `goauth.New()`.

| Variable | Description |
|---|---|
| `AUTH_SECRET` | HMAC secret used to sign JWT access tokens |
| `AUTH_SMTP_CLIENT` | SMTP host |
| `AUTH_SMTP_USERNAME` | SMTP username (also used as the `From` address) |
| `AUTH_SMTP_PASSWORD` | SMTP password |
| `AUTH_SMTP_PORT` | SMTP port |
| `AUTH_VERIFICATION_TOKEN_BYTES` | Entropy (bytes) for email-verification tokens |
| `AUTH_VERIFICATION_TOKEN_TTL` | Verification token lifetime, in **seconds** |
| `AUTH_VERIFICATION_ENDPOINT` | Base URL used to build the verification link |
| `AUTH_PASSWORD_TOKEN_BYTES` | Entropy (bytes) for password-reset tokens |
| `AUTH_PASSWORD_TOKEN_TTL` | Password-reset token lifetime, in **seconds** |
| `AUTH_PASSWORD_ENDPOINT` | Base URL used to build the password-reset link |
| `AUTH_REFRESH_TOKEN_TTL` | Refresh token lifetime, in **seconds** |

See [example.env](example.env) for a template.

## API reference

All request/response bodies are JSON unless noted. Endpoints under **Auth required** expect the `authorization` cookie set by `/login`, `/login/fido/finish`, or `/refresh`. Endpoints under **Admin required** additionally require the caller's user record to have `admin = true`.

Errors share one envelope:

```json
{ "success": false, "error": { "code": "003", "message": "...", "status": 400 } }
```

### Public

| Method & path | Body / params | Description |
|---|---|---|
| `POST /signup` | `{firstname, lastname, username, email, password}` | Creates an unverified user, emails a verification link |
| `POST /signup/fido/begin` | query `?email=` | Starts WebAuthn registration for a new passwordless account, returns `PublicKeyCredentialCreationOptions` |
| `POST /signup/fido/finish` | query `?email=`, WebAuthn attestation response | Completes registration, stores the credential, emails a verification link |
| `GET /verify/{token}` | path param `token` | Marks the user `verified = true` |
| `POST /login` | `{email, password}` | Verifies password, sets `authorization` (JWT) + `refresh` cookies |
| `POST /login/fido/begin` | query `?email=` | Starts WebAuthn assertion, returns `PublicKeyCredentialRequestOptions` |
| `POST /login/fido/finish` | query `?email=`, WebAuthn assertion response | Completes assertion, sets `authorization` + `refresh` cookies |
| `POST /logout` | cookie `refresh` | Revokes the refresh token, clears both cookies |
| `POST /refresh` | cookie `refresh` | Rotates the refresh token, issues a new JWT + refresh cookie |
| `POST /password/forgot` | `{email}` | Emails a password-reset token |
| `POST /password/reset` | `{token, password}` | Consumes the reset token, sets a new password |

### Authenticated (`Authorization` middleware)

| Method & path | Body / params | Description |
|---|---|---|
| `POST /profile/password/change` | `{oldPassword, password}` | Changes the current user's password |
| `POST /profile/fido/begin` | — | Starts WebAuthn registration to add a credential to the current account |
| `POST /profile/fido/finish` | WebAuthn attestation response | Stores the new credential on the current account |
| `GET /profile` | — | Returns the current user (`id, username, firstname, lastname, mail, admin`) |
| `PUT /profile` | `{username, firstname, lastname, email}` | Updates the current user's profile |
| `DELETE /profile` | — | Deletes the current user's account |
| `PUT /profile/image` | multipart form, field `avatar` (≤5MB) | Sets the current user's avatar |
| `GET /profile/image` | — | Streams the current user's avatar |

### Admin (`Authorization` + `Admin` middleware)

| Method & path | Body / params | Description |
|---|---|---|
| `POST /admin/users` | `{firstname, lastname, username, email, password}` | Creates a user (pre-verified flow not triggered) |
| `GET /admin/users` | query `?limit=&offset=` | Lists users |
| `GET /admin/users/{id}` | path param `id` | Gets a single user |
| `PUT /admin/users/{id}` | `{username, firstname, lastname, email}` | Updates a user |
| `DELETE /admin/users/{id}` | path param `id` | Deletes a user |
| `POST /admin/users/{id}/verify` | path param `id` | Sends that user a fresh verification email |
| `PUT /admin/users/{id}/image` | multipart form, field `avatar` (≤5MB) | Sets a user's avatar |
| `GET /admin/users/{id}/image` | path param `id` | Streams a user's avatar |

### Dashboard (server-rendered)

Mounted under `<pattern>/_/` (e.g. `/auth/_/`), gated behind `Authorization` + `Admin` except `/login`:

| Path | Description |
|---|---|
| `GET /_/` , `GET /_/dashboard` | Admin dashboard — user table, sidebar nav (templ + HTMX) |
| `GET /_/login` | Standalone email/password login page |
| `GET /_/fido` | Standalone WebAuthn login page |
| `GET /_/signup` | Standalone signup page |
| `GET /_/reset` | Standalone password-reset page |
| `GET /_/assets/*` | Embedded static assets (HTMX, JS) |
| `GET /_/components/{bundle}` | Bundled component scripts |

## Database / storage

goauth uses **two** storage backends, both created automatically inside `goauth.New()` / `.GetRoutes()`:

### SQLite (`database/sql` + sqlc + goose)

The caller supplies the `*sql.DB` (any SQLite driver connection); goauth owns the schema. On every startup, [goose](https://github.com/pressly/goose) applies embedded migrations from [store/migrations](store/migrations) against a dedicated `goose_db_auth_version` tracking table, so it's safe to point goauth at a database also used by the host application. All queries are generated by [sqlc](https://sqlc.dev) from [store/queries](store/queries) into [store/gen](store/gen) (see [sqlc.yaml](sqlc.yaml)).

| Table | Purpose | Key columns |
|---|---|---|
| `auth_users` | User accounts | `id` (UUID PK), `mail` (unique), `password_hash` (argon2id, empty for FIDO-only accounts), `username`, `firstname`, `lastname`, `verified`, `admin`, `credentials` (JSON array of WebAuthn credentials), `image` (BLOB avatar) |
| `auth_verification` | Email-verification tokens | `id`, `token_id` (SHA-256 hash of the emailed token), `user_id`, `issued_at`, `expires_at`, `revoked` |
| `auth_refresh` | Refresh tokens | same shape as above; one row per active/rotated session, deleted on logout |
| `auth_password_forgot` | Password-reset tokens | same shape as above |
| `webauthn_credentials` | Reserved for a normalized WebAuthn credential store (FK to `auth_users`, cascade delete) | *currently unused — credentials are stored inline as JSON on `auth_users.credentials`* |

Notes:
- Raw tokens are never stored — only `sha256(token)` (`encryption.HashToken`), so a DB leak alone can't be replayed as a live session.
- Passwords are hashed with **argon2id** (`m=64MB, t=3, p=4`) and compared in constant time.
- IDs are UUIDv4, generated with a collision-check loop (`store.DB.CreateID`) against the target table before insert.
- `sqlc.arg('limit')`/`offset` power paginated `GET /admin/users` listing.

### Badger (embedded KV store)

A [badger/v4](https://github.com/dgraph-io/badger) instance is opened at `./tmp/badger` on init (`store/session.go`) and used **only** to hold transient WebAuthn ceremony state (ephemeral ~5 minute TTL) between the `begin` and `finish` steps of registration/login — it is not used for anything else and is safe to wipe between deploys.

## Package layout

| Package | Responsibility |
|---|---|
| [api](api) | Wires the chi router: public, authenticated, and admin route groups + dashboard mount |
| [handler](handler) | HTTP handlers — request parsing, cookie management, calls into `service` |
| [service](service) | Business logic per domain (`user`, `verification`, `refresh`, `password`) |
| [models](models) | Request/response DTOs and validation tags (`go-playground/validator`) |
| [store](store) | SQLite connection, goose migrations, sqlc-generated queries, Badger session store |
| [config](config) | `.env`-driven configuration |
| [middleware](middleware) | `Authorization` / `Admin` chi middleware, claim extraction |
| [token](token) | JWT (HS256) issuance/verification, refresh-token entropy |
| [encryption](encryption) | Argon2id password hashing, SHA-256 token hashing |
| [mail](mail) | SMTP client + default verification/reset email builders |
| [auth](auth) | WebAuthn (`go-webauthn`) relying-party setup |
| [error_msg](error_msg) | Shared JSON error envelope + numbered error codes |
| [frontend](frontend) | templ + HTMX + Tailwind admin dashboard and auth pages |

## Frontend / dashboard development

The dashboard UI is built with [templ](https://templ.guide), [Tailwind CSS v4](https://tailwindcss.com), and [shadcn-templ](https://shadcn-templ.com) components (see [components.json](components.json)). `.templ` files are compiled to `_templ.go` files and checked in — regenerate with the `templ` CLI after editing any `.templ` file:

```bash
templ generate
```

Tailwind classes are compiled via the CLI declared in [package.json](package.json):

```bash
npm install
npx @tailwindcss/cli -i frontend/css/globals.css -o frontend/assets/app.css
```

## Regenerating SQL code

After editing anything under [store/queries](store/queries) or [store/schemas/schema.sql](store/schemas/schema.sql):

```bash
sqlc generate
```

New schema changes belong in a new file under [store/migrations](store/migrations) (goose format) — `store/schemas/schema.sql` is the sqlc-facing snapshot, not what runs at startup.
