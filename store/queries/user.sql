-- name: GetUser :one
SELECT * FROM auth_users
WHERE id = ? LIMIT 1;

-- name: GetFromMail :one
SELECT * FROM auth_users
WHERE mail = ? LIMIT 1;

-- name: CreateUser :one
INSERT INTO auth_users (
  id, name, password_hash, mail, credentials, verified
) VALUES (
  ?, ?, ?, ?, ?, FALSE
)
RETURNING *;

-- name: VerifyUser :exec
UPDATE auth_users
SET
  verified = ?
WHERE id = ?;

-- name: UpdateUserName :exec
UPDATE auth_users
SET
  name = ?
WHERE id = ?;

-- name: DeleteUser :exec
DELETE FROM auth_users
WHERE id = ?;

-- name: UserIDExists :one
SELECT EXISTS(
    SELECT 1 FROM auth_users WHERE id = ?
) AS id_exists;

-- name: UserUpdatePassword :exec
UPDATE auth_users
SET
  password_hash = ?
WHERE id = ?;

-- name: UserUpdateSignupCredentials :exec
UPDATE auth_users
SET
  credentials = ?,
  mail = ?
WHERE id = ?;