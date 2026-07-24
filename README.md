POST /signup (email, password, name) -> Send verification email
POST /verify-email (verificationToken) -> Success
POST /login (email, password) -> accessToken, refreshToken
POST /logout (refreshToken or current session) -> Invalidate refresh token
POST /refresh (refreshToken) -> accessToken, refreshToken (recommended to rotate)
POST /forgot-password (email) -> Send reset email
POST /reset-password (resetToken, newPassword) -> Success
POST /change-password (oldPassword, newPassword) -> Auth required
GET /me -> User
~~PATCH /me -> Update profile~~
DELETE /me -> Delete account