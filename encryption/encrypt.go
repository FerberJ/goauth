package encryption

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

var (
	memory      uint32 = 64 * 1024 // 64 MB
	iterations  uint32 = 3
	parallelism uint8  = 4
	saltLength  uint32 = 16
	keyLength   uint32 = 32
)

func HashPassword(password string) (string, error) {
	salt := make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, keyLength)

	// Encode the parts into a standard string format:
	// $argon2id$v=19$m=65536,t=3,p=4$<base64-salt>$<base64-hash>
	// "v=19" is the version number for Argon2
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	format := "$argon2id$v=%v$m=%d,t=%d,p=%d$%s$%s"
	full := fmt.Sprintf(format, argon2.Version, memory, iterations, parallelism, b64Salt, b64Hash)

	return full, nil
}

func CompareHash(hashStr, password string) (bool, error) {
	// Split the hash string into parts
	vals := strings.Split(hashStr, "$")
	if len(vals) != 6 {
		return false, errors.New("invalid hash format")
	}

	if vals[1] != "argon2id" {
		return false, errors.New("incompatible algorithm")
	}

	if vals[2] != fmt.Sprintf("v=%v", argon2.Version) {
		return false, errors.New("wrong argons2 version")
	}

	var mem, iter uint32
	var parrall uint8
	_, err := fmt.Sscanf(vals[3], "m=%d,t=%d,p=%d", &mem, &iter, &parrall)
	if err != nil {
		return false, err
	}

	// Decode salt and hash
	salt, err := base64.RawStdEncoding.DecodeString(vals[4])
	if err != nil {
		return false, err
	}

	decodedHash, err := base64.RawStdEncoding.DecodeString(vals[5])
	if err != nil {
		return false, err
	}

	comparisonHash := argon2.IDKey([]byte(password), salt, iter, mem, parrall, uint32(len(decodedHash)))

	return subtle.ConstantTimeCompare(decodedHash, comparisonHash) == 1, nil
}

func GenerateRandomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
