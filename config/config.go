package config

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	SMTP         SMTP
	Secret       string
	DB           *sql.DB
	Verification Verification
	Password     Password
	Refresh      Refresh
}

type Refresh struct {
	TokenTTL time.Duration
}
type Verification struct {
	TokenBytes int
	TokenTTL   time.Duration
	Endpoint   string
}

type Password struct {
	TokenBytes int
	TokenTTL   time.Duration
	Endpoint   string
}

type SMTP struct {
	Client   string
	Username string
	Password string
	Port     int
}

func GetConf(db *sql.DB) (Config, error) {
	var conf Config = Config{}
	err := godotenv.Load() // loads ".env" from current directory by default
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	secret := os.Getenv("AUTH_SECRET")

	// SMTP
	client := os.Getenv("AUTH_SMTP_CLIENT")
	username := os.Getenv("AUTH_SMTP_USERNAME")
	password := os.Getenv("AUTH_SMTP_PASSWORD")
	portStr := os.Getenv("AUTH_SMTP_PORT")
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return conf, fmt.Errorf("port must be a int: %w", err)
	}

	// Verification
	tokenBytesStr := os.Getenv("AUTH_VERIFICATION_TOKEN_BYTES")
	tokenBytes, err := strconv.Atoi(tokenBytesStr)
	if err != nil {
		return conf, fmt.Errorf("tokenBytes must be a int: %w", err)
	}
	tokenTTLStr := os.Getenv("AUTH_VERIFICATION_TOKEN_TTL")
	tokenTTL, err := strconv.Atoi(tokenTTLStr)
	if err != nil {
		return conf, fmt.Errorf("verification tokenTTL must be a int: %w", err)
	}
	endpoint := os.Getenv("AUTH_VERIFICATION_ENDPOINT")

	// Password forgot token
	pwTokenBytesStr := os.Getenv("AUTH_PASSWORD_TOKEN_BYTES")
	pwTokenBytes, err := strconv.Atoi(pwTokenBytesStr)
	if err != nil {
		return conf, fmt.Errorf("password tokenBytes must be a int: %w", err)
	}
	pwTokenTTLStr := os.Getenv("AUTH_PASSWORD_TOKEN_TTL")
	pwTokenTTL, err := strconv.Atoi(pwTokenTTLStr)
	if err != nil {
		return conf, fmt.Errorf("verification password tokenTTL must be a int: %w", err)
	}
	pwEndpoint := os.Getenv("AUTH_PASSWORD_ENDPOINT")

	// Refresh
	tokenTTLRefreshStr := os.Getenv("AUTH_PASSWORD_TOKEN_TTL")
	tokenTTLRefresh, err := strconv.Atoi(tokenTTLRefreshStr)
	if err != nil {
		return conf, fmt.Errorf("refresh password tokenTTL must be a int: %w", err)
	}

	conf = Config{
		Secret: secret,
		DB:     db,
		SMTP: SMTP{
			Client:   client,
			Username: username,
			Password: password,
			Port:     port,
		},
		Password: Password{
			TokenBytes: pwTokenBytes,
			TokenTTL:   time.Duration(pwTokenTTL),
			Endpoint:   pwEndpoint,
		},
		Verification: Verification{
			TokenBytes: tokenBytes,
			TokenTTL:   time.Duration(tokenTTL),
			Endpoint:   endpoint,
		},
		Refresh: Refresh{
			TokenTTL: time.Duration(tokenTTLRefresh),
		},
	}

	return conf, nil
}
