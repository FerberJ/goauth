package main

import (
	"context"
	"database/sql"
	"fmt"
	"go/playground/auth"
	"go/playground/config"
	"go/playground/models"
	"log"
	"net/http"

	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/chi/v5"
	_ "github.com/mattn/go-sqlite3"
)

func main() {
	conn, err := sql.Open("sqlite3", "abcd.db")
	if err != nil {
		log.Fatal(err)
	}

	conf, _ := config.GetConf(conn)

	if err := conn.Ping(); err != nil {
		log.Fatal(err)
	}
	a, err := auth.Init(conf)

	ctx := context.Background()
	s := models.SignupRequest{
		Name:     "efrrruru",
		Email:    "abc@derurr.com",
		Password: "superPW",
	}
	token, err := a.Signup(ctx, s)
	fmt.Println(token)

	err = a.VerifyEmail(ctx, token)

	fmt.Println("what happend?")

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Mount("/auth", a.GetRoutes())

	addr := ":1122"
	log.Printf("listening on %s", addr)
	if err := http.ListenAndServe(addr, r); err != nil {
		log.Fatal(err)
	}

}
