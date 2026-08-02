package main

import (
	"database/sql"
	"go/playground/api"
	"go/playground/auth"
	"go/playground/config"
	"go/playground/mail"
	"go/playground/store"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
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

	st, _ := store.Init(conn)

	mailClient, _ := mail.Init(conf.SMTP)

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	wa, _ := auth.Init()

	rout := api.GetRoutes(conf, st, mailClient, wa)

	r.Mount("/auth", rout)
	fs := http.FileServer(http.Dir("./static"))
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		fs.ServeHTTP(w, r)
	})
	r.Handle("/*", fs)

	chi.Walk(r, func(method, route string, handler http.Handler, middlewares ...func(http.Handler) http.Handler) error {
		log.Println("AUTH ROUTE:", method, route)
		return nil
	})

	addr := ":1122"
	log.Printf("listening on %s", addr)
	if err := http.ListenAndServe(addr, r); err != nil {
		log.Fatal(err)
	}

}
