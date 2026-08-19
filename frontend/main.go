package frontend

import (
	"embed"
	"io/fs"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/FerberJ/goauth/frontend/components"
	p "github.com/FerberJ/goauth/frontend/middleware/pattern"
	loginpage "github.com/FerberJ/goauth/frontend/pages/login"
	loginfidopage "github.com/FerberJ/goauth/frontend/pages/loginfido"
	resetpwpage "github.com/FerberJ/goauth/frontend/pages/resetpw"
	signuppage "github.com/FerberJ/goauth/frontend/pages/signup"
	"github.com/FerberJ/goauth/middleware"
	"github.com/go-chi/chi/v5"
)

func Run(mw middleware.Middleware, pattern string) chi.Router {
	ro := chi.NewRouter()

	setupAssetsRoutes(ro)
	r := ro.With(p.NewHandler(pattern).PatternMw)
	loginpage.NewHandler(r, mw)
	signuppage.NewHandler(r, mw)
	resetpwpage.NewHandler(r, mw)
	loginfidopage.NewHandler(r, mw)

	return r
}

//go:embed assets/*
var assetsFS embed.FS

func setupAssetsRoutes(r *chi.Mux) {
	sub, err := fs.Sub(assetsFS, "assets")
	if err != nil {
		log.Fatal(err)
	}
	fileServer := http.FileServer(http.FS(sub))

	r.Get("/assets/*", func(w http.ResponseWriter, r *http.Request) {
		if os.Getenv("GO_ENV") != "production" {
			w.Header().Set("Cache-Control", "no-store")
		} else {
			w.Header().Set("Cache-Control", "public, max-age=31536000")
		}

		rctx := chi.RouteContext(r.Context())
		pathPrefix := strings.TrimSuffix(rctx.RoutePattern(), "/*")
		http.StripPrefix(pathPrefix, fileServer).ServeHTTP(w, r)
	})

	r.Get("/components/{bundle}", components.ScriptsHandler().ServeHTTP)
}
