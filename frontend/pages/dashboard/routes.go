package dashboardpage

import (
	"net/http"

	"github.com/FerberJ/goauth/frontend/components/button"
	"github.com/FerberJ/goauth/frontend/components/loginfidoform"
	"github.com/FerberJ/goauth/frontend/components/loginform"
)

func (h *Handler) addRoutes() {
	r := h.r.With(h.mw.Authorization)
	h.r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		Dashboard().Render(r.Context(), w)
	})
	r.Get("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		component := button.Button()

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := component.Render(r.Context(), w); err != nil {
			http.Error(w, "failed to render", http.StatusInternalServerError)
			return
		}
	})
	h.r.Get("/fido", func(w http.ResponseWriter, r *http.Request) {
		component := loginfidoform.LoginForm()

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := component.Render(r.Context(), w); err != nil {
			http.Error(w, "failed to render", http.StatusInternalServerError)
			return
		}
	})
	h.r.Get("/login", func(w http.ResponseWriter, r *http.Request) {
		component := loginform.LoginForm()

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := component.Render(r.Context(), w); err != nil {
			http.Error(w, "failed to render", http.StatusInternalServerError)
			return
		}
	})
}
