package signuppage

import "net/http"

func (h *Handler) addRoutes() {
	h.r.Get("/signup", func(w http.ResponseWriter, r *http.Request) {
		Signup().Render(r.Context(), w)
	})
}
