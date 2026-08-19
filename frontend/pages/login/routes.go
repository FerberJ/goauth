package loginpage

import "net/http"

func (h *Handler) addRoutes() {
	h.r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		if h.mw.IsAuthorized(r) {
			if h.mw.IsAdmin(r) {
				// Load Dashboard
			} else {
				// Load Profile Editor
			}
		} else {
			Login().Render(r.Context(), w)
		}
	})
}
