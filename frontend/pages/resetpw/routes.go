package resetpwpage

import "net/http"

func (h *Handler) addRoutes() {
	h.r.Get("/reset", func(w http.ResponseWriter, r *http.Request) {
		ResetPw().Render(r.Context(), w)
	})
}
