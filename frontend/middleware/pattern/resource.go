package pattern

type Handler struct {
	pattern string
}

func NewHandler(pattern string) *Handler {
	return &Handler{
		pattern: pattern,
	}
}
