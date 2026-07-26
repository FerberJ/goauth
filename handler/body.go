package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
)

func decodeBody[T any](r *http.Request) (T, error) {
	var t T

	err := json.NewDecoder(r.Body).Decode(&t)
	if err != nil {
		return t, fmt.Errorf("could not decode request body")
	}

	return t, nil
}
