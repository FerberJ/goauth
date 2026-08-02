package handler

import (
	"encoding/json"
	"fmt"
	"go/playground/models"
	"net/http"
)

func getValidBody[T models.Validate](r *http.Request) (T, error) {
	var t T

	err := json.NewDecoder(r.Body).Decode(&t)
	if err != nil {
		return t, fmt.Errorf("could not decode request body")
	}

	err = t.Validate()
	if err != nil {
		return t, fmt.Errorf("could not validate request: %w", err)
	}

	return t, nil
}
