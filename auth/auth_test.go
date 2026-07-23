package auth

import (
	"database/sql"
	"errors"
	"go/playground/store"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func TestInit(t *testing.T) {
	conn, _ := sql.Open("sqlite3", ":memory:")
	err := Init("secret", conn)
	if err != nil {
		_, ok := errors.AsType[*store.MigrateError](err)
		if !ok {
			t.Error(err)
		}
	}
}
