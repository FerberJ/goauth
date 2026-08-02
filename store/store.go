package store

import (
	"context"
	"database/sql"
	"embed"
	"fmt"

	"github.com/FerberJ/goauth/store/gen"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/pressly/goose/v3"
)

type MigrateError struct {
	Op  string
	Err error
}

func (e *MigrateError) Error() string {
	return fmt.Sprintf("migrate: %s: %v", e.Op, e.Err)
}

func (e *MigrateError) Unwrap() error {
	return e.Err
}

type DB struct {
	DB      *sql.DB
	Queries *gen.Queries
	Session Session
}

// Init Database with the Queries from sqlc
// Mirgration will also be happing with `up`
// Returns Database Struct that has the postgres connection
// and queries
func Init(s *sql.DB) (DB, error) {
	db := DB{
		DB:      s,
		Queries: gen.New(s),
	}

	err := db.migrate()
	if err != nil {
		return db, err
	}

	session, err := initSession()
	if err != nil {
		return db, err
	}
	db.Session = session

	return db, nil
}

//go:embed migrations/*.sql
var embedMigrations embed.FS

// Migrate the database structer into postgres
// return a custom error Migrate error for sorting out during testing
func (db DB) migrate() error {
	goose.SetBaseFS(embedMigrations)

	err := goose.SetDialect("sqlite")
	if err != nil {
		return &MigrateError{Op: "set dialect", Err: err}
	}

	err = goose.Up(db.DB, "migrations")
	if err != nil {
		return &MigrateError{Op: "up", Err: err}
	}

	return nil
}

func Open(dataSourceName string) (*sql.DB, error) {
	return sql.Open("sqlite3", dataSourceName)
}

type Datatable int

const (
	User Datatable = iota
	Verification
	Refresh
	Password
)

func (db DB) CreateID(ctx context.Context, dt Datatable) (string, error) {
	id := ""
	for {
		var err error
		var exists bool
		id = uuid.NewString()

		switch dt {
		case User:
			exists, err = db.Queries.UserIDExists(ctx, id)
		case Verification:
			exists, err = db.Queries.VerificationIDExists(ctx, id)
		case Refresh:
			exists, err = db.Queries.RefreshExists(ctx, id)
		case Password:
			exists, err = db.Queries.PasswordForgotExists(ctx, id)
		default:
			err = fmt.Errorf("creating a id for this table has not been implemented yet!")
		}

		if err != nil {
			return "", err
		}
		if !exists {
			break
		}
	}

	return id, nil
}
