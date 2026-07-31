package store

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/dgraph-io/badger/v4"
	"github.com/go-webauthn/webauthn/webauthn"
)

type Session struct {
	*badger.DB
}

func initSession() (Session, error) {
	var session Session
	db, err := badger.Open(badger.DefaultOptions("./tmp/badger"))
	if err != nil {
		return session, fmt.Errorf("could not open new badger instants: %w", err)
	}

	session.DB = db
	return session, nil
}

func (s Session) Set(key string, sessionData *webauthn.SessionData) error {
	sessionByte, err := json.Marshal(sessionData)
	if err != nil {
		return fmt.Errorf("could not marshal sessionData: %w", err)
	}

	err = s.DB.Update(func(txn *badger.Txn) error {
		entry := badger.NewEntry([]byte(key), sessionByte).WithTTL(5 * time.Minute)
		return txn.SetEntry(entry)
	})
	if err != nil {
		return fmt.Errorf("could not save session data: %w", err)
	}

	return nil
}

func (s Session) Get(key string) (*webauthn.SessionData, error) {
	var sessionData *webauthn.SessionData

	err := s.DB.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(key))
		if err != nil {
			return fmt.Errorf("could not get session data from key: %w", err)
		}

		return item.Value(func(val []byte) error {
			if err := json.Unmarshal(val, &sessionData); err != nil {
				return fmt.Errorf("could not unmarshal session data: %w", err)
			}
			return nil
		})
	})
	if err != nil {
		return nil, err
	}

	return sessionData, nil
}
