package store

import "database/sql"

func NullStringToString(s sql.NullString) string {
	if s.Valid {
		return s.String
	} else {
		return ""
	}
}

func StringToNullString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{Valid: false}
	}

	return sql.NullString{
		String: s,
		Valid:  true,
	}
}
