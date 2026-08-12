package errormsg

import (
	"encoding/json"
	"net/http"
)

type Msg struct {
	Success bool `json:"success"`
	Error   Err  `json:"error"`
}

type Err struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Status  int    `json:"status"`
}

func responseWriter(w http.ResponseWriter, code string, status int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	_ = json.NewEncoder(w).Encode(Msg{
		Success: false,
		Error: Err{
			Code:    code,
			Message: err.Error(),
			Status:  status,
		},
	})
}

// 001
func AppContextErr(w http.ResponseWriter, err error) {
	responseWriter(w, "001", http.StatusInternalServerError, err)
}

// 002
func ClaimErr(w http.ResponseWriter, err error) {
	responseWriter(w, "002", http.StatusBadRequest, err)
}

// 003
// When Get a entry
func GetEntryErr(w http.ResponseWriter, err error) {
	responseWriter(w, "003", http.StatusBadRequest, err)
}

// 004
func DecodeErr(w http.ResponseWriter, err error) {
	responseWriter(w, "004", http.StatusInternalServerError, err)
}

// 005
func UpdateErr(w http.ResponseWriter, err error) {
	responseWriter(w, "005", http.StatusInternalServerError, err)
}

// 006
func CreateErr(w http.ResponseWriter, err error) {
	responseWriter(w, "006", http.StatusInternalServerError, err)
}

// 007
func JoinPathErr(w http.ResponseWriter, err error) {
	responseWriter(w, "007", http.StatusInternalServerError, err)
}

// 008
func SendMailErr(w http.ResponseWriter, err error) {
	responseWriter(w, "008", http.StatusInternalServerError, err)
}

// 009
func ValidatePasswordErr(w http.ResponseWriter, err error) {
	responseWriter(w, "009", http.StatusBadRequest, err)
}

// 010
func GetTokenErr(w http.ResponseWriter, err error) {
	responseWriter(w, "010", http.StatusInternalServerError, err)
}

// 011
func GetCookieErr(w http.ResponseWriter, err error) {
	responseWriter(w, "011", http.StatusBadRequest, err)
}

// 012
func DeleteErr(w http.ResponseWriter, err error) {
	responseWriter(w, "012", http.StatusBadRequest, err)
}

// 013
func ExpireErr(w http.ResponseWriter, err error) {
	responseWriter(w, "013", http.StatusBadRequest, err)
}

// 014
func RevokeErr(w http.ResponseWriter, err error) {
	responseWriter(w, "014", http.StatusBadRequest, err)
}

// 015
func VerifyErr(w http.ResponseWriter, err error) {
	responseWriter(w, "015", http.StatusBadRequest, err)
}

// 016
func WrongUserErr(w http.ResponseWriter, err error) {
	responseWriter(w, "016", http.StatusBadRequest, err)
}

// 017
func UpdatePasswordErr(w http.ResponseWriter, err error) {
	responseWriter(w, "017", http.StatusBadRequest, err)
}

// 018
func RequestErr(w http.ResponseWriter, err error) {
	responseWriter(w, "018", http.StatusBadRequest, err)
}

// 019
func BeginRegistrationErr(w http.ResponseWriter, err error) {
	responseWriter(w, "019", http.StatusInternalServerError, err)
}

// 020
func UserAlreadyExistsErr(w http.ResponseWriter, err error) {
	responseWriter(w, "020", http.StatusBadRequest, err)
}

// 021
func ResetPasswordErr(w http.ResponseWriter, err error) {
	responseWriter(w, "021", http.StatusInternalServerError, err)
}

// 022
func ParseQueryErr(w http.ResponseWriter, err error) {
	responseWriter(w, "022", http.StatusBadRequest, err)
}
