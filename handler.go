package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	uuid "github.com/satori/go.uuid"
	"fmt"
	"encoding/base64"
	"database/sql"
)

func BuildAuthorizationMiddleware(next http.Handler, token string) http.HandlerFunc {
	result := func(w http.ResponseWriter, r *http.Request) {
		providedToken := r.Header.Get("Authorization")
		if providedToken != token {
			w.WriteHeader(403)
			return
		}
		next.ServeHTTP(w, r)
	}
	return result
}

func BuildHealthHandler(db *sql.DB) VarsHandler {
	result := func(w http.ResponseWriter, r *http.Request, vars map[string]string) int {
		err := db.Ping()
		if err != nil {
			return 500
		}
		return 200
	}
	return result
}

func BuildGetSchemaHandler(repo AccountRepository) VarsHandler {
	result := func(w http.ResponseWriter, r *http.Request, vars map[string]string) int {
		accountName := vars["accountName"]

		account, err := repo.GetAccount(accountName)

		if err != nil {
			switch err {
			case sql.ErrNoRows:
				return 404
			default:
				log.Println(err)
				return 500
			}
		}
		encoder := json.NewEncoder(w)
		encoder.Encode(account)
		return 0
	}

	return result
}

func BuildCreateSchemaHandler(repo AccountRepository, pwdGenerator PasswordGenerator) VarsHandler {
	result := func(w http.ResponseWriter, r *http.Request, vars map[string]string) int {

		decoder := json.NewDecoder(r.Body)

		var account DatabaseAccount
		err := decoder.Decode(&account)
		if err != nil {
			fmt.Println(err)
			return 400
		}
		cleartextPassword := pwdGenerator()
		block, _ := pem.Decode([]byte(account.PublicKeyPEM))

		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			fmt.Println(err)
			return 400
		}

		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return 400
		}
		label := []byte("orders")
		rng := rand.Reader

		encryptedPwd, err := rsa.EncryptOAEP(sha256.New(), rng, rsaPub, []byte(cleartextPassword), label)
		if err != nil {
			return 500
		}

		account.EncryptedPwd = base64.StdEncoding.EncodeToString(encryptedPwd)

		err = repo.SaveAccount(&account, cleartextPassword)

		if err != nil {
			return 409
		}

		w.WriteHeader(201)
		encoder := json.NewEncoder(w)
		err = encoder.Encode(account)

		if err != nil {
			log.Println(err)
		}

		return 0

	}
	return result
}

type VarsHandler func(w http.ResponseWriter, r *http.Request, vars map[string]string) int

func (vh VarsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	code := vh(w, r, vars)
	if code != 0 {
		w.WriteHeader(code)
	}
}

type PasswordGenerator func() string

func UUIDPasswordGenerator() string {
	return uuid.NewV4().String()
}
