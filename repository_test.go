package main

import (
	"testing"
	"fmt"
	"database/sql"
	"os"
	"github.com/stretchr/testify/assert"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"crypto/rand"
)

func TestIntegrationCreateSchema(t *testing.T) {

	repo.SaveAccount()
}

func prepareRepo(t *testing.T) AccountRepository {
	dbHost := os.Getenv("DB_HOST")

	if dbHost == "" {
		dbHost = "localhost"
	}
	dbinfo := fmt.Sprintf("host=%s user=db_master password=ohoch3 dbname=home_erp sslmode=disable", dbHost)
	db, err := sql.Open("postgres", dbinfo)
	assert.Nil(t, err)
	repo := NewPostgresAccountRepository(db)

	privKey, err := rsa.GenerateKey(rand.Reader, 4096)

	if err != nil {
		t.Fatal(err)
	}

	pubAsn1, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)

	if err != nil {
		t.Fatal(err)
	}

	pubKeyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubAsn1,
	})

	account := DatabaseAccount{
		SchemaName:   "foo",
		PublicKeyPEM: string(pubKeyPem),
	}
	repo.SaveAccount(&account,"ohoch3")
}
