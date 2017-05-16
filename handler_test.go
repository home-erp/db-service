package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"crypto/rsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"os"
	"fmt"
	"database/sql"
	_ "github.com/lib/pq"
)

func TestGetAccount(t *testing.T) {
	req, err := http.NewRequest("GET", "/database-accounts/foo", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()

	repo := testRepo{t}

	handler := VarsHandler(BuildGetSchemaHandler(&repo))

	vars := make(map[string]string)
	vars["accountName"] = "foo"
	code := handler(rr, req, vars)

	assert.Equal(t, 200, code)

	decoder := json.NewDecoder(rr.Body)

	var account DatabaseAccount
	err = decoder.Decode(&account)

	assert.Equal(t, "foo", account.SchemaName)
}

func TestSaveAccount(t *testing.T) {
	repo := testRepo{t}
	testSave(t,repo)
}

func testSave(t *testing.T, repo AccountRepository) {

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

	buffer := bytes.NewBuffer(make([]byte, 0))
	encoder := json.NewEncoder(buffer)
	err = encoder.Encode(&account)
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest("POST", "/database-accounts", buffer)
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	handler := VarsHandler(BuildCreateSchemaHandler(repo, fakePwdGenerator))

	code := handler(rr, req, nil)

	assert.Equal(t, 201, code)

	decoder := json.NewDecoder(rr.Body)
	var newAccount DatabaseAccount
	err = decoder.Decode(&newAccount)

	assert.Equal(t, "bar", newAccount.SchemaName)

	label := []byte("orders")
	decoded, err := base64.StdEncoding.DecodeString(newAccount.EncryptedPwd)
	assert.Nil(t, err)

	plaintext, err := rsa.DecryptOAEP(sha256.New(),
		rand.Reader,
		privKey,
		decoded,
		label,
	)
	assert.Nil(t, err)

	assert.Equal(t, "ohoch3", string(plaintext))

}

func TestIntegrationAccount(t *testing.T) {

	dbHost := os.Getenv("DB_HOST")

	if dbHost == "" {
		dbHost = "localhost"
	}
	dbinfo := fmt.Sprintf("host=%s user=db_master password=ohoch3 dbname=home_erp sslmode=disable", dbHost)
	db, err := sql.Open("postgres", dbinfo)
	assert.Nil(t, err)
	repo := NewPostgresAccountRepository(db)
	testSave(t,repo)
}

type testRepo struct {
	t *testing.T
}

func (r *testRepo) SaveAccount(account *DatabaseAccount, pwd string) error {
	return nil
}

func (r *testRepo) GetAccount(accountName string) (*DatabaseAccount, error) {
	assert.NotEmpty(r.t, accountName)
	result := DatabaseAccount{
		SchemaName: accountName,
	}

	return &result, nil
}

func fakePwdGenerator() string {
	return "ohoch3"
}
