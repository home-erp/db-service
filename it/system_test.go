package it

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDatabaseService(t *testing.T) {

	containerName := "database-service-it_" + uuid.NewV4().String()

	databasePort := getPort()
	cmd := exec.Command("docker",
		"run",
		"-d",
		"-p",
		fmt.Sprintf("%d:5432", databasePort),
		"--name",
		containerName,
		"home-erp/database",
	)

	assert.Nil(t, cmd.Run())

	serverPort := getPort()

	serverCmd := exec.Command("../db-service",
		"-db-port",
		fmt.Sprintf("%d", databasePort),
		"-db-host",
		"localhost",
		"-port",
		fmt.Sprintf("%d", serverPort),
		"-token",
		"123",
	)
	serverCmd.Stdout = os.Stdout
	serverCmd.Stderr = os.Stderr

	err := serverCmd.Start()

	assert.Nil(t, err)

	defer serverCmd.Process.Kill()

	serviceUrl := fmt.Sprintf("http://localhost:%d", serverPort)

	err = waitForService(serviceUrl+"/health", 200)

	require.Nil(t, err)

	resp, err := sendRequest("GET", serviceUrl+"/database-accounts/foo", nil)

	require.Nil(t, err)

	defer resp.Body.Close()

	require.Equal(t, 403, resp.StatusCode)

	resp, err = sendRequest("GET", serviceUrl+"/database-accounts/foo", nil, "Authorization:123")

	require.Nil(t, err)

	defer resp.Body.Close()

	require.Equal(t, 404, resp.StatusCode)

	key, err := rsa.GenerateKey(rand.Reader, 2048)

	newAccount := databaseAccount{
		SchemaName:   "foo",
		PublicKeyPEM: getPublicKeyString(key),
	}

	resp, err = sendRequest("POST", serviceUrl+"/database-accounts", &newAccount)

	require.Nil(t, err)

	defer resp.Body.Close()

	require.Equal(t, 403, resp.StatusCode)

	resp, err = sendRequest("POST", serviceUrl+"/database-accounts", &newAccount, "Authorization:123")
	require.Nil(t, err)

	defer resp.Body.Close()
	require.Equal(t, 201, resp.StatusCode)

	decoder := json.NewDecoder(resp.Body)

	err = decoder.Decode(&newAccount)

	require.Nil(t, err)
	plaintext, err := newAccount.decryptPwd(key)

	require.Nil(t, err)

	log.Println("got password " + string(plaintext))

	resp, err = sendRequest("GET", serviceUrl+"/database-accounts/foo", nil, "Authorization:123")

	require.Nil(t, err)

	defer resp.Body.Close()

	require.Equal(t, 200, resp.StatusCode)

	decoder = json.NewDecoder(resp.Body)

	err = decoder.Decode(&newAccount)

	newPlaintext, err := newAccount.decryptPwd(key)

	assert.Nil(t, err)
	assert.Equal(t, string(newPlaintext), string(plaintext))

	dbinfo := fmt.Sprintf("port=%d host=localhost user=foo password=%s dbname=home_erp sslmode=disable", databasePort, string(plaintext))
	db, err := sql.Open("postgres", dbinfo)

	require.Nil(t, err)

	_, err = db.Exec("create table bla(id int)")
	require.Nil(t, err)

	_, err = db.Exec("insert into foo.bla(id) values(1)")
	require.Nil(t, err)

	out, err := exec.Command("docker", "rm", "-f", containerName).CombinedOutput()

	fmt.Println(string(out))

}

func (account *databaseAccount) decryptPwd(priv *rsa.PrivateKey) (string, error) {

	decoded, _ := base64.StdEncoding.DecodeString(account.EncryptedPwd)

	plaintext, err := rsa.DecryptOAEP(sha256.New(),
		rand.Reader,
		priv,
		decoded,
		[]byte("orders"),
	)

	if err != nil {
		return "", err
	}

	return string(plaintext), nil

}

func sendRequest(method, url string, entity interface{}, headers ...string) (*http.Response, error) {

	var body io.Reader
	if entity != nil {
		buffer := bytes.NewBuffer(make([]byte, 0))
		encoder := json.NewEncoder(buffer)
		_ = encoder.Encode(entity)
		body = buffer

	}

	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}

	for _, val := range headers {
		parts := strings.Split(val, ":")
		req.Header.Add(parts[0], parts[1])
	}

	return http.DefaultClient.Do(req)

}

// Ask the kernel for a free open port that is ready to use
func getPort() int {
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		panic(err)
	}

	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		panic(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func waitForService(url string, maxRetries int) error {
	for i := 0; i < maxRetries; i++ {
		response, err := http.Get(url)
		if err != nil || response.StatusCode != 200 {
			time.Sleep(3 * time.Second)
			continue
		}
		return nil
	}
	return fmt.Errorf("Service %s not reachable.", url)
}

type databaseAccount struct {
	SchemaName   string
	PublicKeyPEM string
	EncryptedPwd string
}

func getPublicKeyString(key *rsa.PrivateKey) string {

	pubAsn1, err := x509.MarshalPKIXPublicKey(&key.PublicKey)

	if err != nil {
		log.Fatal(err)
	}

	pubKeyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubAsn1,
	})
	return string(pubKeyPem)
}
