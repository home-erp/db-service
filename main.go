package main

import (
	"database/sql"
	"flag"
	"fmt"
	"log"
	"net/http"

	"time"

	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
	uuid "github.com/satori/go.uuid"
)

func main() {

	r := mux.NewRouter()

	defaultToken := uuid.NewV4().String()

	var port = flag.Int("port", 8080, "the port of the application")
	var dbHost = flag.String("db-host", "postgres", "the host of the database")
	var dbUser = flag.String("db-user", "db_master", "the user of the database")
	var dbPwd = flag.String("db-pwd", "ohoch3", "the password of the database")
	var dbName = flag.String("db-name", "home_erp", "the name of the database")
	var dbPort = flag.Int("db-port", 5432, "the port of the database")
	var token = flag.String("token", defaultToken, "the token that authorizes clients.")
	flag.Parse()

	fmt.Println(*token)
	fmt.Println(*port)

	if *token == defaultToken {
		fmt.Printf("No token provided. Generated the following token: %s", defaultToken)
	}

	dbinfo := fmt.Sprintf("port=%d host=%s user=%s password=%s dbname=%s sslmode=disable", *dbPort, *dbHost, *dbUser, *dbPwd, *dbName)

	PingDatabase(dbinfo, 200)

	db, err := sql.Open("postgres", dbinfo)

	if err != nil {
		log.Fatal(err)
	}

	repo := NewPostgresAccountRepository(db)

	createAccountsHandler := BuildAuthorizationMiddleware(BuildCreateSchemaHandler(repo, UUIDPasswordGenerator), *token)
	getAccountsHandler := BuildAuthorizationMiddleware(BuildGetSchemaHandler(repo), *token)

	r.HandleFunc("/database-accounts", createAccountsHandler).Methods("POST")
	r.HandleFunc("/database-accounts/{accountName}", getAccountsHandler).Methods("GET")
	r.Handle("/health", BuildHealthHandler(db)).Methods("GET")

	portString := fmt.Sprintf(":%d", *port)
	log.Printf("listening on %s", portString)
	log.Fatal(http.ListenAndServe(portString, r))
}

func PingDatabase(dbInfo string, maxRetries int) error {

	for i := 0; i < maxRetries; i++ {
		db, err := sql.Open("postgres", dbInfo)
		if err != nil {
			fmt.Println("Cannot connect to database yet.")
			time.Sleep(3 * time.Second)
			continue
		}
		defer db.Close()

		err = db.Ping()

		if err != nil {
			fmt.Println("Cannot connect to database yet.")
			fmt.Println(err)
			time.Sleep(3 * time.Second)
			continue
		}
		return nil
	}
	return fmt.Errorf("Database not reachable. Max retries exceeded.")
}
