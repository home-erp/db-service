package main

import (
	"database/sql"
	"log"
)

type DatabaseAccount struct {
	SchemaName   string
	PublicKeyPEM string
	EncryptedPwd string
}

type AccountRepository interface {
	GetAccount(accountName string) (*DatabaseAccount, error)
	SaveAccount(account *DatabaseAccount, cleartextPassword string) error
}

type PostgresAccountRespository struct {
	con *sql.DB
}

func (r *PostgresAccountRespository) GetAccount(accountName string) (*DatabaseAccount, error) {
	log.Println(accountName)
	stmt, err := r.con.Prepare("SELECT schema_name, encrypted_pwd FROM database_accounts where schema_name = $1")
	if err != nil {
		return nil, err
	}
	row := stmt.QueryRow(accountName)
	account := DatabaseAccount{}
	err = row.Scan(&account.SchemaName, &account.EncryptedPwd)
	if err != nil {
		return nil, err
	}
	return &account, nil
}

func (r *PostgresAccountRespository) SaveAccount(account *DatabaseAccount, cleartextPassword string) error {

	_, err := r.con.Exec("select create_database_account($1,$2,$3,$4)",
		account.SchemaName,
		cleartextPassword,
		account.EncryptedPwd,
		account.PublicKeyPEM,
	)
	return err
}

func NewPostgresAccountRepository(db *sql.DB) *PostgresAccountRespository {
	return &PostgresAccountRespository{
		con: db,
	}
}
