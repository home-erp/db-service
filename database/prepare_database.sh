#!/bin/sh

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" <<-EOSQL
  CREATE ROLE db_master login password 'ohoch3' createrole;
  CREATE DATABASE home_erp;
  GRANT ALL PRIVILEGES ON database home_erp to db_master;
EOSQL
export PGPASSWORD="ohoch3"
psql -v ON_ERROR_STOP=1 --username db_master -d home_erp <<-EOSQL
  CREATE TABLE database_accounts(schema_name varchar PRIMARY KEY, encrypted_pwd text, public_key text);
  CREATE or replace FUNCTION create_database_account(in_account_name varchar, in_pwd varchar, in_encrypted_pwd text, in_public_key text) RETURNS VOID AS \$\$
  BEGIN
    IF EXISTS (
        SELECT schema_name
        FROM   database_accounts
        WHERE  schema_name = in_account_name) THEN
          RAISE EXCEPTION 'user account already exists.' USING ERRCODE = '1';
    END IF;

    execute 'CREATE ROLE ' || in_account_name || ' login password '''||in_pwd||'''';
    execute 'GRANT connect on database home_erp to ' || in_account_name;
    execute 'GRANT ' || in_account_name || ' to db_master';
    execute 'CREATE SCHEMA authorization ' || in_account_name;
    execute 'ALTER ROLE ' || in_account_name || ' SET search_path TO ' || in_account_name;
    insert into database_accounts(schema_name,encrypted_pwd,public_key) values(in_account_name,in_encrypted_pwd,in_public_key);
  END
  \$\$ LANGUAGE plpgsql;
EOSQL
