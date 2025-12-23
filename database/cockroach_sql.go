package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/golang-migrate/migrate/v4/database/cockroachdb"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/pkg/errors"
	"github.com/quantumauth-io/quantum-go-utils/retry"
	"go.elastic.co/apm/module/apmsql/v2"
	_ "go.elastic.co/apm/module/apmsql/v2/pq"
)

type CockroachSQLDatabase struct {
	dbPool   *sql.DB
	settings DatabaseSettings
}

func (db *CockroachSQLDatabase) MigrateWithIOFS(ctx context.Context, source source.Driver) error {
	return migrateWithIOFS(ctx, source, db.settings)
}

type sqlDatabaseRows struct {
	rows *sql.Rows
}

type sqlTransaction struct {
	tx *sql.Tx
}

type sqlDatabaseExecResult struct {
	result sql.Result
}

func NewCockroachSQLDatabase(ctx context.Context, dbSettings DatabaseSettings) (QuantumAuthDatabase, error) {

	retryCfg := retry.DefaultConfig()
	retryCfg.MaxDelayBeforeRetrying = 1 * time.Second
	retryCfg.MaxNumRetries = defaultMaxRetry

	connStr, err := getConnectionString(dbSettings)
	if err != nil {
		return nil, err
	}
	result, err := retry.Retry(ctx, retryCfg,
		func(context.Context) ([]interface{}, error) {
			db, err3 := apmsql.Open("postgres", fmt.Sprintf(connStr))
			if err3 != nil {
				return nil, errors.Wrap(err3, "error opening the database")
			}

			dbPoolWithConfig := setDBConfig(db, dbSettings)
			return []interface{}{&CockroachSQLDatabase{dbPool: dbPoolWithConfig.(*sql.DB), settings: dbSettings}}, nil

		},
		nil,
		"Database Connection",
	)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to instanciate db after retries")
	}
	return result[0].(*CockroachSQLDatabase), nil

}

func (db *CockroachSQLDatabase) QueryRow(ctx context.Context, sql string, arguments ...interface{}) (QuantumAuthDatabaseRow, error) {
	return db.dbPool.QueryRowContext(ctx, sql, arguments...), nil
}

func (db *CockroachSQLDatabase) Query(ctx context.Context, sql string, arguments ...interface{}) (QuantumAuthDatabaseRows, error) {
	result, err := db.dbPool.QueryContext(ctx, sql, arguments...)
	if err != nil {
		return nil, err
	}
	return &sqlDatabaseRows{result}, nil
}
func (db *CockroachSQLDatabase) Close() error {
	return db.dbPool.Close()
}

func (db *CockroachSQLDatabase) Ping(ctx context.Context) error {
	return pingDB(ctx, db.dbPool.PingContext)
}

func (dbRows *sqlDatabaseRows) Close() error {
	return dbRows.rows.Close()
}

func (dbRows *sqlDatabaseRows) Err() error {
	return dbRows.rows.Err()
}

func (dbRows *sqlDatabaseRows) Next() bool {
	return dbRows.rows.Next()
}

func (db *CockroachSQLDatabase) Exec(ctx context.Context, sql string, arguments ...interface{}) (QuantumAuthDatabaseExecResult, error) {
	return db.dbPool.ExecContext(ctx, sql, arguments...)
}

func (db *CockroachSQLDatabase) GetTransaction(ctx context.Context) (QuantumAuthDatabaseTransaction, error) {
	opts := &sql.TxOptions{
		ReadOnly:  false,
		Isolation: sql.LevelDefault,
	}

	txResult, err := db.dbPool.BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	return &sqlTransaction{txResult}, nil
}

func (dbRows *sqlDatabaseRows) Scan(dest ...interface{}) error {
	return dbRows.rows.Scan(dest...)
}

func (sqlResult sqlDatabaseExecResult) RowsAffected() (int64, error) {
	return sqlResult.result.RowsAffected()
}

func (sqlTx *sqlTransaction) Exec(ctx context.Context, sql string, arguments ...interface{}) (QuantumAuthDatabaseExecResult, error) {
	return sqlTx.tx.ExecContext(ctx, sql, arguments...)
}
func (sqlTx *sqlTransaction) Commit(ctx context.Context) error {
	return sqlTx.tx.Commit()
}
func (sqlTx *sqlTransaction) Rollback(ctx context.Context) error {
	return sqlTx.tx.Rollback()
}
