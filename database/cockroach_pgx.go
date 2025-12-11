package database

import (
	"context"
	"time"

	"github.com/cockroachdb/cockroach-go/v2/crdb"
	"github.com/golang-migrate/migrate/v4/source"
	"github.com/jackc/pgconn"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/pkg/errors"
	"github.com/quantumauth-io/quantum-go-utils/retry"
	"go.elastic.co/apm/module/apmpgx/v2"
)

type CockroachPGXDatabase struct {
	dbPool   *pgxpool.Pool
	settings DatabaseSettings
}

func (db *CockroachPGXDatabase) MigrateWithIOFS(ctx context.Context, source source.Driver) error {
	return migrateWithIOFS(ctx, source, db.settings)
}

func (db *CockroachPGXDatabase) GetSettings() DatabaseSettings {
	return db.settings
}

type pgxTransaction struct {
	tx pgx.Tx
}

type pgxDatabaseExecResult struct {
	cmdTag pgconn.CommandTag
}

type pgxDatabaseRows struct {
	rows pgx.Rows
}

// Fargate-friendly PGX pool
func NewCockroachPGXDatabase(ctx context.Context, dbSettings DatabaseSettings) (QuantumAuthDatabase, error) {
	connStr, err := getConnectionString(dbSettings)
	if err != nil {
		return nil, err
	}

	retryCfg := retry.DefaultConfig()
	retryCfg.MaxDelayBeforeRetrying = 1 * time.Second
	retryCfg.MaxNumRetries = defaultMaxRetry

	result, err := retry.Retry(ctx, retryCfg,
		func(context.Context) ([]interface{}, error) {
			cfg, err := pgxpool.ParseConfig(databaseDriverType + "://" + connStr)
			if err != nil {
				return nil, errors.Wrap(err, "error parsing pgx config")
			}

			// pool sizing based on your settings/defaults
			finalMinPoolSize := dbSettings.MinPoolSize
			if finalMinPoolSize == 0 {
				finalMinPoolSize = defaultMinDBPoolSize
			}
			finalMaxPoolSize := dbSettings.MaxPoolSize
			if finalMaxPoolSize == 0 {
				finalMaxPoolSize = defaultMaxDBPoolSize
			}

			cfg.MinConns = int32(finalMinPoolSize)
			cfg.MaxConns = int32(finalMaxPoolSize)

			// Fargate/NAT-friendly lifetimes
			cfg.MaxConnLifetime = 60 * time.Second
			cfg.MaxConnIdleTime = 30 * time.Second
			cfg.HealthCheckPeriod = 15 * time.Second

			dbPool, err2 := pgxpool.ConnectConfig(ctx, cfg)
			if err2 != nil {
				return nil, errors.Wrap(err2, "error opening the database")
			}

			// ping to verify connectivity
			pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			if err := dbPool.Ping(pingCtx); err != nil {
				dbPool.Close()
				return nil, errors.Wrap(err, "failed to ping database")
			}

			return []interface{}{&CockroachPGXDatabase{
				dbPool:   dbPool,
				settings: dbSettings,
			}}, nil
		},
		nil,
		"Database Connection",
	)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to instantiate db after retries")
	}
	return result[0].(*CockroachPGXDatabase), nil
}

func (db *CockroachPGXDatabase) GetTransaction(ctx context.Context) (QuantumAuthDatabaseTransaction, error) {
	opts := pgx.TxOptions{
		IsoLevel:       pgx.Serializable,
		AccessMode:     pgx.ReadWrite,
		DeferrableMode: pgx.Deferrable,
	}

	retryCfg := retry.DefaultConfig()
	retryCfg.MaxDelayBeforeRetrying = 1 * time.Second
	retryCfg.MaxNumRetries = defaultMaxRetry

	result, err := retry.Retry(ctx, retryCfg,
		func(context.Context) ([]interface{}, error) {
			txn, err2 := db.dbPool.BeginTx(ctx, opts)
			if err2 != nil {
				return nil, errors.Wrap(err2, "Failed to begin db transaction")
			}
			apmpgx.Instrument(txn.Conn().Config())

			return []interface{}{&pgxTransaction{txn}}, nil
		},
		isRetryable, // <- use retryable logic here too
		"Get DB Transaction",
	)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to begin transaction after retries")
	}
	return result[0].(*pgxTransaction), nil
}

func (db *CockroachPGXDatabase) Exec(ctx context.Context, sql string, arguments ...interface{}) (QuantumAuthDatabaseExecResult, error) {
	retryCfg := retry.DefaultConfig()
	retryCfg.MaxDelayBeforeRetrying = 1 * time.Second
	retryCfg.MaxNumRetries = defaultMaxRetry

	result, err := retry.Retry(ctx, retryCfg,
		func(context.Context) ([]interface{}, error) {
			conn, err := db.dbPool.Acquire(ctx)
			if err != nil {
				return nil, err
			}
			defer conn.Release()
			apmpgx.Instrument(conn.Conn().Config())

			var cmd pgconn.CommandTag
			err = crdb.Execute(func() error {
				cmd, err = conn.Exec(ctx, sql, arguments...)
				if err != nil {
					return err
				}
				return nil
			})
			if err != nil {
				return nil, err
			}
			return []interface{}{&pgxDatabaseExecResult{cmdTag: cmd}}, nil
		},
		isRetryable, // <- was nil
		"Database Exec",
	)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to execute %s after retries", sql)
	}

	return result[0].(*pgxDatabaseExecResult), nil
}

func (db *CockroachPGXDatabase) QueryRow(ctx context.Context, sql string, arguments ...interface{}) (QuantumAuthDatabaseRow, error) {
	retryCfg := retry.DefaultConfig()
	retryCfg.MaxDelayBeforeRetrying = 1 * time.Second
	retryCfg.MaxNumRetries = defaultMaxRetry

	result, err := retry.Retry(ctx, retryCfg,
		func(context.Context) ([]interface{}, error) {
			conn, err := db.dbPool.Acquire(ctx)
			if err != nil {
				return nil, err
			}
			defer conn.Release()
			apmpgx.Instrument(conn.Conn().Config())

			var row QuantumAuthDatabaseRow
			err = crdb.Execute(func() error {
				row = conn.QueryRow(ctx, sql, arguments...)
				return nil
			})
			if err != nil {
				return nil, err
			}

			return []interface{}{row}, nil
		},
		isRetryable,
		"Database QueryRow",
	)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to QueryRow %s", sql)
	}

	return result[0].(QuantumAuthDatabaseRow), nil
}

func (db *CockroachPGXDatabase) Query(ctx context.Context, sql string, arguments ...interface{}) (QuantumAuthDatabaseRows, error) {
	retryCfg := retry.DefaultConfig()
	retryCfg.MaxDelayBeforeRetrying = 1 * time.Second
	retryCfg.MaxNumRetries = defaultMaxRetry

	result, err := retry.Retry(ctx, retryCfg,
		func(context.Context) ([]interface{}, error) {
			conn, err := db.dbPool.Acquire(ctx)
			if err != nil {
				return nil, err
			}
			defer conn.Release()
			apmpgx.Instrument(conn.Conn().Config())

			var rows pgx.Rows
			err = crdb.Execute(func() error {
				rows, err = conn.Query(ctx, sql, arguments...)
				if err != nil {
					return err
				}
				return nil
			})
			if err != nil {
				return nil, errors.Wrapf(err, "Failed to Execute Query %s", sql)
			}

			return []interface{}{&pgxDatabaseRows{rows: rows}}, nil
		},
		isRetryable,
		"Database Query",
	)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to queryRows %s after retries", sql)
	}

	return result[0].(*pgxDatabaseRows), nil
}

func (pgxRows *pgxDatabaseRows) Close() error {
	pgxRows.rows.Close()
	return nil
}
func (pgxRows *pgxDatabaseRows) Err() error {
	return pgxRows.rows.Err()
}
func (pgxRows *pgxDatabaseRows) Next() bool {
	return pgxRows.rows.Next()
}
func (pgxRows *pgxDatabaseRows) Scan(dest ...interface{}) error {
	return pgxRows.rows.Scan(dest...)
}

func (pgxResult *pgxDatabaseExecResult) RowsAffected() (int64, error) {
	return pgxResult.cmdTag.RowsAffected(), nil
}

func (pgxTransaction *pgxTransaction) Exec(ctx context.Context, sql string, arguments ...interface{}) (QuantumAuthDatabaseExecResult, error) {
	var dbResult pgconn.CommandTag
	var err error

	retryCfg := retry.DefaultConfig()
	retryCfg.MaxDelayBeforeRetrying = 1 * time.Second
	retryCfg.MaxNumRetries = defaultMaxRetry

	result, err := retry.Retry(ctx, retryCfg,
		func(context.Context) ([]interface{}, error) {
			err = crdb.Execute(func() error {
				dbResult, err = pgxTransaction.tx.Exec(ctx, sql, arguments...)
				if err != nil {
					return err
				}
				return nil
			})
			if err != nil {
				return nil, err
			}
			return []interface{}{&pgxDatabaseExecResult{cmdTag: dbResult}}, nil
		},
		isRetryable, // <- was nil
		"Database Execute Transaction",
	)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to execute db transaction %s after retries", sql)
	}

	return result[0].(*pgxDatabaseExecResult), nil
}

func (pgxTransaction *pgxTransaction) Commit(ctx context.Context) error {
	retryCfg := retry.DefaultConfig()
	retryCfg.MaxDelayBeforeRetrying = 1 * time.Second
	retryCfg.MaxNumRetries = defaultMaxRetry

	_, err := retry.Retry(ctx, retryCfg,
		func(context.Context) ([]interface{}, error) {
			if err := pgxTransaction.tx.Commit(ctx); err != nil {
				return nil, err
			}
			return nil, nil
		},
		isRetryable,
		"Database Commit Transaction",
	)
	if err != nil {
		return errors.Wrapf(err, "Failed to commit db transaction after retries")
	}
	return nil
}

func (pgxTransaction *pgxTransaction) Rollback(ctx context.Context) error {
	retryCfg := retry.DefaultConfig()
	retryCfg.MaxDelayBeforeRetrying = 1 * time.Second
	retryCfg.MaxNumRetries = defaultMaxRetry

	_, err := retry.Retry(ctx, retryCfg,
		func(context.Context) ([]interface{}, error) {
			if err := pgxTransaction.tx.Rollback(ctx); err != nil {
				return nil, err
			}
			return nil, nil
		},
		isRetryable,
		"Database Rollback Transaction",
	)
	if err != nil {
		return errors.Wrapf(err, "Failed to rollback db transaction after retries")
	}
	return nil
}

func (pgxTransaction *pgxTransaction) SendBatch(ctx context.Context, b *pgx.Batch) pgx.BatchResults {
	return pgxTransaction.tx.SendBatch(ctx, b)
}

func (db *CockroachPGXDatabase) Close() error {
	db.dbPool.Close()
	return nil
}
func (db *CockroachPGXDatabase) Ping(ctx context.Context) error {
	return pingDB(ctx, db.dbPool.Ping)
}
