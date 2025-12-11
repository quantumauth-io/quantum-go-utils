package database

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/source"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/lib/pq"
	"github.com/pkg/errors"
	"github.com/quantumauth-io/quantum-go-utils/constants"
	"github.com/quantumauth-io/quantum-go-utils/retry"
)

const (
	// Default values for DB
	databaseDriverType           = "postgresql"
	defaultMaxRetry              = 10
	defaultMinDBPoolSize         = 5
	defaultMaxDBPoolSize         = 10
	defaultConnectionMaxLifetime = time.Duration(2) * time.Minute
	defaultConnectionMaxIdleTime = defaultConnectionMaxLifetime
	defaultDBPoolSize            = 5
	defaultIdlePoolSize          = defaultDBPoolSize
)

type DatabaseSettings struct {
	Host                  string
	Port                  string
	User                  string
	Password              string
	Database              string
	SSLModeDisable        bool
	CertPath              string
	ConnectionMaxLifetime time.Duration
	ConnectionMaxIdleTime time.Duration
	MaxIdleConnections    uint
	MaxPoolSize           uint //pgx
	MinPoolSize           uint //pgx
	PoolSize              uint //sql
}

func migrateWithIOFS(ctx context.Context, source source.Driver, cfg DatabaseSettings) error {
	retryCfg := retry.DefaultConfig()
	retryCfg.MaxDelayBeforeRetrying = 1 * time.Second
	retryCfg.MaxNumRetries = defaultMaxRetry

	connectionString, err := getConnectionString(cfg)
	if err != nil {
		return errors.Wrap(err, "Failed to create connection string")
	}

	_, err = retry.Retry(ctx, retryCfg,
		func(context.Context) ([]interface{}, error) {
			m, err2 := migrate.NewWithSourceInstance("iofs", source, "cockroachdb://"+connectionString)
			if err2 != nil {
				return nil, errors.Wrap(err2, "Failed to initialize migrations")
			}
			if err3 := m.Up(); err3 != nil && err3.Error() != "no change" {
				return nil, errors.Wrap(err3, "error migrating database schema")
			}
			return nil, nil
		},
		nil,
		"Database Migration",
	)

	return err
}

func getConnectionString(dbSettings DatabaseSettings) (string, error) {
	connString := fmt.Sprintf("%s:%s@%s:%s/%s", dbSettings.User, dbSettings.Password, dbSettings.Host, dbSettings.Port, dbSettings.Database)

	if dbSettings.SSLModeDisable {
		connString += "?sslmode=disable"
	} else {
		if dbSettings.CertPath == "" {
			return "", errors.New("ssl mode was enabled but cert path was empty")
		}

		if _, err := os.Stat(dbSettings.CertPath); errors.Is(err, os.ErrNotExist) {
			return "", errors.New("ssl mode was enabled but cert file not found")
		}

		connString += fmt.Sprintf("?sslmode=verify-ca&sslrootcert=%s", dbSettings.CertPath)

	}

	return connString, nil
}

func pingDB(ctx context.Context, pingFn func(ctx context.Context) error) error {
	deadline := time.Now().Add(60 * time.Second)
	err := errors.New("something went wrong")
	for time.Now().Before(deadline) {
		err = pingFn(ctx)
		if err == nil {
			return nil
		}
	}
	if err != nil {
		return errors.Wrap(err, "failed to ping database")
	}
	return nil
}

func setDBConfig(dbPoolI interface{}, dbSettings DatabaseSettings) interface{} {

	finalMinPoolSize := dbSettings.MinPoolSize
	if dbSettings.MinPoolSize == 0 {
		finalMinPoolSize = defaultMinDBPoolSize
	}
	finalMaxPoolSize := dbSettings.MaxPoolSize
	if dbSettings.MaxPoolSize == 0 {
		finalMaxPoolSize = defaultMaxDBPoolSize
	}
	finalMaxLifetime := dbSettings.ConnectionMaxLifetime
	if finalMaxLifetime.Milliseconds() == 0 {
		finalMaxLifetime = defaultConnectionMaxLifetime
	}
	finalMaxIdleTime := dbSettings.ConnectionMaxIdleTime
	if finalMaxIdleTime.Milliseconds() == 0 {
		finalMaxIdleTime = defaultConnectionMaxIdleTime
	}
	finalPoolSize := dbSettings.PoolSize
	if dbSettings.PoolSize == 0 {
		finalPoolSize = defaultDBPoolSize
	}
	finalMaxIdleConns := dbSettings.MaxIdleConnections
	if finalMaxIdleConns == 0 {
		finalMaxIdleConns = defaultIdlePoolSize
	}

	if dbPool, pgx := dbPoolI.(*pgxpool.Pool); pgx {
		dbPool.Config().MinConns = int32(finalMinPoolSize)
		dbPool.Config().MaxConns = int32(finalMaxPoolSize)
		dbPool.Config().MaxConnLifetime = finalMaxLifetime
		dbPool.Config().MaxConnIdleTime = finalMaxIdleTime

		return dbPool

	} else if db, sql := dbPoolI.(*sql.DB); sql {
		db.SetMaxOpenConns(int(finalPoolSize))
		db.SetMaxIdleConns(int(finalMaxIdleConns))
		db.SetConnMaxLifetime(finalMaxLifetime)
		db.SetConnMaxIdleTime(finalMaxIdleTime)

		return db
	}
	return nil
}

// used by both SQL + PGX drivers
func isRetryable(err error) bool {
	if err == nil {
		return false
	}

	// 1) never retry "no rows"
	if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, sql.ErrNoRows) {
		return false
	}

	// 2) never retry unique constraint violations
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		if pqErr.Code == constants.UniqueConstraintViolationCode {
			return false
		}
	}

	// 3) network-level errors (e.g. "use of closed network connection")
	var netErr *net.OpError
	if errors.As(err, &netErr) {
		// let the pool create a fresh connection and retry
		return true
	}

	// 4) default: optimistic for Cockroach / transient DB errors
	return true
}
