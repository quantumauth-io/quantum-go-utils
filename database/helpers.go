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
	databaseDriverType = "postgresql"

	defaultMaxRetry = 6

	// Pool sizing per task (good starting point for Fargate)
	defaultMinDBPoolSize = 1
	defaultMaxDBPoolSize = 8

	// Keep connections relatively short-lived / not too idle
	defaultConnectionMaxLifetime = 2 * time.Minute
	defaultConnectionMaxIdleTime = 30 * time.Second

	defaultDBPoolSize   = 5
	defaultIdlePoolSize = defaultDBPoolSize
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
	MaxPoolSize           uint // pgx
	MinPoolSize           uint // pgx
	PoolSize              uint // sql
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
			m, err2 := migrate.NewWithSourceInstance("iofs", source, "postgres://"+connectionString)
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
	connString := fmt.Sprintf("%s:%s@%s:%s/%s",
		dbSettings.User,
		dbSettings.Password,
		dbSettings.Host,
		dbSettings.Port,
		dbSettings.Database,
	)

	// Local/dev docker etc.
	if dbSettings.SSLModeDisable {
		return connString + "?sslmode=disable", nil
	}

	// Aurora / RDS: encryption required.
	// Default to "require" so we don't need a CA bundle inside the container.
	// Only use verify-ca when a cert path is provided.
	if dbSettings.CertPath == "" {
		return connString + "?sslmode=require", nil
	}

	// If cert path is provided, enforce it exists and do verify-ca
	if _, err := os.Stat(dbSettings.CertPath); errors.Is(err, os.ErrNotExist) {
		return "", errors.New("ssl mode was enabled but cert file not found")
	} else if err != nil {
		return "", err
	}

	return connString + fmt.Sprintf("?sslmode=verify-ca&sslrootcert=%s", dbSettings.CertPath), nil
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
	if finalMinPoolSize == 0 {
		finalMinPoolSize = defaultMinDBPoolSize
	}
	finalMaxPoolSize := dbSettings.MaxPoolSize
	if finalMaxPoolSize == 0 {
		finalMaxPoolSize = defaultMaxDBPoolSize
	}
	finalMaxLifetime := dbSettings.ConnectionMaxLifetime
	if finalMaxLifetime == 0 {
		finalMaxLifetime = defaultConnectionMaxLifetime
	}
	finalMaxIdleTime := dbSettings.ConnectionMaxIdleTime
	if finalMaxIdleTime == 0 {
		finalMaxIdleTime = defaultConnectionMaxIdleTime
	}
	finalPoolSize := dbSettings.PoolSize
	if finalPoolSize == 0 {
		finalPoolSize = defaultDBPoolSize
	}
	finalMaxIdleConns := dbSettings.MaxIdleConnections
	if finalMaxIdleConns == 0 {
		finalMaxIdleConns = defaultIdlePoolSize
	}

	if dbPool, ok := dbPoolI.(*pgxpool.Pool); ok {
		cfg := dbPool.Config()
		cfg.MinConns = int32(finalMinPoolSize)
		cfg.MaxConns = int32(finalMaxPoolSize)
		cfg.MaxConnLifetime = finalMaxLifetime
		cfg.MaxConnIdleTime = finalMaxIdleTime

		// extra: proactively check connections so dead ones don’t linger
		cfg.HealthCheckPeriod = 15 * time.Second

		return dbPool
	}

	if db, ok := dbPoolI.(*sql.DB); ok {
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
