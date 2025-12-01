package redis

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	"github.com/redis/go-redis/v9"
)

type Config struct {
	Host         string        // "localhost:6379"
	Port         string        // "6379"
	Username     string        // optional
	Password     string        // optional
	DB           int           // default 0
	TLS          bool          // enable TLS
	DialTimeout  time.Duration // default 5s
	ReadTimeout  time.Duration // default 3s
	WriteTimeout time.Duration // default 3s
}

// NewClient creates and pings a Redis client.
func NewClient(ctx context.Context, cfg Config) (*redis.Client, error) {
	if cfg.Host == "" {
		cfg.Host = "localhost"
		cfg.Port = "6379"
	}
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = 5 * time.Second
	}
	if cfg.ReadTimeout == 0 {
		cfg.ReadTimeout = 3 * time.Second
	}
	if cfg.WriteTimeout == 0 {
		cfg.WriteTimeout = 3 * time.Second
	}

	opts := &redis.Options{
		Addr:         net.JoinHostPort(cfg.Host, cfg.Port),
		Username:     cfg.Username,
		Password:     cfg.Password,
		DB:           cfg.DB,
		DialTimeout:  cfg.DialTimeout,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
	}
	if cfg.TLS {
		opts.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
	}

	rdb := redis.NewClient(opts)

	if err := rdb.Ping(ctx).Err(); err != nil {
		_ = rdb.Close()
		return nil, err
	}

	return rdb, nil
}
