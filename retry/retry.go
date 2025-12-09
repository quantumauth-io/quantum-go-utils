package retry

import (
	"context"
	"fmt"
	"time"

	"github.com/pkg/errors"
	"github.com/quantumauth-io/quantum-go-utils/log"
)

func SleepWithContext(ctx context.Context, duration time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(duration):
	}
}

func Min[V int | int64](a V, b V) V {
	if a <= b {
		return a
	}
	return b
}

type Config struct {
	MaxNumRetries                int32
	InitialDelayBeforeRetrying   time.Duration
	MaxDelayBeforeRetrying       time.Duration
	ShouldLogFirstFailure        bool
	LogEveryNthFailure           int32
	LogLevelWhenFailure          log.Level
	ShouldLogNumRetriesOnSuccess bool
	LogLevelWhenSuccess          log.Level
}

const (
	/* (S)tructured (L)ogging */
	SLnumRetries    = "numRetries"
	InfiniteRetries = -1
)

func DefaultConfig() *Config {
	return &Config{
		MaxNumRetries:                InfiniteRetries,
		InitialDelayBeforeRetrying:   time.Duration(100) * time.Millisecond,
		MaxDelayBeforeRetrying:       time.Duration(10) * time.Second,
		ShouldLogFirstFailure:        true,
		LogEveryNthFailure:           10,
		LogLevelWhenFailure:          log.WarnLevel,
		ShouldLogNumRetriesOnSuccess: false,
		LogLevelWhenSuccess:          log.DebugLevel,
	}
}

/*
Pass nil for shouldRetryFn in order to always retry.
*/
func Retry(ctx context.Context, cfg *Config, retryableOperationFn func(ctx context.Context) ([]interface{}, error),
	shouldRetryFn func(error) bool, descriptionOfOperation string) ([]interface{}, error) {
	delayBeforeRetryMS := cfg.InitialDelayBeforeRetrying.Milliseconds()
	var numRetries int32
performOperation:
	result, err := retryableOperationFn(ctx)
	if err != nil {
		if cfg.MaxNumRetries != InfiniteRetries && numRetries == cfg.MaxNumRetries {
			return nil, errors.Wrapf(err, "Failed after max %d retries: %s", numRetries, descriptionOfOperation)
		}

		if shouldRetryFn != nil && !shouldRetryFn(err) {
			return nil, errors.Wrapf(err, "Failed, unretryable, after %d retries: %s", numRetries,
				descriptionOfOperation)
		}

		numRetries++

		if numRetries > 1 {
			delayBeforeRetryMS = Min(delayBeforeRetryMS*2, cfg.MaxDelayBeforeRetrying.Milliseconds())
		}

		if (cfg.ShouldLogFirstFailure && numRetries == 1) ||
			(cfg.LogEveryNthFailure > 0 && ((numRetries % cfg.LogEveryNthFailure) == 0)) {
			log.Info(string(cfg.LogLevelWhenFailure), fmt.Sprintf("Retrying failure: %s", descriptionOfOperation),
				err, SLnumRetries, numRetries,
				"delayBeforeRetry", time.Duration(delayBeforeRetryMS)*time.Millisecond)
		}

		SleepWithContext(ctx, time.Duration(delayBeforeRetryMS)*time.Millisecond)
		if err2 := ctx.Err(); err2 != nil {
			return nil, errors.Wrapf(err, "Experienced context error during retry: %s - %s", descriptionOfOperation,
				err2.Error())
		}
		goto performOperation
	}

	if numRetries > 0 && cfg.ShouldLogNumRetriesOnSuccess {
		log.Info(string(cfg.LogLevelWhenSuccess), fmt.Sprintf("Ultimately succeeded: %s", descriptionOfOperation),
			SLnumRetries, numRetries)
	}

	return result, nil
}
