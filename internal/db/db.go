package db

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func Open(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	cfg.MaxConns = 20
	cfg.MinConns = 2
	cfg.MaxConnLifetime = time.Hour
	var pool *pgxpool.Pool
	for i := 0; i < 30; i++ {
		pool, err = pgxpool.NewWithConfig(ctx, cfg)
		if err == nil {
			err = pool.Ping(ctx)
		}
		if err == nil {
			return pool, nil
		}
		if pool != nil {
			pool.Close()
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return nil, fmt.Errorf("database unavailable: %w", err)
}

func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	if len(migrations) == 0 {
		return nil
	}
	if _, err := pool.Exec(ctx, migrations[0]); err != nil {
		return fmt.Errorf("migration bootstrap: %w", err)
	}
	for i := 1; i < len(migrations); i++ {
		version := i
		tx, err := pool.Begin(ctx)
		if err != nil {
			return err
		}
		ok := false
		func() {
			defer func() {
				if !ok {
					_ = tx.Rollback(ctx)
				}
			}()
			// Serialize migrations across multiple ZentCal instances. The lock is scoped
			// to this transaction and is automatically released on commit/rollback.
			if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(99270122)`); err != nil {
				return
			}
			var applied bool
			if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=$1)`, version).Scan(&applied); err != nil {
				return
			}
			if applied {
				if err = tx.Commit(ctx); err == nil {
					ok = true
				}
				return
			}
			// Each migration is authored as a complete SQL script. Executing the script
			// as-is avoids corrupting PostgreSQL functions or quoted strings that contain
			// semicolons.
			if _, err = tx.Exec(ctx, migrations[i]); err != nil {
				return
			}
			if _, err = tx.Exec(ctx, `INSERT INTO schema_migrations(version) VALUES($1)`, version); err != nil {
				return
			}
			if err = tx.Commit(ctx); err != nil {
				return
			}
			ok = true
		}()
		if err != nil {
			return fmt.Errorf("migration %d: %w", version, err)
		}
	}
	return nil
}
