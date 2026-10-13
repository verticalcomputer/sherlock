package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
)

func main() {
	directory := flag.String("dir", "migrations", "migration directory")
	flag.Parse()
	databaseURL := os.Getenv("SHERLOCK_DATABASE_URL")
	if databaseURL == "" {
		log.Fatal("SHERLOCK_DATABASE_URL is required")
	}
	ctx := context.Background()
	connection, err := pgx.Connect(ctx, databaseURL)
	if err != nil {
		log.Fatal("connect to PostgreSQL: ", err)
	}
	defer func() { _ = connection.Close(ctx) }()
	files, err := filepath.Glob(filepath.Join(*directory, "*.up.sql"))
	if err != nil {
		log.Fatal(err)
	}
	sort.Strings(files)
	for _, file := range files {
		name := filepath.Base(file)
		version := strings.SplitN(name, "_", 2)[0]
		var exists bool
		err := connection.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='schema_migrations')`).Scan(&exists)
		if err != nil {
			log.Fatal(err)
		}
		if exists {
			var applied bool
			if err := connection.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version=$1)`, version).Scan(&applied); err != nil {
				log.Fatal(err)
			}
			if applied {
				continue
			}
		}
		contents, err := os.ReadFile(file)
		if err != nil {
			log.Fatal(err)
		}
		tx, err := connection.Begin(ctx)
		if err != nil {
			log.Fatal(err)
		}
		if _, err := tx.Exec(ctx, string(contents)); err != nil {
			_ = tx.Rollback(ctx)
			log.Fatal(fmt.Errorf("apply %s: %w", name, err))
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1) ON CONFLICT DO NOTHING`, version); err != nil {
			_ = tx.Rollback(ctx)
			log.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			log.Fatal(err)
		}
		log.Printf("applied migration %s", name)
	}
}
