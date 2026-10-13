// Explicit operator enrollment. No discovery or secret output.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/networkmonitor"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

func main() {
	path := flag.String("enrollment", "", "reviewed enrollment JSON")
	management := flag.Bool("enable-management", false, "explicitly add reviewed management bonds to an existing IB enrollment")
	disableManagement := flag.String("disable-management", "", "disable only management monitoring for cluster")
	disable := flag.String("disable", "", "cluster to disable")
	flag.Parse()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, os.Getenv("SHERLOCK_DATABASE_URL"))
	if err != nil {
		fail()
	}
	defer pool.Close()
	if *disableManagement != "" {
		if *disableManagement != "fixture2-zone2" || storepg.NewNetworkMonitorStore(pool).DisableManagement(ctx, *disableManagement) != nil {
			fail()
		}
		fmt.Println("management monitoring disabled")
		return
	}
	if *disable != "" {
		if *disable != "fixture2-zone2" {
			fail()
		}
		if _, err := pool.Exec(ctx, `UPDATE gp09_network_monitors SET enabled=false WHERE cluster_id=$1`, *disable); err != nil {
			fail()
		}
		fmt.Println("network monitoring disabled")
		return
	}
	data, err := os.ReadFile(*path)
	if err != nil || len(data) > 65536 {
		fail()
	}
	var e networkmonitor.Enrollment
	if json.Unmarshal(data, &e) != nil {
		fail()
	}
	store := storepg.NewNetworkMonitorStore(pool)
	if *management {
		err = store.EnableManagement(ctx, e)
	} else {
		err = store.Enroll(ctx, e)
	}
	if err != nil {
		fail()
	}
	fmt.Println("network enrollment accepted:", e.ClusterID, e.Revision, len(e.Ports))
}
func fail() { fmt.Fprintln(os.Stderr, "network enrollment failed"); os.Exit(1) }
