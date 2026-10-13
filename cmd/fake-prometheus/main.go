package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"
)

func main() {
	address := flag.String("listen", "127.0.0.1:9090", "listen address")
	scenario := flag.String("scenario", "success", "success, empty, malformed, slow, or unavailable")
	flag.Parse()
	handler := http.NewServeMux()
	handler.HandleFunc("/api/v1/query", func(w http.ResponseWriter, r *http.Request) {
		switch *scenario {
		case "success":
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Query().Get("query") == "up" {
				_, _ = fmt.Fprint(w, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{"__name__":"up","instance":"fixture-prometheus","job":"prometheus"},"value":[1787133600,"1"]}]}}`)
			} else {
				_, _ = fmt.Fprint(w, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{"__name__":"DCGM_FI_DEV_GPU_UTIL","Hostname":"comp001","gpu":"0","UUID":"GPU-fixture"},"value":[1787133600,"42.5"]}]}}`)
			}
		case "empty":
			_, _ = fmt.Fprint(w, `{"status":"success","data":{"resultType":"vector","result":[]}}`)
		case "malformed":
			_, _ = fmt.Fprint(w, `{"status":"success","data":`)
		case "partial":
			_, _ = fmt.Fprint(w, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{"__name__":"DCGM_FI_DEV_GPU_UTIL","Hostname":"comp001","gpu":"0"},"value":[1787133600,"42.5"]}]},"warnings":["synthetic partial response"]}`)
		case "slow":
			time.Sleep(15 * time.Second)
			_, _ = fmt.Fprint(w, `{"status":"success","data":{"resultType":"vector","result":[]}}`)
		case "unavailable":
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
		default:
			http.Error(w, "unknown fixture scenario", http.StatusBadRequest)
		}
	})
	handler.HandleFunc("/api/v1/query_range", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"status":"success","data":{"resultType":"matrix","result":[{"metric":{"__name__":"DCGM_FI_DEV_GPU_UTIL","Hostname":"comp001","gpu":"0"},"values":[[1787133570,"40"],[1787133600,"42.5"]]}]}}`)
	})
	log.Printf("fake Prometheus listening on %s with scenario %s", *address, *scenario)
	log.Fatal(http.ListenAndServe(*address, handler))
}
