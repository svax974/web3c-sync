// syncd is the web3c-sync server: an end-to-end-encrypted document vault.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"web3c.cc/sync/internal/api"
	"web3c.cc/sync/internal/config"
	"web3c.cc/sync/internal/store"
)

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	st, err := store.Open(cfg.DBPath, cfg.BlobDir)
	if err != nil {
		log.Fatalf("store: %v", err)
	}
	defer st.Close()

	srv := api.New(cfg, st)
	stop := make(chan struct{})
	go srv.Maintain(stop)

	main := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	var metrics *http.Server
	if cfg.MetricsListen != "" {
		metrics = &http.Server{Addr: cfg.MetricsListen, Handler: srv.MetricsHandler(), ReadHeaderTimeout: 5 * time.Second}
		go func() {
			if err := metrics.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("metrics: %v", err)
			}
		}()
	}
	go func() {
		log.Printf("syncd instance=%s listen=%s community=%v", cfg.Instance, cfg.Listen, cfg.Community)
		if err := main.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("listen: %v", err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	close(stop)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = main.Shutdown(ctx)
	if metrics != nil {
		_ = metrics.Shutdown(ctx)
	}
}
