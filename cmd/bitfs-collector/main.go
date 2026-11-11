// Command bitfs-collector runs the collector receiver: verify + archive + takeover manifest.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/bsv8/BitFSCollector/internal/archive"
	"github.com/bsv8/BitFSCollector/internal/auth"
	"github.com/bsv8/BitFSCollector/internal/config"
	"github.com/bsv8/BitFSCollector/internal/manifest"
	"github.com/bsv8/BitFSCollector/internal/web"
	collector "github.com/bsv8/BitFSCollectorProtocol/collector"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	configPath := flag.String("config", "config.json", "JSON 配置文件路径 (JSON config file path)")
	flag.Parse()
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.ArchiveRoot, 0o755); err != nil {
		return fmt.Errorf("archive root: %w", err)
	}
	db, err := manifest.Open(cfg.ManifestPath)
	if err != nil {
		return err
	}
	defer db.Close()
	if _, err := archive.Recover(cfg.ArchiveRoot, db, cfg.MaxBodyBytes); err != nil {
		return fmt.Errorf("recover: %w", err)
	}
	if n, err := archive.RecoverCleanup(db); err != nil {
		fmt.Printf("bitfs-collector: cleanup compensation: %d cleaned, first error: %v\n", n, err)
	} else if n > 0 {
		fmt.Printf("bitfs-collector: cleanup compensation: %d cleaned\n", n)
	}
	store := &archive.Store{Root: cfg.ArchiveRoot, MaxBodyBytes: cfg.MaxBodyBytes, MinFreeBytes: cfg.MinFreeBytes, Manifest: db}
	v2 := &archive.V2{Manifest: db, Auth: auth.New(cfg.PullTokens), MaxDownloadBytes: cfg.MaxBodyBytes}
	sem := make(chan struct{}, cfg.MaxConcurrent)
	withSem := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-r.Context().Done():
				return
			}
			h(w, r)
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc(collector.SubmissionsPath, withSem(store.Handle))
	mux.HandleFunc(collector.ArchivesPath, withSem(v2.HandleList))
	mux.HandleFunc(collector.ArchivesPath+"/", withSem(v2.HandleArtifact))
	// 内置文档控制台：GET / 返回展示页，不影响提交接口。
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, collector.ArchivesPath) {
			http.NotFound(w, r)
			return
		}
		web.Handler(w, r)
	})
	server := &http.Server{
		Addr:              cfg.Listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
	}
	listener, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen %s: %w", cfg.Listen, err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	fmt.Printf("bitfs-collector: listening on %s archive=%s\n", listener.Addr(), cfg.ArchiveRoot)
	if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}
