// Command bitfs-collector runs the collector receiver: verify + archive.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/bsv8/BitFSCollector/internal/archive"
	"github.com/bsv8/BitFSCollector/internal/config"
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
	store := &archive.Store{Root: cfg.ArchiveRoot, MaxBodyBytes: cfg.MaxBodyBytes}
	sem := make(chan struct{}, cfg.MaxConcurrent)
	mux := http.NewServeMux()
	mux.HandleFunc(collector.SubmissionsPath, func(w http.ResponseWriter, r *http.Request) {
		select {
		case sem <- struct{}{}:
			defer func() { <-sem }()
		case <-r.Context().Done():
			return
		}
		store.Handle(w, r)
	})
	// 内置文档控制台：GET / 返回展示页，不影响提交接口。
	mux.HandleFunc("/", web.Handler)
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
