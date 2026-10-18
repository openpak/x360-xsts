// Command x360-xsts is OpenPak's Xbox 360 token service: POST /xsts/xsts.svc/IWSTrust13
// on Live service 33, behind the security gateway's service tunnel.
package main

import (
	"context"
	"crypto/rand"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/openpak/x360-xsts/internal/xsts"
)

func main() {
	level := slog.LevelInfo
	if os.Getenv("X360_XSTS_DEBUG") == "true" {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	addr := os.Getenv("X360_XSTS_ADDR")
	if addr == "" {
		addr = ":10033"
	}
	keyFile := os.Getenv("X360_XSTS_KEY")
	if keyFile == "" {
		log.Error("config", "err", "X360_XSTS_KEY (token signing key file) is required")
		os.Exit(2)
	}
	key, err := os.ReadFile(keyFile)
	if errors.Is(err, os.ErrNotExist) { // first start: create a 32-byte key, 0600
		key = make([]byte, 32)
		rand.Read(key)
		err = os.WriteFile(keyFile, key, 0o600)
	}
	if err != nil || len(key) < 16 {
		log.Error("signing key", "err", err, "len", len(key))
		os.Exit(2)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Error("listen", "err", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Info("x360-xsts listening", "addr", ln.Addr())
	srv := &http.Server{Handler: &xsts.Handler{Key: key, Log: log}, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		sc, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(sc)
	}()
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("serve", "err", err)
		os.Exit(1)
	}
}
