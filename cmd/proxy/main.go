package main

import (
	"context"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"

	"metal-db-proxy/internal/proxy"
)

var logger = logrus.New()

func init() {
	logger.SetFormatter(&logrus.JSONFormatter{})
	logger.SetLevel(logrus.InfoLevel)
}

func main() {
	listener, err := net.Listen("tcp", ":3306")
	if err != nil {
		logger.WithError(err).Fatal("failed to start listener")
	}
	defer listener.Close()

	logger.Info("metal-db-proxy listening on :3306")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go acceptConnections(ctx, listener)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	logger.Info("shutting down gracefully...")
	cancel()

	// Give connections time to close gracefully
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()

	<-shutdownCtx.Done()
	logger.Info("shutdown timeout reached")

	listener.Close()
	logger.Info("listener closed, shutdown complete")
}

func acceptConnections(ctx context.Context, listener net.Listener) {
	for {
		select {
		case <-ctx.Done():
			logger.Info("accept loop stopped")
			return
		default:
			conn, err := listener.Accept()
			if err != nil {
				if ctx.Err() != nil {
					return // Context cancelled
				}
				logger.WithError(err).Warn("accept error")
				continue
			}

			// Handling each MySQL connection in goroutine
			go func(c net.Conn) {
				defer c.Close()
				logger.WithField("remote", c.RemoteAddr()).Info("new MySQL connection")
				proxy.Handle(c)
			}(conn)
		}
	}
}
