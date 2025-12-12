package proxy

import (
	"net"

	"github.com/sirupsen/logrus"
)

var log = logrus.New()

func init() {
	log.SetFormatter(&logrus.JSONFormatter{})
	log.SetLevel(logrus.InfoLevel)
}

// Handle processes a MySQL client connection
func Handle(conn net.Conn) {
	defer conn.Close()

	log.WithField("remote", conn.RemoteAddr()).Info("handling MySQL connection")

	// TODO: Implement MySQL protocol handling
	// - Send greeting packet
	// - Handle authentication
	// - Process queries

	// For now, just log and close
	log.WithField("remote", conn.RemoteAddr()).Info("connection closed")
}
