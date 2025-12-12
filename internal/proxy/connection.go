package proxy

import (
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	COM_QUIT    = 0x01
	COM_INIT_DB = 0x02
	COM_QUERY   = 0x03
)

type Connection struct {
	conn      net.Conn
	logger    *logrus.Entry
	sequence  uint8 // server-side sequence counter
	username  string
	connected time.Time
}

func NewConnection(c net.Conn) *Connection {
	return &Connection{
		conn:      c,
		logger:    logrus.WithField("remote", c.RemoteAddr().String()),
		sequence:  0,
		connected: time.Now(),
	}
}

func (c *Connection) Handle() {
	defer func() {
		if r := recover(); r != nil {
			c.logger.Errorf("panic in connection: %v", r)
		}
		c.conn.Close()
		c.logger.Info("connection closed")
	}()

	c.logger.Info("new connection")

	scramble, err := SendHandshake(c.conn)
	if err != nil {
		c.logger.WithError(err).Error("failed to send handshake")
		return
	}
	c.sequence = 1

	if err := HandleHandshake(c.conn, c.conn, scramble, c.sequence); err != nil {
		c.logger.WithError(err).Error("handshake/auth failed")
		return
	}
	c.logger.Info("client authenticated")

	for {
		pkt, err := ReadPacket(c.conn)
		if err != nil {
			if errors.Is(err, io.EOF) {
				c.logger.Info("client disconnected (EOF)")
				return
			}
			c.logger.WithError(err).Warn("error reading packet")
			return
		}

		if len(pkt.Payload) == 0 {
			continue
		}

		start := time.Now()
		resp, err := c.handleCommand(pkt.Payload)
		_ = start // placeholder until metrics are wired

		if err != nil {
			errPkt := NewErrPacket(1064, "42000", err.Error())
			if werr := WritePacket(c.conn, pkt.Sequence+1, errPkt); werr != nil {
				c.logger.WithError(werr).Warn("failed to write error packet")
				return
			}
			continue
		}

		if resp == nil {
			continue
		}

		if err := WritePacket(c.conn, pkt.Sequence+1, resp); err != nil {
			c.logger.WithError(err).Warn("failed to write response packet")
			return
		}
	}
}

func (c *Connection) handleCommand(payload []byte) ([]byte, error) {
	cmd := payload[0]
	data := payload[1:]

	switch cmd {
	case COM_QUIT:
		c.logger.Info("COM_QUIT received")
		return nil, io.EOF

	case COM_INIT_DB:
		dbName := string(data)
		c.logger.WithField("db", dbName).Info("COM_INIT_DB received")
		return NewOKPacket(0, 0, 0), nil

	case COM_QUERY:
		query := string(data)
		c.logger.WithField("query", query).Debug("COM_QUERY received")
		return c.executeQuery(query)

	default:
		c.logger.WithField("cmd", cmd).Warn("unsupported command")
		return nil, fmt.Errorf("unsupported command: %d", cmd)
	}
}
func (c *Connection) executeQuery(query string) ([]byte, error) {
	_ = query
	return NewOKPacket(0, 0, 0), nil
}

func Handle(conn net.Conn) {
	NewConnection(conn).Handle()
}
