package peertracker

import (
	"net"
	"syscall"

	"github.com/sirupsen/logrus"
)

// Conn is a wrapper around a net.Conn that exposes AuthInfo about the caller, potentially containing on-behalf-of information.
type Conn struct {
	net.Conn
	info       AuthInfo
	newWatcher func(CallerInfo) (Watcher, error)
	log        logrus.FieldLogger
}

func (c *Conn) Read(b []byte) (int, error) {
	unixConn, ok := c.Conn.(*net.UnixConn)
	if !ok {
		return c.Conn.Read(b)
	}

	oob := make([]byte, syscall.CmsgLen(4))
	n, oobn, _, _, err := unixConn.ReadMsgUnix(b, oob)
	if err != nil {
		return n, err
	}

	obo, ok, close, err := ReadOnBehalfOf(oobn, oob, c.log)
	switch {
	case err != nil:
		close()
		c.log.WithError(err).Error("failed to read on-behalf-of")
		return n, err
	case !ok:
		return n, nil
	}

	c.log.WithField("obo-pid", obo.PID).WithField("obo-uid", obo.UID).Info("On-behalf-of data received")

	oboWatcher, err := c.newWatcher(*obo)
	if err != nil {
		close()
		return n, err
	}

	if obo != nil {
		c.info.OnBehalfOf = obo
		c.info.Watcher = &OnBehalfOfWatcher{
			callerWatcher:   c.info.Watcher,
			workloadWatcher: oboWatcher,
			onClose:         close,
			log:             c.log,
		}
	}

	return n, nil
}

func (c *Conn) Info() *AuthInfo {
	return &c.info
}

func (c *Conn) Close() error {
	c.log.Info("Closing connection")
	c.info.Watcher.Close()
	return c.Conn.Close()
}
