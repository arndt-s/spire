package peertracker

import (
	"net"
	"syscall"
)

// Conn is a wrapper around a net.Conn that exposes AuthInfo about the caller, potentially containing on-behalf-of information.
type Conn struct {
	net.Conn
	info       AuthInfo
	newWatcher func(CallerInfo) (Watcher, error)
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

	obo, ok, err := ReadOnBehalfOf(oobn, oob)
	switch {
	case err != nil:
		return n, err
	case !ok:
		return n, nil
	}

	oboWatcher, err := c.newWatcher(*obo)
	if err != nil {
		return n, err
	}

	if obo != nil {
		c.info.OnBehalfOf = obo
		c.info.Watcher = &OnBehalfOfWatcher{
			callerWatcher:   c.info.Watcher,
			workloadWatcher: oboWatcher,
		}
	}

	return n, nil
}

func (c *Conn) Info() *AuthInfo {
	return &c.info
}

func (c *Conn) Close() error {
	c.info.Watcher.Close()
	return c.Conn.Close()
}
