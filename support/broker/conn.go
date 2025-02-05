package main

import (
	"errors"
	"net"
	"syscall"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/credentials"
)

// Conn is a wrapper around a UnixConn that sends a SCM_RIGHTS socket control message on the first write.
type Conn struct {
	*net.UnixConn
	info credentials.AuthInfo
	sent bool
	log  logrus.FieldLogger
}

func (c *Conn) Write(b []byte) (int, error) {
	if c.sent {
		return c.UnixConn.Write(b)
	}

	var n, oobn int
	var err error
	if fdInfo, ok := c.info.(fdAuthInfo); ok {
		c.log.WithField("fd", fdInfo.Fd).Info("Sending SCM_RIGHTS")
		n, oobn, err = writeFileDescriptor(c.UnixConn, b, fdInfo.Fd)
	} else if creds, ok := c.info.(credsAuthInfo); ok {
		c.log.
			WithField("pid", creds.PID).
			WithField("uid", creds.UID).
			WithField("gid", creds.GID).Info("Sending SCM_CREDS")
		n, oobn, err = writeCreds(c.UnixConn, b, creds.PID, creds.UID, creds.GID)
	} else {
		return 0, errors.New("unsupported auth info type")
	}

	if err == nil && oobn > 0 {
		c.sent = true
	}

	return n, err
}

func (c *Conn) Close() error {
	c.log.Info("Closing agent connection")
	return c.UnixConn.Close()
}

func writeFileDescriptor(unixConn *net.UnixConn, b []byte, fd uintptr) (int, int, error) {
	rights := syscall.UnixRights(int(fd))
	return unixConn.WriteMsgUnix(b, rights, nil)
}
