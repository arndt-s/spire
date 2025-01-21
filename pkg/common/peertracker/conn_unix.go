package peertracker

import (
	"errors"
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

var _ net.Conn = &UnixConn{}

type UnixConn struct {
	*Conn
	unixConn *net.UnixConn
	tracker  PeerTracker
	Watcher  Watcher
}

func (c *UnixConn) Read(b []byte) (n int, err error) {
	oob := []byte{}
	n, oobn, _, _, err := c.unixConn.ReadMsgUnix(b, oob)

	if oobn > 0 {
		scms, err := syscall.ParseSocketControlMessage(oob[:oobn])
		if err != nil {
			return n, fmt.Errorf("failed to parse socket control message: %v", err)
		}

		var fds []int
		for _, scm := range scms {
			if scm.Header.Level == syscall.SOL_SOCKET && scm.Header.Type == syscall.SCM_RIGHTS {
				fd, err := syscall.ParseUnixRights(&scm)
				if err != nil {
					return n, fmt.Errorf("failed to parse unix rights: %v", err)
				}
				fds = append(fds, fd...)
			}
		}

		if len(fds) > 1 {
			return n, errors.New("received more than one file descriptor")
		}

		if len(fds) == 1 {
			// TODO: add to watcher
			obo, err := getCallerInfoFromFileDescriptor(uintptr(unsafe.Pointer(&b[0])))
			if err != nil {
				return n, fmt.Errorf("failed to get caller info from file descriptor: %v", err)
			}

			if c.Conn.Info.OnBehalfOf != nil && *c.Conn.Info.OnBehalfOf != obo {
				return n, errors.New("received file descriptor from different caller")
			}

			w, err := c.tracker.NewWatcher(obo)
			if err != nil {
				return n, fmt.Errorf("failed to create watcher: %v", err)
			}

			c.Info.Watcher = &CombinedWatcher{
				callerWatcher: c.Info.Watcher,
				oboWatcher:    w,
			}
			c.Info.OnBehalfOf = &obo
		}
	}

	return n, err
}

var _ Watcher = &CombinedWatcher{}

type CombinedWatcher struct {
	callerWatcher Watcher
	oboWatcher    Watcher
}

func (w *CombinedWatcher) PID() int32 {
	return w.oboWatcher.PID()
}

func (w *CombinedWatcher) IsAlive() error {
	if err := w.callerWatcher.IsAlive(); err != nil {
		return err
	}
	return w.oboWatcher.IsAlive()
}

func (w *CombinedWatcher) Close() {
	w.callerWatcher.Close()
	w.oboWatcher.Close()
}
