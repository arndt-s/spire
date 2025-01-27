package peertracker

import (
	"errors"
	"fmt"
	"syscall"
)

var _ Watcher = &OnBehalfOfWatcher{}

// OnBehalfOfWatcher is a Watcher that combines the watcher of the caller and the watcher of the on-behalf-of process.
type OnBehalfOfWatcher struct {
	callerWatcher   Watcher
	workloadWatcher Watcher
}

func (w *OnBehalfOfWatcher) PID() int32 {
	return w.workloadWatcher.PID()
}

func (w *OnBehalfOfWatcher) IsAlive() error {
	if err := w.callerWatcher.IsAlive(); err != nil {
		return err
	}
	return w.workloadWatcher.IsAlive()
}

func (w *OnBehalfOfWatcher) Close() {
	w.callerWatcher.Close()
	w.workloadWatcher.Close()
}

// ReadOnBehalfOf reads the optional caller information from the given out-of-band data.
func ReadOnBehalfOf(oobn int, oob []byte) (*CallerInfo, bool, error) {
	if oobn == 0 {
		return nil, false, nil
	}

	scms, err := syscall.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return nil, false, fmt.Errorf("failed to parse socket control message: %w", err)
	}

	var info *CallerInfo
	for _, scm := range scms {
		if info != nil {
			return nil, false, errors.New("received more than one socket control message")
		}

		if scm.Header.Level == syscall.SOL_SOCKET && scm.Header.Type == syscall.SCM_RIGHTS {
			info, err = readScmRights(scm)
			if err != nil {
				return nil, false, fmt.Errorf("failed to read SCM_RIGHTS: %w", err)
			}
		} else if scm.Header.Level == syscall.SOL_SOCKET && scm.Header.Type == syscall.SCM_CREDENTIALS {
			info, err = readScmCreds(scm)
			if err != nil {
				return nil, false, fmt.Errorf("failed to read SCM_CREDS: %w", err)
			}
		}
	}

	return info, true, nil
}

func readScmCreds(_ syscall.SocketControlMessage) (*CallerInfo, error) {
	// TODO: Implement this
	return nil, errors.New("SCM_CREDS are not supported yet")
}

func readScmRights(scm syscall.SocketControlMessage) (*CallerInfo, error) {
	fds, err := syscall.ParseUnixRights(&scm)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SCM_RIGHTS: %w", err)
	}

	switch {
	case len(fds) > 1:
		return nil, errors.New("received more than one file descriptor with SCM_RIGHTS")
	case len(fds) == 0:
		return nil, errors.New("received no file descriptor with SCM_RIGHTS")
	}

	info, err := getCallerInfoFromFileDescriptor(uintptr(fds[0]))
	if err != nil {
		return nil, fmt.Errorf("failed to get caller info from file descriptor: %w", err)
	}

	return &info, nil
}
