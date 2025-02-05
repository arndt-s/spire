package peertracker

import (
	"errors"
	"fmt"
	"strconv"
	"syscall"

	"github.com/prometheus/procfs"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

var _ Watcher = &OnBehalfOfWatcher{}

// OnBehalfOfWatcher is a Watcher that combines the watcher of the caller and the watcher of the on-behalf-of process.
type OnBehalfOfWatcher struct {
	callerWatcher   Watcher
	workloadWatcher Watcher
	onClose         func()
	log             logrus.FieldLogger
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
	w.log.Info("Closing on-behalf-of watcher")
	w.onClose()
	w.callerWatcher.Close()
	w.workloadWatcher.Close()
}

// ReadOnBehalfOf reads the optional caller information from the given out-of-band data.
func ReadOnBehalfOf(oobn int, oob []byte, log logrus.FieldLogger) (*CallerInfo, bool, func(), error) {
	close := func() {}
	if oobn == 0 {
		return nil, false, close, nil
	}

	scms, err := syscall.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return nil, false, close, fmt.Errorf("failed to parse socket control message: %w", err)
	}

	var info *CallerInfo
	for _, scm := range scms {
		if info != nil {
			return nil, false, close, errors.New("received more than one socket control message")
		}

		if scm.Header.Level == syscall.SOL_SOCKET && scm.Header.Type == syscall.SCM_RIGHTS {
			info, close, err = readScmRights(scm, log)
			if err != nil {
				return nil, false, close, fmt.Errorf("failed to read SCM_RIGHTS: %w", err)
			}
		} else if scm.Header.Level == syscall.SOL_SOCKET && scm.Header.Type == syscall.SCM_CREDENTIALS {
			info, err = readScmCreds(scm)
			if err != nil {
				return nil, false, close, fmt.Errorf("failed to read SCM_CREDS: %w", err)
			}
		}
	}

	return info, true, close, nil
}

func readScmCreds(_ syscall.SocketControlMessage) (*CallerInfo, error) {
	// TODO: Implement this
	return nil, errors.New("SCM_CREDS are not supported yet")
}

func readScmRights(scm syscall.SocketControlMessage, log logrus.FieldLogger) (*CallerInfo, func(), error) {
	close := func() {}
	fds, err := syscall.ParseUnixRights(&scm)
	if err != nil {
		return nil, close, fmt.Errorf("failed to parse SCM_RIGHTS: %w", err)
	}

	switch {
	case len(fds) > 1:
		return nil, close, errors.New("received more than one file descriptor with SCM_RIGHTS")
	case len(fds) == 0:
		return nil, close, errors.New("received no file descriptor with SCM_RIGHTS")
	}

	// We need to close it once the connection is finisehd, otherwise
	// the file or socket remains open and is effectively handed over the SPIRE.
	close = func() {
		unix.Close(fds[0])
	}

	info, err := getCallerInfoFromFileDescriptor(uintptr(fds[0]))
	if err != nil {
		return nil, close, fmt.Errorf("failed to get caller info from file descriptor: %w", err)
	}

	if info.PID == 0 {
		log.Info("no direct file descriptor received, trying tcp ...")
		// this is an indication that the file descriptor is from a network socket.
		tcpInfo, err := extractCallerInfoFromTCP(fds[0])
		if err != nil {
			return nil, close, fmt.Errorf("failed to extract caller info from TCP: %w", err)
		}

		info = tcpInfo
	}

	return &info, close, nil
}

func extractCallerInfoFromTCP(fd int) (CallerInfo, error) {
	sockAddr, err := syscall.Getpeername(fd)
	if err != nil {
		return CallerInfo{}, fmt.Errorf("failed to get peer name: %w", err)
	}

	addr4, ok := sockAddr.(*syscall.SockaddrInet4)
	if !ok {
		return CallerInfo{}, errors.New("only IPv4 addresses are allowed")
	}

	fs, err := procfs.NewFS("/proc")
	if err != nil {
		return CallerInfo{}, fmt.Errorf("failed to open /proc: %w", err)
	}

	tcp, err := fs.NetTCP()
	if err != nil {
		return CallerInfo{}, fmt.Errorf("failed to read /proc/net/tcp: %w", err)
	}

	var inode uint64
	for _, entry := range tcp {
		if entry.LocalPort != uint64(addr4.Port) || !entry.LocalAddr.IsLoopback() {
			continue
		}

		if inode != 0 {
			return CallerInfo{}, errors.New("found multiple matching sockets")
		}

		inode = entry.Inode
	}

	if inode == 0 {
		return CallerInfo{}, errors.New("socket not found")
	}

	procs, err := fs.AllProcs()
	if err != nil {
		return CallerInfo{}, fmt.Errorf("failed to read /proc: %w", err)
	}

	var creds []CallerInfo
	for _, proc := range procs {
		fdInfos, err := proc.FileDescriptorsInfo()
		if err != nil {
			continue
		}

		for _, fdInfo := range fdInfos {

			// string to uint64
			fdInode, err := strconv.ParseUint(fdInfo.Ino, 10, 64)
			if err != nil {
				continue
			}

			if fdInode == inode {
				status, err := proc.NewStatus()
				if err != nil {
					continue
				}

				creds = append(creds, CallerInfo{
					PID: int32(proc.PID),
					UID: uint32(status.UIDs[0]),
					GID: uint32(status.GIDs[0]),
				})
			}
		}
	}

	if len(creds) == 0 {
		return CallerInfo{}, errors.New("PID not found for inode")
	} else if len(creds) > 1 {
		return CallerInfo{}, errors.New("found multiple PIDs for inode")
	}

	return creds[0], nil
}
