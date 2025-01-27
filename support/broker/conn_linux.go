//go:build linux

package main

import (
	"net"
	"syscall"
)

func writeCreds(unixConn *net.UnixConn, b []byte, pid int32, uid uint32, gid uint32) (int, int, error) {
	ucred := syscall.Ucred{
		Pid: pid,
		Uid: uid,
		Gid: gid,
	}
	scm := syscall.UnixCredentials(&ucred)
	return unixConn.WriteMsgUnix(b, scm, nil)
}
