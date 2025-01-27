//go:build !linux

package main

import (
	"errors"
	"net"
)

func writeCreds(_ *net.UnixConn, _ []byte, _ int32, _ uint32, _ uint32) (int, int, error) {
	return 0, 0, errors.New("credential passing is only supported in Linux")
}
