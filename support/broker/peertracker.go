package main

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/credentials"
)

type fdAuthInfo struct {
	Fd uintptr
}

func (a fdAuthInfo) AuthType() string {
	return "fd"
}

type credsAuthInfo struct {
	PID int32
	UID uint32
	GID uint32
}

func (a credsAuthInfo) AuthType() string {
	return "cred"
}

type TransportCredential struct {
	log logrus.FieldLogger
}

func (c TransportCredential) ServerHandshake(rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	if uc, ok := rawConn.(*net.UnixConn); ok {
		file, err := uc.File()
		if err != nil {
			return nil, nil, fmt.Errorf("error getting file from connection: %w", err)
		}

		c.log.WithField("fd", file.Fd()).Infof("Received file descriptor from workload")

		return uc, fdAuthInfo{Fd: file.Fd()}, nil
	}

	if tcpc, ok := rawConn.(*net.TCPConn); ok {
		file, err := tcpc.File()
		if err != nil {
			return nil, nil, fmt.Errorf("error getting file from connection: %w", err)
		}

		c.log.WithField("fd", file.Fd()).Infof("Received file descriptor from network connection")

		return tcpc, fdAuthInfo{Fd: file.Fd()}, nil
	}

	return nil, nil, errors.New("invalid connection")
}

func (c TransportCredential) ClientHandshake(ctx context.Context, authority string, rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	rawConn.Close()
	return rawConn, &fdAuthInfo{}, errors.New("invalid connection")
}

func (c TransportCredential) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{}
}

func (c TransportCredential) Clone() credentials.TransportCredentials {
	return c
}

func (c TransportCredential) OverrideServerName(serverNameOverride string) error {
	return nil
}
