package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/prometheus/procfs"
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
		info, err := ExtractOwnPIDForTesting()
		if err != nil {
			return nil, nil, fmt.Errorf("error extracting PID from TCP connection: %w", err)
		}

		c.log.
			WithField("pid", info.PID).
			WithField("uid", info.UID).
			WithField("gid", info.GID).Infof("Received creds from workload")

		return tcpc, info, nil
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

func ExtractOwnPIDForTesting() (credsAuthInfo, error) {
	fs, err := procfs.NewDefaultFS()
	if err != nil {
		return credsAuthInfo{}, fmt.Errorf("failed to open /proc: %w", err)
	}

	proc, err := fs.Self()
	if err != nil {
		return credsAuthInfo{}, fmt.Errorf("failed to read /proc/self: %w", err)
	}

	status, err := proc.NewStatus()
	if err != nil {
		return credsAuthInfo{}, fmt.Errorf("failed to read /proc/self/status: %w", err)
	}

	return credsAuthInfo{
		PID: int32(proc.PID),
		UID: uint32(status.UIDs[0]),
		GID: uint32(status.GIDs[0]),
	}, nil
}

func ExtractPIDFromTCP2(conn *net.TCPConn) (credsAuthInfo, error) {
	fd, err := conn.File()
	if err != nil {
		return credsAuthInfo{}, fmt.Errorf("failed to get file descriptor: %w", err)
	}

	sockAddr, err := syscall.Getpeername(int(fd.Fd()))
	if err != nil {
		return credsAuthInfo{}, fmt.Errorf("failed to get peer name: %w", err)
	}

	addr4, ok := sockAddr.(*syscall.SockaddrInet4)
	if !ok {
		return credsAuthInfo{}, errors.New("only IPv4 addresses are allowed")
	}

	fs, err := procfs.NewFS("/proc")
	if err != nil {
		return credsAuthInfo{}, fmt.Errorf("failed to open /proc: %w", err)
	}

	tcp, err := fs.NetTCP()
	if err != nil {
		return credsAuthInfo{}, fmt.Errorf("failed to read /proc/net/tcp: %w", err)
	}

	var inode uint64
	for _, entry := range tcp {
		if entry.LocalPort != uint64(addr4.Port) || !entry.LocalAddr.IsLoopback() {
			continue
		}

		if inode != 0 {
			return credsAuthInfo{}, errors.New("found multiple matching sockets")
		}

		inode = entry.Inode
	}

	if inode == 0 {
		return credsAuthInfo{}, errors.New("socket not found")
	}

	procs, err := fs.AllProcs()
	if err != nil {
		return credsAuthInfo{}, fmt.Errorf("failed to read /proc: %w", err)
	}

	var creds []credsAuthInfo
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
				// status, err := proc.NewStatus()
				// if err != nil {
				// 	continue
				// }

				creds = append(creds, credsAuthInfo{
					//PID: int32(proc.PID),
					//UID: uint32(status.UIDs[0]),
					//GID: uint32(status.GIDs[0]),
				})
			}
		}
	}

	if len(creds) == 0 {
		return credsAuthInfo{}, errors.New("PID not found for inode")
	} else if len(creds) > 1 {
		return credsAuthInfo{}, errors.New("found multiple PIDs for inode")
	}

	return creds[0], nil
}

func ExtractPIDFromTCP(conn *net.TCPConn) (credsAuthInfo, error) {
	fd, err := conn.File()
	if err != nil {
		return credsAuthInfo{}, fmt.Errorf("failed to get file descriptor: %w", err)
	}

	sockAddr, err := syscall.Getpeername(int(fd.Fd()))
	if err != nil {
		return credsAuthInfo{}, fmt.Errorf("failed to get peer name: %w", err)
	}

	addr4, ok := sockAddr.(*syscall.SockaddrInet4)
	if !ok {
		return credsAuthInfo{}, errors.New("only IPv4 addresses are allowed")
	}

	pid, err := findPIDByPort(addr4.Port, addr4.Addr[:])
	if err != nil {
		return credsAuthInfo{}, fmt.Errorf("failed to find PID by port: %w", err)
	}

	fmt.Println("PID:", pid)

	return credsAuthInfo{}, errors.New("not implemented")
}

func findPIDByPort(port int, addr []byte) (int, error) {
	// Convert port to hex string format as found in /proc/net/tcp
	portHex := fmt.Sprintf("%04X", port)

	// Convert IP to hex string format
	ipHex := fmt.Sprintf("%02X%02X%02X%02X", addr[3], addr[2], addr[1], addr[0])

	// Read /proc/net/tcp
	file, err := os.Open("/proc/net/tcp")
	if err != nil {
		return 0, fmt.Errorf("failed to open /proc/net/tcp: %v", err)
	}
	defer file.Close()

	var inode string
	scanner := bufio.NewScanner(file)
	// Skip header line
	scanner.Scan()

	// Scan each line
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}

		// Split local address into IP and port
		local := strings.Split(fields[1], ":")
		if len(local) != 2 {
			continue
		}

		// Check if this is our connection
		if local[1] == portHex && local[0] == ipHex {
			inode = fields[9]
			break
		}
	}

	if inode == "" {
		return 0, fmt.Errorf("socket not found")
	}

	return findPIDByInode(inode)
}

func findPIDByInode(inode string) (int, error) {
	// Read /proc directory
	procDir, err := os.Open("/proc")
	if err != nil {
		return 0, fmt.Errorf("failed to open /proc: %v", err)
	}
	defer procDir.Close()

	// Read all directory entries
	entries, err := procDir.Readdir(-1)
	if err != nil {
		return 0, fmt.Errorf("failed to read /proc: %v", err)
	}

	// Look through each process directory
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		// Check if directory name is a number (PID)
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		// Check fd directory for this process
		fdPath := filepath.Join("/proc", entry.Name(), "fd")
		fds, err := ioutil.ReadDir(fdPath)
		if err != nil {
			continue
		}

		// Look through each file descriptor
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdPath, fd.Name()))
			if err != nil {
				continue
			}

			// Socket file descriptors have the format: "socket:[inode]"
			if strings.Contains(link, "socket:["+inode+"]") {
				return pid, nil
			}
		}
	}

	return 0, fmt.Errorf("PID not found for inode %s", inode)
}
