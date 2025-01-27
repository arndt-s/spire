package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"

	"github.com/gogo/status"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/reflection"
)

const (
	agentSocketPath = "/tmp/spire-agent/public/api.sock"
	brokerSocketDir = "/tmp/spire-broker/public"
	networkUnix     = "unix"
	networkTcp      = "tcp"
	brokerPort      = 8080
)

var brokerSocketPath = fmt.Sprintf("%s/api.sock", brokerSocketDir)
var loopbackIP = net.ParseIP("127.0.0.1")

func main() {
	log := logrus.StandardLogger()
	if err := runBroker(log); err != nil {
		log.Fatalf("Error running broker: %v", err)
	}
}

func runBroker(log logrus.FieldLogger) error {
	wlServer := BrokeringWorkloadAPIServer{
		log: log,
	}
	s := grpc.NewServer(grpc.Creds(TransportCredential{log: log}))
	workload.RegisterSpiffeWorkloadAPIServer(s, &wlServer)
	reflection.Register(s)

	errg := new(errgroup.Group)
	errg.Go(func() error {
		if err := os.MkdirAll(brokerSocketDir, 0777); err != nil {
			return fmt.Errorf("failed to create broker directory: %v", err)
		}

		os.Remove(brokerSocketPath)
		listener, err := net.ListenUnix(networkUnix, &net.UnixAddr{Name: brokerSocketPath, Net: networkUnix})
		if err != nil {
			return fmt.Errorf("failed to listen on %s: %v", agentSocketPath, err)
		}

		log.WithField("socket", brokerSocketPath).Info("Starting broker on UDS")
		if err := s.Serve(listener); err != nil {
			return fmt.Errorf("failed to serve: %v", err)
		}

		return nil
	})

	errg.Go(func() error {
		l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: loopbackIP, Port: brokerPort})
		if err != nil {
			return fmt.Errorf("failed to listen on TCP: %v", err)
		}

		log.WithField("port", brokerPort).Info("Starting broker on TCP")
		if err := s.Serve(l); err != nil {
			return fmt.Errorf("failed to serve: %v", err)
		}

		return nil
	})

	return errg.Wait()
}

type BrokeringWorkloadAPIServer struct {
	workload.UnimplementedSpiffeWorkloadAPIServer
	log logrus.FieldLogger
}

func (s *BrokeringWorkloadAPIServer) FetchJWTSVID(ctx context.Context, req *workload.JWTSVIDRequest) (*workload.JWTSVIDResponse, error) {
	wlc, close, err := s.newWorkloadClient(ctx)
	defer close()
	if err != nil {
		s.log.WithError(err).Error("Failed to create workload client")
		return nil, fmt.Errorf("failed to create workload client: %w", err)
	}

	md := metadata.New(map[string]string{"workload.spiffe.io": "true"})
	ctx = metadata.NewOutgoingContext(ctx, md)

	resp, err := wlc.FetchJWTSVID(ctx, req)
	if err != nil {
		s.log.WithError(err).Error("Failed to fetch jwt svid")
		return nil, fmt.Errorf("failed to fetch JWT SVID from agent: %w", err)
	}

	return resp, nil
}

func (s *BrokeringWorkloadAPIServer) FetchJWTBundles(req *workload.JWTBundlesRequest, srv workload.SpiffeWorkloadAPI_FetchJWTBundlesServer) error {
	ctx := srv.Context()
	wlc, close, err := s.newWorkloadClient(ctx)
	defer close()
	if err != nil {
		s.log.WithError(err).Error("Failed to create workload client")
		return fmt.Errorf("failed to create workload client: %w", err)
	}

	md := metadata.New(map[string]string{"workload.spiffe.io": "true"})
	ctx = metadata.NewOutgoingContext(ctx, md)

	stream, err := wlc.FetchJWTBundles(ctx, req)
	if err != nil {
		s.log.WithError(err).Error("Failed to fetch jwt bundles")
		return fmt.Errorf("failed to fetch JWT bundles from agent: %w", err)
	}

	for {
		msg, err := stream.Recv()
		switch {
		case errors.Is(err, io.EOF):
			return nil
		case err != nil:
			if st, ok := status.FromError(err); ok && st.Code() == codes.Canceled {
				return nil
			}
			s.log.WithError(err).Error("Failed to receive jwt bundles")
			return fmt.Errorf("failed to receive JWT bundles from agent: %w", err)
		}

		if err := srv.Send(msg); err != nil {
			s.log.WithError(err).Error("Failed to send jwt bundles")
			return fmt.Errorf("failed to send JWT bundles to client: %w", err)
		}
	}
}

func (s *BrokeringWorkloadAPIServer) newWorkloadClient(ctx context.Context) (workload.SpiffeWorkloadAPIClient, func() error, error) {
	peer, ok := peer.FromContext(ctx)
	noopClose := func() error { return nil }
	if !ok {
		return nil, noopClose, fmt.Errorf("no peer info")
	}

	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			unixConn, err := net.DialUnix(networkUnix, nil, &net.UnixAddr{Name: agentSocketPath, Net: networkUnix})
			if err != nil {
				s.log.WithError(err).Error("Failed to dial agent")
				return nil, fmt.Errorf("failed to dial: %w", err)
			}
			// TODO: is this necessary?
			err = activatePassCreds(unixConn)
			if err != nil {
				s.log.WithError(err).Error("Failed to activate pass creds")
				return nil, fmt.Errorf("failed to activate pass creds: %w", err)
			}
			return &Conn{
				info:     peer.AuthInfo,
				UnixConn: unixConn,
				log:      s.log,
			}, nil
		}),
	}
	c, err := grpc.NewClient(fmt.Sprintf("%s://%s", networkUnix, agentSocketPath), opts...)
	if err != nil {
		return nil, noopClose, fmt.Errorf("failed to create client: %w", err)
	}

	return workload.NewSpiffeWorkloadAPIClient(c), c.Close, nil
}

func activatePassCreds(conn *net.UnixConn) error {
	file, err := conn.File()
	if err != nil {
		return fmt.Errorf("failed to get file from connection: %w", err)
	}

	if err := syscall.SetsockoptInt(int(file.Fd()), syscall.SOL_SOCKET, syscall.SO_PASSCRED, 1); err != nil {
		return fmt.Errorf("failed to set SO_PASSCRED: %w", err)
	}

	return nil
}
