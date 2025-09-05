package kubernetes

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"time"

	kubernetesv1api "github.com/spiffe/spire/pkg/agent/api/kubernetes/v1"
	kubernetesv1 "github.com/spiffe/spire/proto/spire/agent/kubernetes/v1"
	kubernetestokenv1 "github.com/spiffe/spire/proto/spire/server/kubernetestoken/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type Server struct {
	config       *Config
	serverClient kubernetestokenv1.KubernetesTokenClient
	grpcServer   *grpc.Server
}

type Config struct {
	SocketPath        string
	AllowedSPIFFEIDs  []string
	MaxTokenLifetime  time.Duration
	KeyRefreshHint    time.Duration
}

func New(config *Config, serverClient kubernetestokenv1.KubernetesTokenClient) *Server {
	return &Server{
		config:       config,
		serverClient: serverClient,
	}
}

func (s *Server) Start(ctx context.Context) error {
	// Remove existing socket file
	os.Remove(s.config.SocketPath)

	listener, err := net.Listen("unix", s.config.SocketPath)
	if err != nil {
		return fmt.Errorf("failed to listen on socket: %v", err)
	}

	// Set up access control
	interceptor := kubernetesv1api.NewAccessControlInterceptor(s.config.AllowedSPIFFEIDs)

	// Create gRPC server with interceptor and mTLS for external connections
	// For external connections from Kubernetes API server, we need TLS credentials
	s.grpcServer = grpc.NewServer(
		grpc.UnaryInterceptor(interceptor.UnaryInterceptor),
		grpc.Creds(credentials.NewTLS(&tls.Config{
			ClientAuth: tls.RequireAndVerifyClientCert,
			// TODO: Configure proper CA bundle for verifying client certificates
		})),
	)

	// Register service
	serviceConfig := &kubernetesv1api.Config{
		MaxTokenLifetime: s.config.MaxTokenLifetime,
		KeyRefreshHint:   s.config.KeyRefreshHint,
	}

	service := kubernetesv1api.New(s.serverClient, serviceConfig)
	kubernetesv1.RegisterExternalJWTSignerServer(s.grpcServer, service)

	go func() {
		<-ctx.Done()
		s.grpcServer.GracefulStop()
	}()

	return s.grpcServer.Serve(listener)
}

func (s *Server) Stop() {
	if s.grpcServer != nil {
		s.grpcServer.GracefulStop()
	}
	os.Remove(s.config.SocketPath)
}