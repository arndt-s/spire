package kubernetesv1

import (
	"context"
	"time"

	kubernetesv1 "github.com/spiffe/spire/proto/spire/agent/kubernetes/v1"
	kubernetestokenv1 "github.com/spiffe/spire/proto/spire/server/kubernetestoken/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type Service struct {
	kubernetesv1.UnsafeExternalJWTSignerServer

	serverClient kubernetestokenv1.KubernetesTokenClient
	config       *Config
}

type Config struct {
	MaxTokenLifetime time.Duration
	KeyRefreshHint   time.Duration
}

func New(serverClient kubernetestokenv1.KubernetesTokenClient, config *Config) *Service {
	return &Service{
		serverClient: serverClient,
		config:       config,
	}
}

func (s *Service) Metadata(ctx context.Context, req *kubernetesv1.MetadataRequest) (*kubernetesv1.MetadataResponse, error) {
	return &kubernetesv1.MetadataResponse{
		MaxTokenExpirationSeconds: int64(s.config.MaxTokenLifetime.Seconds()),
	}, nil
}

func (s *Service) FetchKeys(ctx context.Context, req *kubernetesv1.FetchKeysRequest) (*kubernetesv1.FetchKeysResponse, error) {
	resp, err := s.serverClient.GetPublicKeys(ctx, &kubernetestokenv1.GetPublicKeysRequest{})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to fetch keys from server: %v", err)
	}

	keys := make([]*kubernetesv1.Key, len(resp.Keys))
	for i, key := range resp.Keys {
		keys[i] = &kubernetesv1.Key{
			KeyId:                    key.KeyId,
			Key:                      key.Key,
			ExcludeFromOidcDiscovery: false,
		}
	}

	return &kubernetesv1.FetchKeysResponse{
		Keys:               keys,
		DataTimestamp:      timestamppb.Now(),
		RefreshHintSeconds: int64(s.config.KeyRefreshHint.Seconds()),
	}, nil
}

func (s *Service) Sign(ctx context.Context, req *kubernetesv1.SignJWTRequest) (*kubernetesv1.SignJWTResponse, error) {
	resp, err := s.serverClient.SignJWT(ctx, &kubernetestokenv1.SignJWTRequest{
		Payload: req.Claims,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to sign JWT: %v", err)
	}

	return &kubernetesv1.SignJWTResponse{
		Header:    resp.Header,
		Signature: resp.Signature,
	}, nil
}