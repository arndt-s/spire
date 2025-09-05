package kubernetestokenv1

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/cryptosigner"
	kubernetestokenv1 "github.com/spiffe/spire/proto/spire/server/kubernetestoken/v1"
	"github.com/spiffe/spire/pkg/common/cryptoutil"
	"github.com/spiffe/spire/pkg/server/ca"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// JWTKeyProvider provides access to JWT signing keys
type JWTKeyProvider interface {
	JWTKey() *ca.JWTKey
}

type Service struct {
	kubernetestokenv1.UnsafeKubernetesTokenServer

	jwtKeyProvider JWTKeyProvider
}

func New(jwtKeyProvider JWTKeyProvider) *Service {
	return &Service{
		jwtKeyProvider: jwtKeyProvider,
	}
}

func (s *Service) SignJWT(ctx context.Context, req *kubernetestokenv1.SignJWTRequest) (*kubernetestokenv1.SignJWTResponse, error) {
	// Get current JWT signing key
	jwtKey := s.jwtKeyProvider.JWTKey()
	if jwtKey == nil {
		return nil, status.Error(codes.Internal, "no JWT signing key available")
	}

	// Determine algorithm from the key
	alg, err := cryptoutil.JoseAlgFromPublicKey(jwtKey.Signer.Public())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to determine JWT key algorithm: %v", err)
	}

	// Create signer with proper headers
	signerOpts := &jose.SignerOptions{}
	signerOpts.WithType("JWT")
	signerOpts.WithHeader("kid", jwtKey.Kid)

	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: alg,
		Key: jose.JSONWebKey{
			Key:   cryptosigner.Opaque(jwtKey.Signer),
			KeyID: jwtKey.Kid,
		},
	}, signerOpts)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create signer: %v", err)
	}

	// Decode payload for signing
	payloadBytes, err := base64.RawURLEncoding.DecodeString(req.Payload)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid base64 payload: %v", err)
	}

	// Sign the payload
	jws, err := signer.Sign(payloadBytes)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to sign JWT: %v", err)
	}

	// Extract header and signature from JWS
	// The JWS format is: header.payload.signature
	serialized := jws.FullSerialize()
	parts := strings.Split(serialized, ".")
	if len(parts) != 3 {
		return nil, status.Error(codes.Internal, "malformed JWS")
	}

	return &kubernetestokenv1.SignJWTResponse{
		Header:    parts[0],
		Signature: parts[2],
	}, nil
}

func (s *Service) GetPublicKeys(ctx context.Context, req *kubernetestokenv1.GetPublicKeysRequest) (*kubernetestokenv1.GetPublicKeysResponse, error) {
	jwtKey := s.jwtKeyProvider.JWTKey()
	if jwtKey == nil {
		return nil, status.Error(codes.Internal, "no JWT signing key available")
	}

	// Get public key from the signer
	publicKey := jwtKey.Signer.Public()

	// Marshal public key to PKIX format
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to marshal public key: %v", err)
	}

	return &kubernetestokenv1.GetPublicKeysResponse{
		Keys: []*kubernetestokenv1.PublicKey{
			{
				KeyId: jwtKey.Kid,
				Key:   publicKeyBytes,
			},
		},
	}, nil
}