package kubernetesv1

import (
	"context"
	"crypto/x509"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

type AccessControlInterceptor struct {
	allowedSPIFFEIDs map[string]bool
}

func NewAccessControlInterceptor(allowedIDs []string) *AccessControlInterceptor {
	allowed := make(map[string]bool, len(allowedIDs))
	for _, id := range allowedIDs {
		allowed[id] = true
	}

	return &AccessControlInterceptor{
		allowedSPIFFEIDs: allowed,
	}
}

func (i *AccessControlInterceptor) UnaryInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	// Extract peer information from context
	peer, ok := peer.FromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no peer information")
	}

	// Extract TLS info
	tlsInfo, ok := peer.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no TLS peer information")
	}

	// Check peer certificates
	if len(tlsInfo.State.PeerCertificates) == 0 {
		return nil, status.Error(codes.Unauthenticated, "no peer certificates")
	}

	// Extract SPIFFE ID from the first certificate
	cert := tlsInfo.State.PeerCertificates[0]
	spiffeID, err := extractSPIFFEID(cert)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "failed to extract SPIFFE ID: %v", err)
	}

	if !i.allowedSPIFFEIDs[spiffeID.String()] {
		return nil, status.Errorf(codes.PermissionDenied, "SPIFFE ID %s not allowed", spiffeID.String())
	}

	return handler(ctx, req)
}

// extractSPIFFEID extracts SPIFFE ID from X.509 certificate
func extractSPIFFEID(cert *x509.Certificate) (spiffeid.ID, error) {
	for _, uri := range cert.URIs {
		if uri.Scheme == "spiffe" {
			return spiffeid.FromURI(uri)
		}
	}
	return spiffeid.ID{}, status.Error(codes.Unauthenticated, "no SPIFFE ID found in certificate")
}