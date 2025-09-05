package agent

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/agent/workloadkey"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/health"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/tlspolicy"
)

type Config struct {
	// Address to bind the workload api to
	BindAddress net.Addr

	// Directory to store runtime data
	DataDir string

	// Directory to bind the admin api to
	AdminBindAddress net.Addr

	// The Validation Context resource name to use when fetching X.509 bundle together with federated bundles with Envoy SDS
	DefaultAllBundlesName string

	// The Validation Context resource name to use for the default X.509 bundle with Envoy SDS
	DefaultBundleName string

	// Disable custom Envoy SDS validator
	DisableSPIFFECertValidation bool

	// The TLS Certificate resource name to use for the default X509-SVID with Envoy SDS
	DefaultSVIDName string

	// If true, the agent will bootstrap insecurely with the server
	InsecureBootstrap bool

	// If true, the agent retries bootstrap with backoff
	RetryBootstrap bool

	// HealthChecks provides the configuration for health monitoring
	HealthChecks health.Config

	// Configurations for agent plugins
	PluginConfigs catalog.PluginConfigs

	Log logrus.FieldLogger

	// LogReopener facilitates handling a signal to rotate log file.
	LogReopener func(context.Context) error

	// Address of SPIRE server
	ServerAddress string

	// SVID key type
	WorkloadKeyType workloadkey.KeyType

	// SyncInterval controls how often the agent sync synchronizer waits
	SyncInterval time.Duration

	// UseSyncAuthorizedEntries controls if the new SyncAuthorizedEntries RPC
	// is used to sync entries from the server.
	UseSyncAuthorizedEntries bool

	// X509SVIDCacheMaxSize is a soft limit of max number of X509-SVIDs that would be stored in cache
	X509SVIDCacheMaxSize int

	// JWTSVIDCacheMaxSize is a soft limit of max number of JWT-SVIDs that would be stored in cache
	JWTSVIDCacheMaxSize int

	// Trust domain and associated CA bundle
	TrustDomain spiffeid.TrustDomain
	TrustBundle []*x509.Certificate

	// Join token to use for attestation, if needed
	JoinToken string

	// If true enables profiling.
	ProfilingEnabled bool

	// Port used by the pprof web server when ProfilingEnabled == true
	ProfilingPort int

	// Frequency in seconds by which each profile file will be generated.
	ProfilingFreq int

	// Array of profiles names that will be generated on each profiling tick.
	ProfilingNames []string

	// Telemetry provides the configuration for metrics exporting
	Telemetry telemetry.FileConfig

	AllowUnauthenticatedVerifiers bool

	// List of allowed claims response when calling ValidateJWTSVID using a foreign identity
	AllowedForeignJWTClaims []string

	AuthorizedDelegates []string

	// AvailabilityTarget controls how frequently rotate SVIDs
	AvailabilityTarget time.Duration

	// TLSPolicy determines the post-quantum-safe TLS policy to apply to all TLS connections.
	TLSPolicy tlspolicy.Policy

	// KubernetesTokenSigner configuration for external JWT signer service
	KubernetesTokenSigner *KubernetesTokenSignerConfig
}

// KubernetesTokenSignerConfig configures the Kubernetes token signer service
type KubernetesTokenSignerConfig struct {
	Enabled           bool     `hcl:"enabled"`
	SocketPath        string   `hcl:"socket_path"`
	AllowedSPIFFEIDs  []string `hcl:"allowed_spiffe_ids"`
	MaxTokenLifetime  string   `hcl:"max_token_lifetime"`
	KeyRefreshHint    string   `hcl:"key_refresh_hint"`
}

func (c *KubernetesTokenSignerConfig) maxTokenLifetimeDuration() time.Duration {
	if c.MaxTokenLifetime == "" {
		return time.Hour // default
	}
	d, _ := time.ParseDuration(c.MaxTokenLifetime)
	return d
}

func (c *KubernetesTokenSignerConfig) keyRefreshHintDuration() time.Duration {
	if c.KeyRefreshHint == "" {
		return 5 * time.Minute // default
	}
	d, _ := time.ParseDuration(c.KeyRefreshHint)
	return d
}

func (c *KubernetesTokenSignerConfig) Validate() error {
	if !c.Enabled {
		return nil
	}

	if c.SocketPath == "" {
		return fmt.Errorf("socket_path is required when kubernetes_token_signer is enabled")
	}

	if len(c.AllowedSPIFFEIDs) == 0 {
		return fmt.Errorf("allowed_spiffe_ids must contain at least one SPIFFE ID")
	}

	// Validate SPIFFE IDs format
	for _, id := range c.AllowedSPIFFEIDs {
		if _, err := spiffeid.FromString(id); err != nil {
			return fmt.Errorf("invalid SPIFFE ID %s: %v", id, err)
		}
	}

	return nil
}

func New(c *Config) *Agent {
	return &Agent{
		c: c,
	}
}
