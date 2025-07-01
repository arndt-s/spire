package github

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/shirou/gopsutil/v4/process"
	workloadattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/workloadattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/pluginconf"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	githubJWKSURL  = "https://token.actions.githubusercontent.com/.well-known/jwks"
	spiffeAudience = "https://spiffe.io"
)

func builtin(p *Plugin) catalog.BuiltIn {
	return catalog.MakeBuiltIn(pluginName,
		workloadattestorv1.WorkloadAttestorPluginServer(p),
		configv1.ConfigServiceServer(p),
	)
}

type processInfo interface {
	Environ() ([]string, error)
}

type PSProcessInfo struct {
	*process.Process
}

func (ps PSProcessInfo) Environ() ([]string, error) {
	switch runtime.GOOS {
	case "linux":
		return ps.readEnvironFromProc()
	case "darwin":
		return ps.readEnvironFromDarwin()
	default:
		// For other systems, use gopsutil's built-in method
		return ps.Process.Environ()
	}
}

// readEnvironFromProc reads environment variables from /proc/[pid]/environ
// This provides a more reliable method for Linux systems
func (ps PSProcessInfo) readEnvironFromProc() ([]string, error) {
	environPath := getProcPath(ps.Pid, "environ")

	data, err := os.ReadFile(environPath)
	if err != nil {
		return nil, err
	}

	// Environment variables in /proc/[pid]/environ are null-terminated
	envStr := string(data)
	if len(envStr) == 0 {
		return []string{}, nil
	}

	// Split by null character and filter out empty strings
	envVars := strings.Split(envStr, "\x00")
	var result []string
	for _, env := range envVars {
		if env != "" {
			result = append(result, env)
		}
	}

	return result, nil
}

// readEnvironFromDarwin reads environment variables on macOS using ps command
// This provides a reliable method for Darwin systems
func (ps PSProcessInfo) readEnvironFromDarwin() ([]string, error) {
	// Use ps command to get environment variables
	// -E flag shows environment variables, -p specifies PID, -o sets output format
	cmd := exec.Command("ps", "-E", "-p", strconv.FormatInt(int64(ps.Pid), 10), "-o", "command=")

	output, err := cmd.Output()
	if err != nil {
		// If ps command fails, try alternative approach using lsof
		return ps.readEnvironFromDarwinLSOF()
	}

	outputStr := strings.TrimSpace(string(output))
	if outputStr == "" {
		return []string{}, nil
	}

	// Parse the ps output to extract environment variables
	// The format is typically: COMMAND with env vars shown as ENV=value
	lines := strings.Split(outputStr, "\n")
	var envVars []string

	for _, line := range lines {
		// Look for environment variable patterns (KEY=VALUE)
		if strings.Contains(line, "=") {
			// Split the line into potential env vars
			parts := strings.Fields(line)
			for _, part := range parts {
				if strings.Contains(part, "=") && !strings.HasPrefix(part, "-") {
					envVars = append(envVars, part)
				}
			}
		}
	}

	return envVars, nil
}

// readEnvironFromDarwinLSOF is a fallback method using lsof for Darwin
func (ps PSProcessInfo) readEnvironFromDarwinLSOF() ([]string, error) {
	// Alternative approach: try to read from process memory using lsof
	// This is less reliable but can work as a fallback
	cmd := exec.Command("lsof", "-p", strconv.FormatInt(int64(ps.Pid), 10), "-F", "n")

	output, err := cmd.Output()
	if err != nil {
		// If both methods fail, return empty slice
		return []string{}, fmt.Errorf("unable to read environment variables for PID %d on Darwin: %v", ps.Pid, err)
	}

	// This is a basic implementation - in practice, extracting env vars from lsof is complex
	// For production use, you might want to implement a more sophisticated parser
	// or use a different approach entirely

	_ = output // Placeholder for now
	return []string{}, nil
}

type Configuration struct {
}

func buildConfig(coreConfig catalog.CoreConfig, hclText string, status *pluginconf.Status) *Configuration {
	newConfig := new(Configuration)
	if err := hcl.Decode(newConfig, hclText); err != nil {
		status.ReportErrorf("failed to decode configuration: %v", err)
		return nil
	}

	return newConfig
}

// JWKS represents the JSON Web Key Set structure
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK represents a JSON Web Key
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	Alg string `json:"alg"`
}

// GitHubOIDCClaims represents the claims in a GitHub OIDC token
type GitHubOIDCClaims struct {
	jwt.RegisteredClaims
	Actor                string `json:"actor,omitempty"`
	ActorID              string `json:"actor_id,omitempty"`
	BaseRef              string `json:"base_ref,omitempty"`
	Environment          string `json:"environment,omitempty"`
	EventName            string `json:"event_name,omitempty"`
	HeadRef              string `json:"head_ref,omitempty"`
	JobWorkflowRef       string `json:"job_workflow_ref,omitempty"`
	JobWorkflowSha       string `json:"job_workflow_sha,omitempty"`
	Ref                  string `json:"ref,omitempty"`
	RefType              string `json:"ref_type,omitempty"`
	Repository           string `json:"repository,omitempty"`
	RepositoryID         string `json:"repository_id,omitempty"`
	RepositoryOwner      string `json:"repository_owner,omitempty"`
	RepositoryOwnerID    string `json:"repository_owner_id,omitempty"`
	RepositoryVisibility string `json:"repository_visibility,omitempty"`
	RunID                string `json:"run_id,omitempty"`
	RunNumber            string `json:"run_number,omitempty"`
	RunAttempt           string `json:"run_attempt,omitempty"`
	RunnerEnvironment    string `json:"runner_environment,omitempty"`
	Workflow             string `json:"workflow,omitempty"`
	WorkflowRef          string `json:"workflow_ref,omitempty"`
	WorkflowSha          string `json:"workflow_sha,omitempty"`
}

type Plugin struct {
	workloadattestorv1.UnsafeWorkloadAttestorServer
	configv1.UnsafeConfigServer

	mu     sync.Mutex
	config *Configuration
	log    hclog.Logger

	// HTTP client for making requests
	httpClient *http.Client

	// hooks for tests
	hooks struct {
		newProcess      func(pid int32) (processInfo, error)
		lookupUserByID  func(id string) (*user.User, error)
		lookupGroupByID func(id string) (*user.Group, error)
	}
}

func New() *Plugin {
	p := &Plugin{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
	p.hooks.newProcess = func(pid int32) (processInfo, error) {
		proc, err := process.NewProcess(pid)
		return PSProcessInfo{proc}, err
	}
	p.hooks.lookupUserByID = user.LookupId
	p.hooks.lookupGroupByID = user.LookupGroupId
	return p
}

func (p *Plugin) SetLogger(log hclog.Logger) {
	p.log = log
}

func (p *Plugin) Attest(_ context.Context, req *workloadattestorv1.AttestRequest) (*workloadattestorv1.AttestResponse, error) {
	_, err := p.getConfig()
	if err != nil {
		return nil, err
	}

	proc, err := p.hooks.newProcess(req.Pid)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get process: %v", err)
	}

	// Get environment variables to check for GitHub Actions OIDC tokens
	envVars, err := proc.Environ()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get process environment: %v", err)
	}

	// Look for GitHub Actions OIDC environment variables
	var requestURL, requestToken string
	for _, envVar := range envVars {
		parts := strings.SplitN(envVar, "=", 2)
		if len(parts) != 2 {
			continue
		}

		switch parts[0] {
		case "ACTIONS_ID_TOKEN_REQUEST_URL":
			requestURL = parts[1]
		case "ACTIONS_ID_TOKEN_REQUEST_TOKEN":
			requestToken = parts[1]
		}
	}

	// If we don't have the required environment variables, return empty selectors
	if requestURL == "" || requestToken == "" {
		p.log.Debug("GitHub Actions OIDC environment variables not found")
		return &workloadattestorv1.AttestResponse{
			SelectorValues: []string{},
		}, nil
	}

	// Exchange for GitHub OIDC token
	oidcToken, err := p.exchangeForOIDCToken(requestURL, requestToken)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to exchange for OIDC token: %v", err)
	}

	// Validate and parse the JWT token
	claims, err := p.validateAndParseJWT(oidcToken)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to validate JWT token: %v", err)
	}

	// Convert claims to selectors
	selectorValues := p.claimsToSelectors(claims)

	return &workloadattestorv1.AttestResponse{
		SelectorValues: selectorValues,
	}, nil
}

// exchangeForOIDCToken exchanges the GitHub Actions environment variables for an OIDC token
func (p *Plugin) exchangeForOIDCToken(requestURL, requestToken string) (string, error) {
	// Add the audience parameter to the request URL
	url := fmt.Sprintf("%s&audience=%s", requestURL, spiffeAudience)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %v", err)
	}

	// Add the bearer token to the authorization header
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", requestToken))

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to make request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("request failed with status %d", resp.StatusCode)
	}

	var tokenResponse struct {
		Value string `json:"value"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return "", fmt.Errorf("failed to decode response: %v", err)
	}

	return tokenResponse.Value, nil
}

// validateAndParseJWT validates the JWT token using GitHub's JWKS and parses the claims
func (p *Plugin) validateAndParseJWT(tokenString string) (*GitHubOIDCClaims, error) {
	// Parse the token without verification first to get the key ID
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, &GitHubOIDCClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %v", err)
	}

	// Get the key ID from the token header
	kid, ok := token.Header["kid"].(string)
	if !ok {
		return nil, fmt.Errorf("token missing kid header")
	}

	// Fetch and parse the JWKS
	jwks, err := p.fetchJWKS()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %v", err)
	}

	// Find the key with matching kid
	var jwk *JWK
	for _, key := range jwks.Keys {
		if key.Kid == kid {
			jwk = &key
			break
		}
	}

	if jwk == nil {
		return nil, fmt.Errorf("key with id %s not found in JWKS", kid)
	}

	// Convert JWK to RSA public key
	publicKey, err := p.jwkToRSAPublicKey(jwk)
	if err != nil {
		return nil, fmt.Errorf("failed to convert JWK to RSA public key: %v", err)
	}

	// Parse and validate the token with the public key
	parsedToken, err := jwt.ParseWithClaims(tokenString, &GitHubOIDCClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify the signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to validate token: %v", err)
	}

	if !parsedToken.Valid {
		return nil, fmt.Errorf("token is not valid")
	}

	claims, ok := parsedToken.Claims.(*GitHubOIDCClaims)
	if !ok {
		return nil, fmt.Errorf("failed to parse claims")
	}

	// Verify the audience is what we expected
	validAudience := false
	for _, aud := range claims.Audience {
		if aud == spiffeAudience {
			validAudience = true
			break
		}
	}
	if !validAudience {
		return nil, fmt.Errorf("invalid audience in token, expected %s", spiffeAudience)
	}

	// Verify the issuer
	if claims.Issuer != "https://token.actions.githubusercontent.com" {
		return nil, fmt.Errorf("invalid issuer in token, expected https://token.actions.githubusercontent.com, got %s", claims.Issuer)
	}

	return claims, nil
}

// fetchJWKS fetches the JWKS from GitHub
func (p *Plugin) fetchJWKS() (*JWKS, error) {
	resp, err := p.httpClient.Get(githubJWKSURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS request failed with status %d", resp.StatusCode)
	}

	var jwks JWKS
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("failed to decode JWKS: %v", err)
	}

	return &jwks, nil
}

// jwkToRSAPublicKey converts a JWK to an RSA public key
func (p *Plugin) jwkToRSAPublicKey(jwk *JWK) (*rsa.PublicKey, error) {
	if jwk.Kty != "RSA" {
		return nil, fmt.Errorf("unsupported key type: %s", jwk.Kty)
	}

	// Decode the modulus (n)
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode modulus: %v", err)
	}

	// Decode the exponent (e)
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode exponent: %v", err)
	}

	// Convert bytes to big integers
	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)

	return &rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}, nil
}

// claimsToSelectors converts GitHub OIDC claims to SPIRE selectors
func (p *Plugin) claimsToSelectors(claims *GitHubOIDCClaims) []string {
	var selectors []string

	// Add claims as selectors
	if claims.Actor != "" {
		selectors = append(selectors, makeSelectorValue("github_actor", claims.Actor))
	}
	if claims.ActorID != "" {
		selectors = append(selectors, makeSelectorValue("github_actor_id", claims.ActorID))
	}
	if claims.Repository != "" {
		selectors = append(selectors, makeSelectorValue("github_repository", claims.Repository))
	}
	if claims.RepositoryID != "" {
		selectors = append(selectors, makeSelectorValue("github_repository_id", claims.RepositoryID))
	}
	if claims.RepositoryOwner != "" {
		selectors = append(selectors, makeSelectorValue("github_repository_owner", claims.RepositoryOwner))
	}
	if claims.RepositoryOwnerID != "" {
		selectors = append(selectors, makeSelectorValue("github_repository_owner_id", claims.RepositoryOwnerID))
	}
	if claims.RepositoryVisibility != "" {
		selectors = append(selectors, makeSelectorValue("github_repository_visibility", claims.RepositoryVisibility))
	}
	if claims.Ref != "" {
		selectors = append(selectors, makeSelectorValue("github_ref", claims.Ref))
	}
	if claims.RefType != "" {
		selectors = append(selectors, makeSelectorValue("github_ref_type", claims.RefType))
	}
	if claims.EventName != "" {
		selectors = append(selectors, makeSelectorValue("github_event_name", claims.EventName))
	}
	if claims.Workflow != "" {
		selectors = append(selectors, makeSelectorValue("github_workflow", claims.Workflow))
	}
	if claims.WorkflowRef != "" {
		selectors = append(selectors, makeSelectorValue("github_workflow_ref", claims.WorkflowRef))
	}
	if claims.WorkflowSha != "" {
		selectors = append(selectors, makeSelectorValue("github_workflow_sha", claims.WorkflowSha))
	}
	if claims.JobWorkflowRef != "" {
		selectors = append(selectors, makeSelectorValue("github_job_workflow_ref", claims.JobWorkflowRef))
	}
	if claims.JobWorkflowSha != "" {
		selectors = append(selectors, makeSelectorValue("github_job_workflow_sha", claims.JobWorkflowSha))
	}
	if claims.RunID != "" {
		selectors = append(selectors, makeSelectorValue("github_run_id", claims.RunID))
	}
	if claims.RunNumber != "" {
		selectors = append(selectors, makeSelectorValue("github_run_number", claims.RunNumber))
	}
	if claims.RunAttempt != "" {
		selectors = append(selectors, makeSelectorValue("github_run_attempt", claims.RunAttempt))
	}
	if claims.Environment != "" {
		selectors = append(selectors, makeSelectorValue("github_environment", claims.Environment))
	}
	if claims.RunnerEnvironment != "" {
		selectors = append(selectors, makeSelectorValue("github_runner_environment", claims.RunnerEnvironment))
	}
	if claims.HeadRef != "" {
		selectors = append(selectors, makeSelectorValue("github_head_ref", claims.HeadRef))
	}
	if claims.BaseRef != "" {
		selectors = append(selectors, makeSelectorValue("github_base_ref", claims.BaseRef))
	}

	// Add standard JWT claims
	if claims.Subject != "" {
		selectors = append(selectors, makeSelectorValue("github_subject", claims.Subject))
	}
	if len(claims.Audience) > 0 {
		for _, aud := range claims.Audience {
			selectors = append(selectors, makeSelectorValue("github_audience", aud))
		}
	}
	if claims.Issuer != "" {
		selectors = append(selectors, makeSelectorValue("github_issuer", claims.Issuer))
	}

	p.log.Info("Generated GitHub OIDC selectors", "selectors", selectors)

	return selectors
}

func (p *Plugin) Configure(_ context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	newConfig, _, err := pluginconf.Build(req, buildConfig)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	p.config = newConfig
	p.mu.Unlock()

	return &configv1.ConfigureResponse{}, nil
}

func (p *Plugin) Validate(_ context.Context, req *configv1.ValidateRequest) (*configv1.ValidateResponse, error) {
	_, notes, err := pluginconf.Build(req, buildConfig)

	return &configv1.ValidateResponse{
		Valid: err == nil,
		Notes: notes,
	}, nil
}

func (p *Plugin) getConfig() (*Configuration, error) {
	p.mu.Lock()
	config := p.config
	p.mu.Unlock()
	if config == nil {
		return nil, status.Error(codes.FailedPrecondition, "not configured")
	}
	return config, nil
}

func makeSelectorValue(kind, value string) string {
	return fmt.Sprintf("%s:%s", kind, value)
}

func getProcPath(pID int32, lastPath string) string {
	procPath := os.Getenv("HOST_PROC")
	if procPath == "" {
		procPath = "/proc"
	}
	return filepath.Join(procPath, strconv.FormatInt(int64(pID), 10), lastPath)
}
