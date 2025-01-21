package endpoints

import (
	"context"
	"fmt"

	attestor "github.com/spiffe/spire/pkg/agent/attestor/workload"
	"github.com/spiffe/spire/pkg/common/peertracker"
	"github.com/spiffe/spire/proto/spire/common"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type PeerTrackerAttestor struct {
	Attestor attestor.Attestor
}

func (a PeerTrackerAttestor) Attest(ctx context.Context) ([]*common.Selector, []*common.Selector, error) {
	authInfo, ok := peertracker.AuthInfoFromContext(ctx)
	if !ok {
		return nil, nil, status.Error(codes.Internal, "auth info missing from context")
	}

	var callerSelectors []*common.Selector = nil
	if _, ok := peertracker.OnBehalfOfFromContext(ctx); ok {
		selectors, err := a.Attestor.Attest(ctx, int(authInfo.Caller.PID))
		if err != nil {
			return nil, nil, fmt.Errorf("failed to attest caller: %v", err)
		}

		callerSelectors = selectors
	}

	wlSelectors, err := a.Attestor.Attest(ctx, int(authInfo.Watcher.PID()))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to attest workload: %v", err)
	}

	// Ensure that the original caller is still alive so that we know we didn't
	// attest some other process that happened to be assigned the original PID
	if err := authInfo.Watcher.IsAlive(); err != nil {
		return nil, nil, status.Errorf(codes.Unauthenticated, "could not verify existence of the original caller: %v", err)
	}

	return wlSelectors, callerSelectors, nil
}
