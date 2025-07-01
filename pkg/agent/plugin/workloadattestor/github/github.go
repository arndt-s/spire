package github

import "github.com/spiffe/spire/pkg/common/catalog"

const (
	pluginName = "github"
)

func BuiltIn() catalog.BuiltIn {
	return builtin(New())
}
