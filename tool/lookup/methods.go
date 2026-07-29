package lookup

import "strings"

const (
	InstallMethod = "lookup"
	ResolveMethod = "lookup"
)

func IsInstallMethod(method string) bool {
	switch strings.ToLower(method) {
	case "path", "path-lookup", "lookup-path", InstallMethod:
		return true
	}
	return false
}

func IsResolveMethod(method string) bool {
	return IsInstallMethod(method)
}

func DefaultVersionResolverConfig(installParams any) (string, any, error) {
	params, ok := installParams.(InstallerParameters)
	if !ok {
		return ResolveMethod, VersionResolutionParameters{}, nil
	}
	return ResolveMethod, VersionResolutionParameters{
		Name:        params.Name,
		Path:        params.Path,
		SearchPaths: params.SearchPaths,
	}, nil
}
