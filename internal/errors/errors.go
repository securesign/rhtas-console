package errors

import "strings"

var (
	ErrArtifactNotFound              = "not found"
	ErrArtifactAuthFailed            = "authentication failed"
	ErrArtifactInvalidImageURI       = "invalid image uri"
	ErrArtifactFailedToFetchImage    = "failed to fetch image"
	ErrArtifactFailedToComputeDigest = "failed to compute digest"
	ErrArtifactFailedToFetchConfig   = "failed to fetch config file"
	ErrArtifactConnectionRefused     = "connection refused"
)

func IsArtifactError(err error, target string) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), target)
}
