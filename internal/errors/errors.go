package errors

import (
	"errors"
)

var (
	ErrImageNotFound                 = errors.New("image not found")
	ErrArtifactAuthFailed            = errors.New("authentication failed")
	ErrArtifactInvalidImageURI       = errors.New("invalid image uri")
	ErrArtifactFailedToFetchImage    = errors.New("failed to fetch image")
	ErrArtifactFailedToComputeDigest = errors.New("failed to compute digest")
	ErrArtifactFailedToFetchConfig   = errors.New("failed to fetch config file")
	ErrArtifactConnectionRefused     = errors.New("connection refused")
	ErrFetchImageMetadataFailed      = errors.New("failed to fetch image metadata")
)
